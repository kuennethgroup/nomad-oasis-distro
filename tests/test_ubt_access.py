from pathlib import Path
from types import SimpleNamespace

import jwt
import pytest
from fastapi import HTTPException

from nomad_ubt_access.policy import (
    ACCESS_RESTRICTION_CODE,
    AccessPolicy,
    build_guarded_resolver,
    email_domain,
    install,
)
from nomad_ubt_access.urls import install_root_path_urls


ROOT = Path(__file__).parent.parent
ALLOWED_EMAILS = frozenset(
    {
        "user@uni-bayreuth.de",
        "first@uni-bayreuth.de",
        "second@uni-bayreuth.de",
    }
)


def policy() -> AccessPolicy:
    return AccessPolicy(
        allowed_domains=frozenset({"uni-bayreuth.de"}),
        allowed_emails=ALLOWED_EMAILS,
        require_verified_email=True,
    )


def keycloak_token(claims: dict) -> str:
    payload = {"iss": "https://keycloak.example/realms/nomad", "sub": "user-id"}
    payload.update(claims)
    return jwt.encode(
        payload,
        "test-only-key-with-at-least-32-bytes",
        algorithm="HS256",
        headers={"kid": "test"},
    )


def guarded_user(email: str, *, claims: dict | None = None):
    user = SimpleNamespace(email=email)
    token = keycloak_token(claims) if claims is not None else None
    resolver = build_guarded_resolver(
        lambda **_kwargs: user,
        policy(),
        lambda _token: claims or {},
    )
    return resolver(keycloak_token=token, request=None)


def restriction_reason(exc_info: pytest.ExceptionInfo[HTTPException]) -> str:
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail["code"] == ACCESS_RESTRICTION_CODE
    return exc_info.value.detail["reason"]


def test_email_domain_is_an_exact_comparison():
    assert email_domain("User@UNI-BAYREUTH.DE") == "uni-bayreuth.de"
    assert email_domain("user@sub.uni-bayreuth.de") == "sub.uni-bayreuth.de"
    assert email_domain("user@eviluni-bayreuth.de") == "eviluni-bayreuth.de"
    assert email_domain("not-an-email") is None
    assert email_domain(123) is None


def test_verified_ubt_keycloak_user_is_allowed():
    user = guarded_user(
        "User@uni-bayreuth.de",
        claims={
            "email": "user@UNI-BAYREUTH.DE",
            "email_verified": True,
        },
    )
    assert user.email == "User@uni-bayreuth.de"


def test_ubt_user_not_in_allowlist_is_denied():
    with pytest.raises(HTTPException) as exc_info:
        guarded_user("not-listed@uni-bayreuth.de")
    assert restriction_reason(exc_info) == "email_allowlist"


@pytest.mark.parametrize(
    ("email", "reason"),
    [
        ("user@example.org", "email_domain"),
        ("user@sub.uni-bayreuth.de", "email_domain"),
        ("user@eviluni-bayreuth.de", "email_domain"),
        ("", "email_domain"),
    ],
)
def test_non_ubt_users_are_denied(email, reason):
    with pytest.raises(HTTPException) as exc_info:
        guarded_user(email)
    assert restriction_reason(exc_info) == reason


@pytest.mark.parametrize("verified", [False, None, "true", 1])
def test_unverified_keycloak_email_is_denied(verified):
    with pytest.raises(HTTPException) as exc_info:
        guarded_user(
            "user@uni-bayreuth.de",
            claims={
                "email": "user@uni-bayreuth.de",
                "email_verified": verified,
            },
        )
    assert restriction_reason(exc_info) == "email_not_verified"


def test_keycloak_claim_and_user_email_must_match():
    with pytest.raises(HTTPException) as exc_info:
        guarded_user(
            "first@uni-bayreuth.de",
            claims={
                "email": "second@uni-bayreuth.de",
                "email_verified": True,
            },
        )
    assert restriction_reason(exc_info) == "email_identity_mismatch"


def test_personal_access_token_uses_the_stored_user_email():
    user = SimpleNamespace(email="user@uni-bayreuth.de")
    resolver = build_guarded_resolver(
        lambda **_kwargs: user,
        policy(),
        lambda _token: pytest.fail("PAT must not be decoded as a Keycloak token"),
    )
    assert (
        resolver(
            keycloak_token="nomad_pat_example",
            personal_access_token="nomad_pat_example",
            request=None,
        )
        is user
    )


def test_empty_allowlist_preserves_domain_only_policy():
    domain_policy = AccessPolicy(
        allowed_domains=frozenset({"uni-bayreuth.de"}),
    )
    domain_policy.validate_email("any-user@uni-bayreuth.de")


def test_allowlist_is_loaded_case_insensitively(monkeypatch):
    monkeypatch.setenv(
        "NOMAD_UBT_ALLOWED_EMAILS",
        " User@UNI-BAYREUTH.DE, Other@uni-bayreuth.de ",
    )
    loaded = AccessPolicy.from_environment()
    assert loaded.allowed_emails == frozenset(
        {"user@uni-bayreuth.de", "other@uni-bayreuth.de"}
    )


def test_anonymous_access_is_not_changed():
    resolver = build_guarded_resolver(
        lambda **_kwargs: None,
        policy(),
        lambda _token: pytest.fail("anonymous requests have no Keycloak token"),
    )
    assert resolver(keycloak_token=None, request=None) is None


def test_install_is_idempotent(monkeypatch):
    from nomad.app.v1.routers import auth as auth_router

    original = auth_router._resolve_user_with_scopes
    try:
        assert install(policy()) is True
        assert install(policy()) is False
    finally:
        monkeypatch.setattr(auth_router, "_resolve_user_with_scopes", original)


def test_root_path_urls_are_normalized(monkeypatch):
    from nomad.config.models.config import Services

    original = Services.api_url
    config = SimpleNamespace(
        services=Services(
            api_host="data.ing.uni-bayreuth.de",
            api_port=443,
            api_base_path="",
            https=True,
        ),
        ui=SimpleNamespace(app_base=None, north_base=None),
    )
    try:
        assert install_root_path_urls(config) is True
        assert config.services.api_url() == "https://data.ing.uni-bayreuth.de/api"
        assert config.services.api_url(api="api/v1") == (
            "https://data.ing.uni-bayreuth.de/api/v1"
        )
        assert config.ui.app_base == "https://data.ing.uni-bayreuth.de"
        assert config.ui.north_base == "https://data.ing.uni-bayreuth.de/north"
        assert install_root_path_urls(config) is False
    finally:
        monkeypatch.setattr(Services, "api_url", original)


def test_distribution_wires_the_policy_into_all_access_paths():
    compose = (ROOT / "docker-compose.yaml").read_text()
    dockerfile = (ROOT / "Dockerfile").read_text()
    nginx = (ROOT / "configs/nginx_base_conf").read_text()
    nomad_config = (ROOT / "configs/nomad.yaml").read_text()
    north = (ROOT / "configs/jupyterhub_ubt_config.py").read_text()
    access_policy = (ROOT / "configs/access/access-policy.js").read_text()
    restricted_page = (ROOT / "configs/access/access-restricted.html").read_text()
    readme = (ROOT / "README.md").read_text()

    assert "python -m nomad_ubt_access admin run app" in compose
    assert "python -m nomad_ubt_access admin run action-internal-worker" in compose
    assert "python -m nomad.cli" not in compose
    assert "--reinstall-package nomad-distribution" in dockerfile
    assert 'NOMAD_UBT_ALLOWED_EMAIL_DOMAINS: "uni-bayreuth.de"' in compose
    assert "${NOMAD_UBT_ALLOWED_EMAILS:?" in compose
    assert 'NOMAD_UBT_RESTRICTION_URL: "/access-restricted"' in compose
    assert "NOMAD_SERVICES_API_PORT: 443" in compose
    assert 'NOMAD_API_URL: "http://app:8000/api/v1"' in compose
    assert 'BASE_URL: "/north/"' in compose
    assert (
        'OAUTH_CALLBACK_URL: "https://data.ing.uni-bayreuth.de/north/hub/oauth_callback"'
        in compose
    )
    assert "http://localhost:9000/north/hub/health" in compose
    assert "jupyterhub_ubt_config.py" in compose
    assert 'api_base_path: ""' in nomad_config
    assert "api_port: 443" in nomad_config
    assert 'deployment_url: "https://data.ing.uni-bayreuth.de/api"' in nomad_config
    assert 'app_base: "https://data.ing.uni-bayreuth.de"' in nomad_config
    assert 'north_base: "https://data.ing.uni-bayreuth.de/north"' in nomad_config
    assert "location = / {" in nginx
    assert "return 302 /gui/;" in nginx
    assert "location /gui/" in nginx
    assert "location /north/" in nginx
    assert "location = /access-policy.js" in nginx
    assert "location = /access-restricted" in nginx
    assert 'fallbackUrl = "/access-restricted"' in access_policy
    assert 'scope = ["openid", "profile", "email"]' in north
    assert "protocol/openid-connect/logout" in restricted_page
    assert "post_logout_redirect_uri" in restricted_page
    assert "Authorization=; Path=" in restricted_page
    assert 'window.location.origin + "/gui/"' in restricted_page
    assert "/nomad-oasis/" not in nginx
    assert "/nomad-oasis/" not in access_policy
    assert "/nomad-oasis/" not in restricted_page
    assert "galadriel" not in readme.lower()
    assert "secret" not in readme.lower()
    compile(north, "configs/jupyterhub_ubt_config.py", "exec")

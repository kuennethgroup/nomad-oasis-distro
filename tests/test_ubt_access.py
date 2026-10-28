import asyncio
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
    return asyncio.run(resolver(keycloak_token=token, request=None))


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
        asyncio.run(
            resolver(
                keycloak_token="nomad_pat_example",
                personal_access_token="nomad_pat_example",
                request=None,
            )
        )
        is user
    )


def test_empty_allowlist_preserves_domain_only_policy():
    domain_policy = AccessPolicy(
        allowed_domains=frozenset({"uni-bayreuth.de"}),
    )
    domain_policy.validate_email("any-user@uni-bayreuth.de")


def test_allowlist_is_loaded_case_insensitively(monkeypatch):
    monkeypatch.delenv("NOMAD_UBT_ALLOWED_EMAILS_FILE", raising=False)
    monkeypatch.setenv(
        "NOMAD_UBT_ALLOWED_EMAILS",
        " User@UNI-BAYREUTH.DE, Other@uni-bayreuth.de ",
    )
    loaded = AccessPolicy.from_environment()
    assert loaded.allowed_emails == frozenset(
        {"user@uni-bayreuth.de", "other@uni-bayreuth.de"}
    )


def test_allowlist_is_loaded_from_json_case_insensitively(monkeypatch, tmp_path):
    allowlist = tmp_path / "allowed-emails.json"
    allowlist.write_text(
        '{"allowed_emails": [" User@UNI-BAYREUTH.DE ", "Other@uni-bayreuth.de"]}'
    )
    monkeypatch.setenv("NOMAD_UBT_ALLOWED_EMAILS_FILE", str(allowlist))

    loaded = AccessPolicy.from_environment()

    assert loaded.allowed_emails == frozenset(
        {"user@uni-bayreuth.de", "other@uni-bayreuth.de"}
    )


@pytest.mark.parametrize("contents", [None, "{}", '{"allowed_emails": []}'])
def test_missing_or_empty_json_allowlist_is_allowed(monkeypatch, tmp_path, contents):
    allowlist = tmp_path / "allowed-emails.json"
    if contents is not None:
        allowlist.write_text(contents)
    monkeypatch.setenv("NOMAD_UBT_ALLOWED_EMAILS_FILE", str(allowlist))

    loaded = AccessPolicy.from_environment()

    assert loaded.allowed_emails == frozenset()
    loaded.validate_email("any-user@uni-bayreuth.de")


@pytest.mark.parametrize(
    "contents",
    ["[]", '{"allowed_emails": "user@uni-bayreuth.de"}', "not-json"],
)
def test_invalid_json_allowlist_fails_closed(monkeypatch, tmp_path, contents):
    allowlist = tmp_path / "allowed-emails.json"
    allowlist.write_text(contents)
    monkeypatch.setenv("NOMAD_UBT_ALLOWED_EMAILS_FILE", str(allowlist))

    with pytest.raises((ValueError, OSError)):
        AccessPolicy.from_environment()


def test_anonymous_access_is_not_changed():
    resolver = build_guarded_resolver(
        lambda **_kwargs: None,
        policy(),
        lambda _token: pytest.fail("anonymous requests have no Keycloak token"),
    )
    assert asyncio.run(resolver(keycloak_token=None, request=None)) is None


def test_async_upstream_resolver_is_awaited():
    user = SimpleNamespace(email="user@uni-bayreuth.de")

    async def original(**_kwargs):
        return user

    resolver = build_guarded_resolver(original, policy(), lambda _token: {})
    assert asyncio.run(resolver(request=None)) is user


def test_async_upstream_resolver_denies_unlisted_user():
    async def original(**_kwargs):
        return SimpleNamespace(email="unlisted@uni-bayreuth.de")

    resolver = build_guarded_resolver(original, policy(), lambda _token: {})
    with pytest.raises(HTTPException):
        asyncio.run(resolver(request=None))


def test_install_is_idempotent(monkeypatch):
    from nomad.app.v1.routers import auth as auth_router

    original = auth_router._resolve_user_with_scopes
    try:
        assert install(policy()) is True
        assert install(policy()) is False
    finally:
        monkeypatch.setattr(auth_router, "_resolve_user_with_scopes", original)


def test_backend_urls_use_nomad_2_mount():
    from nomad.config.models.config import Services

    services = Services(
        api_host="data.ing.uni-bayreuth.de",
        api_port=443,
        api_base_path="/backend",
        https=True,
    )
    assert services.api_url(api="api/v1") == (
        "https://data.ing.uni-bayreuth.de/backend/api/v1"
    )


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
    assert (
        "NOMAD_UBT_ALLOWED_EMAILS_FILE: "
        '"/etc/nomad-ubt-access/allowed-emails.json"' in compose
    )
    assert "./configs/access:/etc/nomad-ubt-access:ro" in compose
    assert 'NOMAD_UBT_RESTRICTION_URL: "/access-restricted"' in compose
    assert "NOMAD_SERVICES_API_PORT: 443" in compose
    assert 'NOMAD_API_URL: "http://app:8000/backend/api/v1"' in compose
    assert 'BASE_URL: "/backend/north/"' in compose
    assert (
        'OAUTH_CALLBACK_URL: "https://data.ing.uni-bayreuth.de/backend/north/hub/oauth_callback"'
        in compose
    )
    assert "http://localhost:9000/backend/north/hub/health" in compose
    assert "jupyterhub_ubt_config.py" in compose
    assert 'api_base_path: "/backend"' in nomad_config
    assert "api_port: 443" in nomad_config
    assert (
        'deployment_url: "https://data.ing.uni-bayreuth.de/backend/api"' in nomad_config
    )
    assert 'name: "nomad_oasis_elastic_9"' in compose
    assert "NOMAD_ELASTIC_VERSION: 9" in compose
    assert "location = / {" in nginx
    assert "location ^~ /gui/" in nginx
    assert "location /backend/north/" in nginx
    assert nginx.count('<script src="/access-policy.js"></script>') >= 5
    assert "location = /access-policy.js" in nginx
    assert "location = /access-restricted" in nginx
    assert 'fallbackUrl = "/access-restricted"' in access_policy
    assert 'scope = ["openid", "profile", "email"]' in north
    assert "protocol/openid-connect/logout" in restricted_page
    assert "post_logout_redirect_uri" in restricted_page
    assert "Authorization=; Path=" in restricted_page
    assert 'window.location.origin + "/"' in restricted_page
    assert "/nomad-oasis/" not in access_policy
    assert "/nomad-oasis/" not in restricted_page
    assert "galadriel" not in readme.lower()
    assert "secret" not in readme.lower()
    compile(north, "configs/jupyterhub_ubt_config.py", "exec")

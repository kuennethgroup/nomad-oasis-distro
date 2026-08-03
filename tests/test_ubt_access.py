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


def policy() -> AccessPolicy:
    return AccessPolicy(
        allowed_domains=frozenset({"uni-bayreuth.de"}),
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


def test_distribution_wires_the_policy_into_all_access_paths():
    compose = (ROOT / "docker-compose.yaml").read_text()
    nginx = (ROOT / "configs/nginx_base_conf").read_text()
    north = (ROOT / "configs/jupyterhub_ubt_config.py").read_text()
    restricted_page = (
        ROOT / "configs/access/access-restricted.html"
    ).read_text()

    assert "python -m nomad_ubt_access admin run app" in compose
    assert 'NOMAD_UBT_ALLOWED_EMAIL_DOMAINS: "uni-bayreuth.de"' in compose
    assert "jupyterhub_ubt_config.py" in compose
    assert "access-policy.js" in nginx
    assert "access-restricted" in nginx
    assert 'scope = ["openid", "profile", "email"]' in north
    assert "protocol/openid-connect/logout" in restricted_page
    assert "post_logout_redirect_uri" in restricted_page
    assert "Authorization=; Path=" in restricted_page
    compile(north, "configs/jupyterhub_ubt_config.py", "exec")

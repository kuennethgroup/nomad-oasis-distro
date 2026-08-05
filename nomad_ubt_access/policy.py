"""Server-side email-domain authorization for authenticated NOMAD users."""

from __future__ import annotations

import functools
import os
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import jwt
from fastapi import HTTPException, status


ACCESS_RESTRICTION_CODE = "email_domain_not_authorized"
_INSTALL_MARKER = "_nomad_ubt_access_policy_installed"


def _parse_bool(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Invalid boolean value: {value!r}")


def _normalize_domains(value: str | None) -> frozenset[str]:
    if not value:
        return frozenset()
    return frozenset(
        domain.strip().lower().lstrip("@")
        for domain in value.split(",")
        if domain.strip().lstrip("@")
    )


def _normalize_emails(value: str | None) -> frozenset[str]:
    if not value:
        return frozenset()
    return frozenset(
        email.strip().lower() for email in value.split(",") if email.strip()
    )


def email_domain(email: str | None) -> str | None:
    """Return an exact, normalized domain for a syntactically simple email."""
    if not isinstance(email, str) or not email:
        return None
    normalized = email.strip().lower()
    if normalized.count("@") != 1:
        return None
    local_part, domain = normalized.rsplit("@", 1)
    if not local_part or not domain:
        return None
    return domain


@dataclass(frozen=True)
class AccessPolicy:
    allowed_domains: frozenset[str]
    allowed_emails: frozenset[str] = frozenset()
    require_verified_email: bool = True
    restriction_url: str = "/access-restricted"

    @classmethod
    def from_environment(cls) -> "AccessPolicy":
        return cls(
            allowed_domains=_normalize_domains(
                os.getenv("NOMAD_UBT_ALLOWED_EMAIL_DOMAINS")
            ),
            allowed_emails=_normalize_emails(os.getenv("NOMAD_UBT_ALLOWED_EMAILS")),
            require_verified_email=_parse_bool(
                os.getenv("NOMAD_UBT_REQUIRE_VERIFIED_EMAIL"), default=True
            ),
            restriction_url=os.getenv(
                "NOMAD_UBT_RESTRICTION_URL",
                "/access-restricted",
            ),
        )

    @property
    def enabled(self) -> bool:
        return bool(self.allowed_domains or self.allowed_emails)

    def deny(self, reason: str) -> None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": ACCESS_RESTRICTION_CODE,
                "reason": reason,
                "message": (
                    "This NOMAD Oasis is restricted to approved, verified "
                    "University of Bayreuth email accounts."
                ),
                "restriction_url": self.restriction_url,
            },
            headers={"X-NOMAD-Access-Restriction": "email-domain"},
        )

    def validate_email(self, email: str | None) -> None:
        domain = email_domain(email)
        if domain is None:
            self.deny("email_domain")
        if self.allowed_domains and domain not in self.allowed_domains:
            self.deny("email_domain")
        normalized_email = email.strip().lower()
        if self.allowed_emails and normalized_email not in self.allowed_emails:
            self.deny("email_allowlist")

    def validate_keycloak_claims(
        self, claims: dict[str, Any], user_email: str | None
    ) -> None:
        claim_email = claims.get("email")
        self.validate_email(claim_email)

        if self.require_verified_email and claims.get("email_verified") is not True:
            self.deny("email_not_verified")

        if (
            not isinstance(claim_email, str)
            or not isinstance(user_email, str)
            or claim_email.strip().lower() != user_email.strip().lower()
        ):
            self.deny("email_identity_mismatch")


def _keycloak_token_from_request(
    request: Any, keycloak_token: str | None
) -> str | None:
    token = keycloak_token
    if token is None and request is not None:
        auth_cookie = request.cookies.get("Authorization")
        if auth_cookie:
            token = urllib.parse.unquote(auth_cookie).removeprefix("Bearer ")

    if not token or token.startswith("nomad_pat_"):
        return None

    try:
        header = jwt.get_unverified_header(token)
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None

    # NOMAD's deprecated simple tokens are JWTs too, but Keycloak tokens
    # carry a key id, issuer, and subject.
    if not header.get("kid") or not claims.get("iss") or not claims.get("sub"):
        return None
    return token


def build_guarded_resolver(
    original: Callable[..., Any],
    policy: AccessPolicy,
    decode_access_token: Callable[[str], dict[str, Any]],
) -> Callable[..., Any]:
    """Wrap NOMAD's central user resolver with the distribution policy."""

    @functools.wraps(original)
    def guarded_resolver(*args: Any, **kwargs: Any) -> Any:
        user = original(*args, **kwargs)
        if user is None:
            return None

        # This applies the email policy to Keycloak, personal access, simple,
        # and upload tokens. Internal API-secret authentication does not
        # resolve a human user through this function and is unaffected.
        policy.validate_email(getattr(user, "email", None))

        keycloak_token = _keycloak_token_from_request(
            kwargs.get("request"), kwargs.get("keycloak_token")
        )
        if keycloak_token is not None:
            claims = decode_access_token(keycloak_token)
            policy.validate_keycloak_claims(claims, getattr(user, "email", None))

        return user

    setattr(guarded_resolver, _INSTALL_MARKER, True)
    return guarded_resolver


def install(policy: AccessPolicy | None = None) -> bool:
    """Install the policy before the NOMAD FastAPI dependencies are used."""
    policy = policy or AccessPolicy.from_environment()
    if not policy.enabled:
        return False

    from nomad.app.v1.routers import auth as auth_router
    from nomad.auth.keycloak import keycloak

    current = auth_router._resolve_user_with_scopes
    if getattr(current, _INSTALL_MARKER, False):
        return False

    auth_router._resolve_user_with_scopes = build_guarded_resolver(
        current,
        policy,
        keycloak.decode_access_token,
    )
    return True

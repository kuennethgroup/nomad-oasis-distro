"""Overlay NORTH's upstream JupyterHub config with the UBT email policy."""

from __future__ import annotations

import json
import os

from oauthenticator.generic import GenericOAuthenticator


# Keep using the configuration shipped by the NORTH image, then override only
# its authenticator. This avoids duplicating its spawner and service settings.
c = get_config()  # type: ignore[name-defined]  # noqa: F821
_UPSTREAM_CONFIG = "/srv/jupyterhub/jupyterhub_config.py"
with open(_UPSTREAM_CONFIG, "rb") as upstream_config:
    exec(compile(upstream_config.read(), _UPSTREAM_CONFIG, "exec"))


def _allowed_domains() -> frozenset[str]:
    return frozenset(
        domain.strip().lower().lstrip("@")
        for domain in os.environ.get("NOMAD_UBT_ALLOWED_EMAIL_DOMAINS", "").split(",")
        if domain.strip().lstrip("@")
    )


def _allowed_emails() -> frozenset[str]:
    path = os.environ.get("NOMAD_UBT_ALLOWED_EMAILS_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as allowlist_file:
                document = json.load(allowlist_file)
        except FileNotFoundError:
            return frozenset()

        if not isinstance(document, dict):
            raise ValueError(
                f"Email allowlist file must contain a JSON object: {path}"
            )
        emails = document.get("allowed_emails", [])
        if not isinstance(emails, list) or not all(
            isinstance(email, str) for email in emails
        ):
            raise ValueError(
                "Email allowlist field 'allowed_emails' must be a list of "
                f"strings: {path}"
            )
        return frozenset(
            email.strip().lower() for email in emails if email.strip()
        )

    # Backward compatibility for deployments that still use the original
    # comma-separated environment variable.
    return frozenset(
        email.strip().lower()
        for email in os.environ.get("NOMAD_UBT_ALLOWED_EMAILS", "").split(",")
        if email.strip()
    )


ALLOWED_EMAIL_DOMAINS = _allowed_domains()
ALLOWED_EMAILS = _allowed_emails()


class UBTEmailDomainOAuthenticator(GenericOAuthenticator):
    async def check_allowed(self, username, auth_model):
        if auth_model is None:
            # Preserve upstream OAuthenticator behavior for JupyterHub's
            # internal checks. Interactive login and refresh supply auth_model.
            return await super().check_allowed(username, auth_model)

        user_info = auth_model.get("auth_state", {}).get(self.user_auth_state_key, {})
        email = user_info.get("email")
        verified = user_info.get("email_verified") is True

        if not verified or not isinstance(email, str) or email.strip().count("@") != 1:
            self.log.warning("Rejecting login without a verified email")
            return False

        normalized_email = email.strip().lower()
        local_part, domain = normalized_email.rsplit("@", 1)
        if not local_part or not domain:
            self.log.warning("Rejecting login without a valid email")
            return False
        if ALLOWED_EMAIL_DOMAINS and domain not in ALLOWED_EMAIL_DOMAINS:
            self.log.warning("Rejecting login from a non-authorized email domain")
            return False
        if ALLOWED_EMAILS and normalized_email not in ALLOWED_EMAILS:
            self.log.warning("Rejecting login for a non-authorized account")
            return False
        return True


if ALLOWED_EMAIL_DOMAINS or ALLOWED_EMAILS:
    c.JupyterHub.authenticator_class = UBTEmailDomainOAuthenticator
    c.Authenticator.allow_all = False
    # Authorization is implemented by check_allowed rather than allowed_users.
    c.Authenticator.any_allow_config = True
    c.GenericOAuthenticator.scope = ["openid", "profile", "email"]

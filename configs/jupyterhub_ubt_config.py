"""Overlay NORTH's upstream JupyterHub config with the UBT email policy."""

from __future__ import annotations

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


ALLOWED_EMAIL_DOMAINS = _allowed_domains()


class UBTEmailDomainOAuthenticator(GenericOAuthenticator):
    async def check_allowed(self, username, auth_model):
        if auth_model is None:
            # Preserve upstream OAuthenticator behavior for JupyterHub's
            # internal checks. Interactive login and refresh supply auth_model.
            return await super().check_allowed(username, auth_model)

        user_info = auth_model.get("auth_state", {}).get(self.user_auth_state_key, {})
        email = user_info.get("email")
        verified = user_info.get("email_verified") is True

        if not verified or not email or email.count("@") != 1:
            self.log.warning("Rejecting login without a verified email")
            return False

        domain = email.rsplit("@", 1)[1].strip().lower()
        allowed = domain in ALLOWED_EMAIL_DOMAINS
        if not allowed:
            self.log.warning("Rejecting login from a non-authorized email domain")
        return allowed


if ALLOWED_EMAIL_DOMAINS:
    c.JupyterHub.authenticator_class = UBTEmailDomainOAuthenticator
    c.Authenticator.allow_all = False
    # Authorization is implemented by check_allowed rather than allowed_users.
    c.Authenticator.any_allow_config = True
    c.GenericOAuthenticator.scope = ["openid", "profile", "email"]

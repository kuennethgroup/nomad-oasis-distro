"""Normalize NOMAD's generated URLs for a domain-root deployment."""

from __future__ import annotations

import functools
from typing import Any
from urllib.parse import urlsplit, urlunsplit


_INSTALL_MARKER = "_nomad_root_path_urls_installed"


def install_root_path_urls(config: Any | None = None) -> bool:
    """Remove duplicate path separators emitted for an empty API base path."""
    if config is None:
        from nomad.config import config as nomad_config

        config = nomad_config

    if config.services.api_base_path.strip("/"):
        return False

    services_type = type(config.services)
    current = services_type.api_url
    if getattr(current, _INSTALL_MARKER, False):
        return False

    @functools.wraps(current)
    def normalized_api_url(self: Any, *args: Any, **kwargs: Any) -> str:
        parsed = urlsplit(current(self, *args, **kwargs))
        path = f"/{parsed.path.lstrip('/')}"
        return urlunsplit(
            (parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment)
        )

    setattr(normalized_api_url, _INSTALL_MARKER, True)
    services_type.api_url = normalized_api_url

    # NOMAD always derives these from its internal service and hub ports during
    # model validation. Behind one public reverse proxy, both use the API host.
    public_origin = config.services.api_url(api="").rstrip("/")
    config.ui.app_base = public_origin
    config.ui.north_base = f"{public_origin}/north"
    return True

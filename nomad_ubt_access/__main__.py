"""Run the NOMAD CLI with the distribution access policy installed."""

from nomad.cli.cli import run_cli

from .policy import install
from .urls import install_root_path_urls


def main() -> None:
    install_root_path_urls()
    install()
    run_cli()


if __name__ == "__main__":
    main()

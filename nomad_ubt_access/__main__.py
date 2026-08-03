"""Run the NOMAD CLI with the distribution access policy installed."""

from nomad.cli.cli import run_cli

from .policy import install


def main() -> None:
    install()
    run_cli()


if __name__ == "__main__":
    main()

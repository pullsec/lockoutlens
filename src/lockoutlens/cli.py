import argparse

from lockoutlens import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lockoutlens",
        description=(
            "Active Directory password policy auditing and "
            "account lockout risk assessment toolkit."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"LockoutLens {__version__}",
    )

    return parser


def main() -> None:
    parser = build_parser()
    parser.parse_args()


if __name__ == "__main__":
    main()

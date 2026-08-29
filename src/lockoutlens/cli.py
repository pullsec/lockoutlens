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

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="COMMAND",
    )

    policy_parser = subparsers.add_parser(
        "policy",
        help="Audit Active Directory password and account lockout policies.",
        description=(
            "Audit Active Directory password and account lockout policies."
        ),
    )

    policy_parser.add_argument(
        "--dc",
        required=True,
        help="Domain controller hostname or IP address.",
    )

    policy_parser.add_argument(
        "--domain",
        required=True,
        help="Active Directory domain name.",
    )

    policy_parser.add_argument(
        "--username",
        required=True,
        help="Username used to authenticate to Active Directory.",
    )

    policy_parser.add_argument(
        "--use-ssl",
        action="store_true",
        help="Use LDAPS for the connection.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    parser.parse_args()


if __name__ == "__main__":
    main()

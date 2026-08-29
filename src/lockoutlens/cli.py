import argparse
from getpass import getpass

from lockoutlens import __version__
from lockoutlens.ldap.client import LDAPClient
from lockoutlens.ldap.exceptions import LDAPBindError

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

def run_policy(args: argparse.Namespace) -> int:
    """Run the Active Directory policy audit command."""
    password = getpass("Password: ")

    client = LDAPClient(
        dc=args.dc,
        domain=args.domain,
        username=args.username,
        password=password,
        use_ssl=args.use_ssl,
    )

    try:
        client.bind()
    except LDAPBindError as exc:
        print(f"Error: {exc}")
        return 1

    print(f"Connected to {args.dc}")
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "policy":
        return run_policy(args)

    parser.print_help()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

import argparse

from getpass import getpass
from lockoutlens.formatting import format_duration
from lockoutlens import __version__
from lockoutlens.ldap.client import LDAPClient
from lockoutlens.ldap.exceptions import LDAPBindError, LDAPError
from lockoutlens.ldap.policy import (
    get_domain_policy,
    normalize_domain_policy,
)

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

    policy_parser.add_argument(
        "--ca-file",
        help="CA certificate file used to validate the LDAPS server.",
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
        ca_file=args.ca_file,
    )

    connection = None

    try:
        connection = client.bind()

        base_dn = client.get_default_naming_context(connection)

        raw_policy = get_domain_policy(
            connection,
            base_dn,
        )

        policy = normalize_domain_policy(raw_policy)

    except (LDAPBindError, LDAPError) as exc:
        print(f"Error: {exc}")
        return 1

    finally:
        if connection is not None:
            connection.unbind()

    print(f"Domain:              {args.domain}")
    print(f"Domain Controller:   {args.dc}")
    print()
    print("Password Policy")
    print("-" * 34)
    print(f"Minimum length:      {policy.min_password_length}")
    print(
        f"Password history:    "
        f"{policy.password_history_length}"
    )
    print(
        f"Minimum age:         "
        f"{format_duration(policy.min_password_age_seconds)}"
    )
    print(
        f"Maximum age:         "
        f"{format_duration(policy.max_password_age_seconds)}"
    )
    print()
    print("Lockout Policy")
    print("-" * 34)
    print(f"Threshold:           {policy.lockout_threshold}")
    print(
        f"Observation window:  "
        f"{format_duration(policy.lockout_observation_window_seconds)}"
    )
    print(
        f"Lockout duration:    "
        f"{format_duration(policy.lockout_duration_seconds)}"
    )

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

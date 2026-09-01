from dataclasses import dataclass
from typing import Any
from ldap3 import SUBTREE, Connection
from lockoutlens.ldap.exceptions import LDAPError


ACCOUNTDISABLE = 0x0002

USER_ATTRIBUTES = (
    "distinguishedName",
    "sAMAccountName",
    "userPrincipalName",
    "userAccountControl",
    "lockoutTime",
    "badPwdCount",
)


@dataclass(frozen=True)
class ADUser:
    """Normalized Active Directory user account."""

    distinguished_name: str
    sam_account_name: str
    user_principal_name: str | None
    enabled: bool
    lockout_time: int
    bad_password_count: int

    @property
    def locked(self) -> bool:
        """Return whether Active Directory reports a lockout time."""
        return self.lockout_time > 0


def is_account_enabled(user_account_control: int | str) -> bool:
    """Return whether an Active Directory account is enabled."""
    value = int(user_account_control)

    return not bool(value & ACCOUNTDISABLE)


def normalize_ad_user(raw_user: dict[str, Any]) -> ADUser:
    """Normalize raw Active Directory user attributes."""
    upn = raw_user.get("userPrincipalName")

    return ADUser(
        distinguished_name=str(raw_user["distinguishedName"]),
        sam_account_name=str(raw_user["sAMAccountName"]),
        user_principal_name=str(upn) if upn else None,
        enabled=is_account_enabled(
            raw_user["userAccountControl"] 
        ),
        lockout_time=int(raw_user.get("lockoutTime") or 0),
        bad_password_count=int(raw_user.get("badPwdCount") or 0),
    )


def get_domain_users(
    connection: Connection,
    base_dn: str,
) -> list[ADUser]:
    """Retrieve and normalize Active Directory user accounts."""
    success = connection.search(
        search_base=base_dn,
        search_filter=(
            "(&(objectCategory=person)(objectClass=user))"
        ),
        search_scope=SUBTREE,
        attributes=list(USER_ATTRIBUTES),
    )

    if not success:
        raise LDAPError(
            f"Unable to retrieve domain users from {base_dn}"
        )

    users = []

    for entry in connection.entries:
        raw_user = {
            attribute: entry[attribute].value
            for attribute in USER_ATTRIBUTES
        }
        users.append(normalize_ad_user(raw_user))

    return users

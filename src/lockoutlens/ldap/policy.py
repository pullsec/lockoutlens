from typing import Any

from ldap3 import BASE, Connection

from lockoutlens.ldap.exceptions import LDAPError


DOMAIN_POLICY_ATTRIBUTES = (
    "minPwdLength",
    "pwdHistoryLength",
    "minPwdAge",
    "maxPwdAge",
    "lockoutThreshold",
    "lockoutDuration",
    "lockoutObservationWindow",
)


def get_domain_policy(
    connection: Connection,
    base_dn: str,
) -> dict[str, Any]:
    """Read the domain password and account lockout policy."""
    success = connection.search(
        search_base=base_dn,
        search_filter="(objectClass=*)",
        search_scope=BASE,
        attributes=list(DOMAIN_POLICY_ATTRIBUTES),
    )

    if not success or not connection.entries:
        raise LDAPError(
            f"Unable to retrieve domain policy from {base_dn}"
        )

    entry = connection.entries[0]

    return {
        attribute: entry[attribute].value
        for attribute in DOMAIN_POLICY_ATTRIBUTES
    }

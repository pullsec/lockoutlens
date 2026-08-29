from typing import Any
from dataclasses import dataclass
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

AD_TICKS_PER_SECOND = 10_000_000

@dataclass(frozen=True)
class DomainPolicy:
    """Normalized Active Directory domain password policy."""

    min_password_length: int
    password_history_length: int
    min_password_age_seconds: int | None
    max_password_age_seconds: int | None
    lockout_threshold: int
    lockout_duration_seconds: int | None
    lockout_observation_window_seconds: int | None

def ad_interval_to_seconds(
    value: int | str | None,
) -> int | None:
    """Convert an Active Directory interval to seconds."""
    if value is None:
        return None

    ticks = int(value)

    return abs(ticks) // AD_TICKS_PER_SECOND


def normalize_domain_policy(
    raw_policy: dict[str, Any],
) -> DomainPolicy:
    """Normalize raw Active Directory domain policy attributes."""
    return DomainPolicy(
        min_password_length=int(raw_policy["minPwdLength"]),
        password_history_length=int(raw_policy["pwdHistoryLength"]),
        min_password_age_seconds=ad_interval_to_seconds(
            raw_policy["minPwdAge"]
        ),
        max_password_age_seconds=ad_interval_to_seconds(
            raw_policy["maxPwdAge"]
        ),
        lockout_threshold=int(raw_policy["lockoutThreshold"]),
        lockout_duration_seconds=ad_interval_to_seconds(
            raw_policy["lockoutDuration"]
        ),
        lockout_observation_window_seconds=ad_interval_to_seconds(
            raw_policy["lockoutObservationWindow"]
        ),
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

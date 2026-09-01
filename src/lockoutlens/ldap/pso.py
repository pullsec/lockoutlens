from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from ldap3 import BASE, Connection

from lockoutlens.ldap.ad import ad_interval_to_seconds
from lockoutlens.ldap.exceptions import LDAPError

from lockoutlens.ldap.ad import ad_interval_to_seconds

PSO_ATTRIBUTES = (
    "name",
    "msDS-PasswordSettingsPrecedence",
    "msDS-MinimumPasswordLength",
    "msDS-PasswordHistoryLength",
    "msDS-MinimumPasswordAge",
    "msDS-MaximumPasswordAge",
    "msDS-LockoutThreshold",
    "msDS-LockoutObservationWindow",
    "msDS-LockoutDuration",
)


@dataclass(frozen=True)
class PasswordSettingsObject:
    """Normalized Active Directory Password Settings Object."""

    distinguished_name: str
    name: str
    precedence: int
    min_password_length: int
    password_history_length: int
    min_password_age_seconds: int | None
    max_password_age_seconds: int | None
    lockout_threshold: int
    lockout_observation_window_seconds: int | None
    lockout_duration_seconds: int | None

    @property
    def lockout_enabled(self) -> bool:
        """Return whether account lockout is enabled."""
        return self.lockout_threshold > 0


def normalize_password_settings_object(
    distinguished_name: str,
    raw_pso: dict[str, Any],
) -> PasswordSettingsObject:
    """Normalize raw Active Directory password settings attributes."""
    return PasswordSettingsObject(
        distinguished_name=distinguished_name,
        name=str(raw_pso["name"]),
        precedence=int(
            raw_pso["msDS-PasswordSettingsPrecedence"]
        ),
        min_password_length=int(
            raw_pso["msDS-MinimumPasswordLength"]
        ),
        password_history_length=int(
            raw_pso["msDS-PasswordHistoryLength"]
        ),
        min_password_age_seconds=ad_interval_to_seconds(
            raw_pso["msDS-MinimumPasswordAge"]
        ),
        max_password_age_seconds=ad_interval_to_seconds(
            raw_pso["msDS-MaximumPasswordAge"]
        ),
        lockout_threshold=int(
            raw_pso["msDS-LockoutThreshold"]
        ),
        lockout_observation_window_seconds=ad_interval_to_seconds(
            raw_pso["msDS-LockoutObservationWindow"]
        ),
        lockout_duration_seconds=ad_interval_to_seconds(
            raw_pso["msDS-LockoutDuration"]
        ),
    )


def normalize_password_settings_object(
    distinguished_name: str,
    raw_pso: dict[str, Any],
) -> PasswordSettingsObject:
    """Normalize raw Active Directory password settings attributes."""
    return PasswordSettingsObject(
        distinguished_name=distinguished_name,
        name=str(raw_pso["name"]),
        precedence=int(
            raw_pso["msDS-PasswordSettingsPrecedence"]
        ),
        min_password_length=int(
            raw_pso["msDS-MinimumPasswordLength"]
        ),
        password_history_length=int(
            raw_pso["msDS-PasswordHistoryLength"]
        ),
        min_password_age_seconds=ad_interval_to_seconds(
            raw_pso["msDS-MinimumPasswordAge"]
        ),
        max_password_age_seconds=ad_interval_to_seconds(
            raw_pso["msDS-MaximumPasswordAge"]
        ),
        lockout_threshold=int(
            raw_pso["msDS-LockoutThreshold"]
        ),
        lockout_observation_window_seconds=ad_interval_to_seconds(
            raw_pso["msDS-LockoutObservationWindow"]
        ),
        lockout_duration_seconds=ad_interval_to_seconds(
            raw_pso["msDS-LockoutDuration"]
        ),
    )


def get_password_settings_object(
    connection: Connection,
    distinguished_name: str,
) -> PasswordSettingsObject:
    """Retrieve and normalize a Password Settings Object."""
    success = connection.search(
        search_base=distinguished_name,
        search_filter="(objectClass=*)",
        search_scope=BASE,
        attributes=list(PSO_ATTRIBUTES),
    )

    if not success or not connection.entries:
        raise LDAPError(
            f"Unable to retrieve password settings object "
            f"{distinguished_name}"
        )

    entry = connection.entries[0]

    raw_pso = {
        attribute: entry[attribute].value
        for attribute in PSO_ATTRIBUTES
    }

    missing_attributes = [
        attribute
        for attribute, value in raw_pso.items()
        if value is None
    ]

    if missing_attributes:
        missing = ", ".join(missing_attributes)
        raise LDAPError(
            "Password settings object attributes are unavailable: "
            f"{missing}"
        )

    return normalize_password_settings_object(
        distinguished_name,
        raw_pso,
    )

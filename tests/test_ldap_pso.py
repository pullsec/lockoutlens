from datetime import timedelta

from lockoutlens.ldap.pso import (
    PasswordSettingsObject,
    normalize_password_settings_object,
)


def test_password_settings_object_model():
    pso = PasswordSettingsObject(
        distinguished_name=(
            "CN=LockoutLens-Test-PSO,"
            "CN=Password Settings Container,"
            "CN=System,DC=lab,DC=local"
        ),
        name="LockoutLens-Test-PSO",
        precedence=10,
        min_password_length=12,
        password_history_length=5,
        min_password_age_seconds=0,
        max_password_age_seconds=2_592_000,
        lockout_threshold=5,
        lockout_observation_window_seconds=1800,
        lockout_duration_seconds=1800,
    )

    assert pso.name == "LockoutLens-Test-PSO"
    assert pso.precedence == 10
    assert pso.lockout_enabled is True


def test_normalize_password_settings_object():
    distinguished_name = (
        "CN=LockoutLens-Test-PSO,"
        "CN=Password Settings Container,"
        "CN=System,DC=lab,DC=local"
    )

    raw_pso = {
        "name": "LockoutLens-Test-PSO",
        "msDS-PasswordSettingsPrecedence": 10,
        "msDS-MinimumPasswordLength": 12,
        "msDS-PasswordHistoryLength": 5,
        "msDS-MinimumPasswordAge": timedelta(0),
        "msDS-MaximumPasswordAge": timedelta(days=-30),
        "msDS-LockoutThreshold": 5,
        "msDS-LockoutObservationWindow": timedelta(minutes=-30),
        "msDS-LockoutDuration": timedelta(minutes=-30),
    }

    pso = normalize_password_settings_object(
        distinguished_name,
        raw_pso,
    )

    assert pso == PasswordSettingsObject(
        distinguished_name=distinguished_name,
        name="LockoutLens-Test-PSO",
        precedence=10,
        min_password_length=12,
        password_history_length=5,
        min_password_age_seconds=0,
        max_password_age_seconds=2_592_000,
        lockout_threshold=5,
        lockout_observation_window_seconds=1800,
        lockout_duration_seconds=1800,
    )


def test_password_settings_object_lockout_disabled():
    pso = PasswordSettingsObject(
        distinguished_name="CN=No-Lockout-PSO",
        name="No-Lockout-PSO",
        precedence=20,
        min_password_length=12,
        password_history_length=5,
        min_password_age_seconds=0,
        max_password_age_seconds=2_592_000,
        lockout_threshold=0,
        lockout_observation_window_seconds=1800,
        lockout_duration_seconds=1800,
    )

    assert pso.lockout_enabled is False


def test_get_password_settings_object():
    from unittest.mock import MagicMock

    from ldap3 import BASE

    from lockoutlens.ldap.pso import (
        PSO_ATTRIBUTES,
        get_password_settings_object,
    )

    distinguished_name = (
        "CN=LockoutLens-Test-PSO,"
        "CN=Password Settings Container,"
        "CN=System,DC=lab,DC=local"
    )

    values = {
        "name": "LockoutLens-Test-PSO",
        "msDS-PasswordSettingsPrecedence": 10,
        "msDS-MinimumPasswordLength": 12,
        "msDS-PasswordHistoryLength": 5,
        "msDS-MinimumPasswordAge": timedelta(0),
        "msDS-MaximumPasswordAge": timedelta(days=-30),
        "msDS-LockoutThreshold": 5,
        "msDS-LockoutObservationWindow": timedelta(minutes=-30),
        "msDS-LockoutDuration": timedelta(minutes=-30),
    }

    connection = MagicMock()
    connection.search.return_value = True

    entry = MagicMock()
    entry.__getitem__.side_effect = lambda key: MagicMock(
        value=values[key]
    )
    connection.entries = [entry]

    pso = get_password_settings_object(
        connection,
        distinguished_name,
    )

    connection.search.assert_called_once_with(
        search_base=distinguished_name,
        search_filter="(objectClass=*)",
        search_scope=BASE,
        attributes=list(PSO_ATTRIBUTES),
    )

    assert pso.name == "LockoutLens-Test-PSO"
    assert pso.precedence == 10
    assert pso.min_password_length == 12
    assert pso.lockout_threshold == 5
    assert pso.lockout_observation_window_seconds == 1800
    assert pso.lockout_duration_seconds == 1800


def test_get_password_settings_object_not_found():
    from unittest.mock import MagicMock

    import pytest

    from lockoutlens.ldap.exceptions import LDAPError
    from lockoutlens.ldap.pso import get_password_settings_object

    connection = MagicMock()
    connection.search.return_value = False
    connection.entries = []

    with pytest.raises(
        LDAPError,
        match="Unable to retrieve password settings object",
    ):
        get_password_settings_object(
            connection,
            "CN=Missing-PSO,DC=lab,DC=local",
        )

def test_get_password_settings_object_missing_attributes():
    from unittest.mock import MagicMock

    import pytest

    from lockoutlens.ldap.exceptions import LDAPError
    from lockoutlens.ldap.pso import get_password_settings_object

    connection = MagicMock()
    connection.search.return_value = True

    entry = MagicMock()
    entry.__getitem__.return_value = MagicMock(value=None)
    connection.entries = [entry]

    with pytest.raises(
        LDAPError,
        match="Password settings object attributes are unavailable",
    ):
        get_password_settings_object(
            connection,
            "CN=Restricted-PSO,DC=lab,DC=local",
        )

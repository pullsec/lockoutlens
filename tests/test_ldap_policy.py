from unittest.mock import MagicMock
from lockoutlens.ldap.ad import ad_interval_to_seconds

import pytest
from ldap3 import BASE
from datetime import timedelta

from lockoutlens.ldap.exceptions import LDAPError
from lockoutlens.ldap.policy import (
    DOMAIN_POLICY_ATTRIBUTES,
    DomainPolicy,
    get_domain_policy,
    normalize_domain_policy,
)

def test_get_domain_policy():
    connection = MagicMock()
    connection.search.return_value = True

    values = {
        "minPwdLength": 12,
        "pwdHistoryLength": 24,
        "minPwdAge": -864000000000,
        "maxPwdAge": -36288000000000,
        "lockoutThreshold": 5,
        "lockoutDuration": -18000000000,
        "lockoutObservationWindow": -18000000000,
    }

    entry = MagicMock()
    entry.__getitem__.side_effect = lambda attribute: MagicMock(
        value=values[attribute]
    )

    connection.entries = [entry]

    policy = get_domain_policy(
        connection,
        "DC=lab,DC=local",
    )

    connection.search.assert_called_once_with(
        search_base="DC=lab,DC=local",
        search_filter="(objectClass=*)",
        search_scope=BASE,
        attributes=list(DOMAIN_POLICY_ATTRIBUTES),
    )

    assert policy == values


def test_get_domain_policy_raises_when_search_fails():
    connection = MagicMock()
    connection.search.return_value = False
    connection.entries = []

    with pytest.raises(
        LDAPError,
        match="Unable to retrieve domain policy",
    ):
        get_domain_policy(
            connection,
            "DC=lab,DC=local",
        )


def test_get_domain_policy_raises_when_no_entry_is_returned():
    connection = MagicMock()
    connection.search.return_value = True
    connection.entries = []

    with pytest.raises(
        LDAPError,
        match="Unable to retrieve domain policy",
    ):
        get_domain_policy(
            connection,
            "DC=lab,DC=local",
        )

@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (-18_000_000_000, 1800),
        (-864_000_000_000, 86400),
        (-36_288_000_000_000, 3628800),
        (0, 0),
        (None, None),
    ],
)
def test_ad_interval_to_seconds(value, expected):
    assert ad_interval_to_seconds(value) == expected


def test_ad_interval_to_seconds_accepts_positive_value():
    assert ad_interval_to_seconds(18_000_000_000) == 1800

def test_normalize_domain_policy():
    raw_policy = {
        "minPwdLength": 12,
        "pwdHistoryLength": 24,
        "minPwdAge": -864_000_000_000,
        "maxPwdAge": -36_288_000_000_000,
        "lockoutThreshold": 5,
        "lockoutDuration": -18_000_000_000,
        "lockoutObservationWindow": -18_000_000_000,
    }

    policy = normalize_domain_policy(raw_policy)

    assert policy == DomainPolicy(
        min_password_length=12,
        password_history_length=24,
        min_password_age_seconds=86400,
        max_password_age_seconds=3628800,
        lockout_threshold=5,
        lockout_duration_seconds=1800,
        lockout_observation_window_seconds=1800,
    )

def test_normalize_domain_policy_preserves_zero_lockout_threshold():
    raw_policy = {
        "minPwdLength": 12,
        "pwdHistoryLength": 24,
        "minPwdAge": 0,
        "maxPwdAge": 0,
        "lockoutThreshold": 0,
        "lockoutDuration": 0,
        "lockoutObservationWindow": 0,
    }

    policy = normalize_domain_policy(raw_policy)

    assert policy.lockout_threshold == 0
    assert policy.lockout_duration_seconds == 0
    assert policy.lockout_observation_window_seconds == 0


def test_domain_policy_is_immutable():
    policy = DomainPolicy(
        min_password_length=12,
        password_history_length=24,
        min_password_age_seconds=86400,
        max_password_age_seconds=3628800,
        lockout_threshold=5,
        lockout_duration_seconds=1800,
        lockout_observation_window_seconds=1800,
    )

    with pytest.raises(AttributeError):
        policy.lockout_threshold = 10

def test_ad_interval_to_seconds_accepts_string_value():
    assert ad_interval_to_seconds("-18000000000") == 1800

def test_ad_interval_to_seconds_from_timedelta():
    value = timedelta(minutes=30)

    assert ad_interval_to_seconds(value) == 1800


def test_ad_interval_to_seconds_from_negative_timedelta():
    value = timedelta(minutes=-30)

    assert ad_interval_to_seconds(value) == 1800

def test_domain_policy_lockout_is_disabled_when_threshold_is_zero():
    policy = DomainPolicy(
        min_password_length=7,
        password_history_length=24,
        min_password_age_seconds=86400,
        max_password_age_seconds=3628800,
        lockout_threshold=0,
        lockout_duration_seconds=1800,
        lockout_observation_window_seconds=1800,
    )

    assert policy.lockout_enabled is False


def test_domain_policy_lockout_is_enabled_when_threshold_is_positive():
    policy = DomainPolicy(
        min_password_length=7,
        password_history_length=24,
        min_password_age_seconds=86400,
        max_password_age_seconds=3628800,
        lockout_threshold=5,
        lockout_duration_seconds=1800,
        lockout_observation_window_seconds=1800,
    )

    assert policy.lockout_enabled is True

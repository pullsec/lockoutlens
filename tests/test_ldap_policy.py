from unittest.mock import MagicMock

import pytest
from ldap3 import BASE

from lockoutlens.ldap.exceptions import LDAPError
from lockoutlens.ldap.policy import (
    DOMAIN_POLICY_ATTRIBUTES,
    ad_interval_to_seconds,
    get_domain_policy,
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

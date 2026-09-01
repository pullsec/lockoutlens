from unittest.mock import MagicMock

import pytest
from ldap3 import SUBTREE

from lockoutlens.ldap.exceptions import LDAPError

from lockoutlens.ldap.users import (
    ADUser,
    get_domain_users,
    is_account_enabled,
    normalize_ad_user,
)

def test_ad_user_model():
    user = ADUser(
        distinguished_name=(
            "CN=Alice,OU=Users,DC=lab,DC=local"
        ),
        sam_account_name="alice",
        user_principal_name="alice@lab.local",
        enabled=True,
        lockout_time=0,
    )

    assert user.distinguished_name == (
        "CN=Alice,OU=Users,DC=lab,DC=local"
    )
    assert user.sam_account_name == "alice"
    assert user.user_principal_name == "alice@lab.local"
    assert user.enabled is True


def test_ad_user_allows_missing_upn():
    user = ADUser(
        distinguished_name=(
            "CN=Service Account,OU=Users,DC=lab,DC=local"
        ),
        sam_account_name="svc_app",
        user_principal_name=None,
        enabled=True,
        lockout_time=0,
    )

    assert user.user_principal_name is None


def test_account_is_enabled():
    assert is_account_enabled(512) is True


def test_account_is_disabled():
    assert is_account_enabled(514) is False


def test_account_control_accepts_string():
    assert is_account_enabled("512") is True


def test_normalize_ad_user():
    raw_user = {
        "distinguishedName": (
            "CN=Alice,OU=Users,DC=lab,DC=local"
        ),
        "sAMAccountName": "alice",
        "userPrincipalName": "alice@lab.local",
        "userAccountControl": 512,
        "lockoutTime": 0,
    }

    user = normalize_ad_user(raw_user)

    assert user == ADUser(
        distinguished_name=(
            "CN=Alice,OU=Users,DC=lab,DC=local"
        ),
        sam_account_name="alice",
        user_principal_name="alice@lab.local",
        enabled=True,
        lockout_time=0,
    )


def test_normalize_ad_user_without_upn():
    raw_user = {
        "distinguishedName": (
            "CN=Service Account,OU=Users,DC=lab,DC=local"
        ),
        "sAMAccountName": "svc_app",
        "userPrincipalName": None,
        "userAccountControl": 514,
    }

    user = normalize_ad_user(raw_user)

    assert user.user_principal_name is None
    assert user.enabled is False


def test_get_domain_users():
    connection = MagicMock()
    connection.search.return_value = True

    entry = MagicMock()

    values = {
        "distinguishedName": (
            "CN=Alice,OU=Users,DC=lab,DC=local"
        ),
        "sAMAccountName": "alice",
        "userPrincipalName": "alice@lab.local",
        "userAccountControl": 512,
        "lockoutTime": 0,
    }

    entry.__getitem__.side_effect = lambda key: MagicMock(
        value=values[key]
    )
    connection.entries = [entry]

    users = get_domain_users(
        connection,
        "DC=lab,DC=local",
    )

    connection.search.assert_called_once_with(
        search_base="DC=lab,DC=local",
        search_filter=(
            "(&(objectCategory=person)(objectClass=user))"
        ),
        search_scope=SUBTREE,
        attributes=[
            "distinguishedName",
            "sAMAccountName",
            "userPrincipalName",
            "userAccountControl",
            "lockoutTime",
        ],
    )

    assert users == [
        ADUser(
            distinguished_name=(
                "CN=Alice,OU=Users,DC=lab,DC=local"
            ),
            sam_account_name="alice",
            user_principal_name="alice@lab.local",
            enabled=True,
            lockout_time=0,
        )
    ]


def test_get_domain_users_returns_empty_list():
    connection = MagicMock()
    connection.search.return_value = True
    connection.entries = []

    users = get_domain_users(
        connection,
        "DC=lab,DC=local",
    )

    assert users == []


def test_get_domain_users_raises_when_search_fails():
    connection = MagicMock()
    connection.search.return_value = False

    with pytest.raises(
        LDAPError,
        match="Unable to retrieve domain users",
    ):
        get_domain_users(
            connection,
            "DC=lab,DC=local",
        )

def test_ad_user_is_not_locked():
    user = ADUser(
        distinguished_name=(
            "CN=Alice,OU=Users,DC=lab,DC=local"
        ),
        sam_account_name="alice",
        user_principal_name="alice@lab.local",
        enabled=True,
        lockout_time=0,
    )

    assert user.locked is False


def test_ad_user_is_locked():
    user = ADUser(
        distinguished_name=(
            "CN=Alice,OU=Users,DC=lab,DC=local"
        ),
        sam_account_name="alice",
        user_principal_name="alice@lab.local",
        enabled=True,
        lockout_time=133_700_000_000_000_000,
    )

    assert user.locked is True

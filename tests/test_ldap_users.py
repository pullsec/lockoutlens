from unittest.mock import MagicMock
from datetime import datetime, timezone

import pytest
from ldap3 import SUBTREE

from lockoutlens.ldap.exceptions import LDAPError

from lockoutlens.ldap.users import (
    ADUser,
    get_domain_users,
    is_account_enabled,
    normalize_ad_user,
    normalize_ad_filetime_datetime,
)

def test_ad_user_model():
    user = ADUser(
        distinguished_name=(
            "CN=Alice,OU=Users,DC=lab,DC=local"
        ),
        sam_account_name="alice",
        sid="S-1-5-21-1111111111-2222222222-3333333333-1100",
        user_principal_name="alice@lab.local",
        enabled=True,
        lockout_time=0,
        bad_password_count=0,
        bad_password_time=None,
        resultant_pso=None,
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
        sid="S-1-5-21-1111111111-2222222222-3333333333-1100",
        user_principal_name=None,
        enabled=True,
        lockout_time=0,
        bad_password_count=0,
        bad_password_time=None,
        resultant_pso=None,
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
        "objectSid": "S-1-5-21-1111111111-2222222222-3333333333-1100",
        "userPrincipalName": "alice@lab.local",
        "userAccountControl": 512,
        "lockoutTime": 0,
        "badPwdCount": 0,
        "badPasswordTime": None,
        "msDS-ResultantPSO": None,
    }

    user = normalize_ad_user(raw_user)

    assert user == ADUser(
        distinguished_name=(
            "CN=Alice,OU=Users,DC=lab,DC=local"
        ),
        sam_account_name="alice",
        sid="S-1-5-21-1111111111-2222222222-3333333333-1100",
        user_principal_name="alice@lab.local",
        enabled=True,
        lockout_time=0,
        bad_password_count=0,
        bad_password_time=None,
        resultant_pso=None,
    )


def test_normalize_ad_user_without_upn():
    raw_user = {
        "distinguishedName": (
            "CN=Service Account,OU=Users,DC=lab,DC=local"
        ),
        "sAMAccountName": "svc_app",
        "objectSid": "S-1-5-21-1111111111-2222222222-3333333333-1100",
        "userPrincipalName": None,
        "userAccountControl": 514,
    }

    user = normalize_ad_user(raw_user)

    assert user.user_principal_name is None
    assert user.enabled is False


def test_normalize_ad_user_with_sid():
    raw_user = {
        "distinguishedName": (
            "CN=test,OU=LockoutLens,"
            "DC=ad,DC=lockoutlens,DC=test"
        ),
        "sAMAccountName": "test",
        "userPrincipalName": "test@ad.lockoutlens.test",
        "userAccountControl": 512,
        "objectSid": (
            "S-1-5-21-4137994730-223011928-2956659907-1103"
        ),
    }

    user = normalize_ad_user(raw_user)

    assert user.sid == (
        "S-1-5-21-4137994730-223011928-2956659907-1103"
    )


def test_get_domain_users():
    connection = MagicMock()
    connection.search.return_value = True

    entry = MagicMock()

    values = {
        "distinguishedName": (
            "CN=Alice,OU=Users,DC=lab,DC=local"
        ),
        "sAMAccountName": "alice",
        "objectSid": "S-1-5-21-1111111111-2222222222-3333333333-1100",
        "userPrincipalName": "alice@lab.local",
        "userAccountControl": 512,
        "lockoutTime": 0,
        "badPwdCount": 0,
        "badPasswordTime": None,
        "msDS-ResultantPSO": None,
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
            "objectSid",
            "lockoutTime",
            "badPwdCount",
            "badPasswordTime",
            "msDS-ResultantPSO",
        ],
    )

    assert users == [
        ADUser(
            distinguished_name=(
                "CN=Alice,OU=Users,DC=lab,DC=local"
            ),
            sam_account_name="alice",
            sid="S-1-5-21-1111111111-2222222222-3333333333-1100",
            user_principal_name="alice@lab.local",
            enabled=True,
            lockout_time=0,
            bad_password_count=0,
            bad_password_time=None,
        resultant_pso=None,
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
        sid="S-1-5-21-1111111111-2222222222-3333333333-1100",
        user_principal_name="alice@lab.local",
        enabled=True,
        lockout_time=0,
        bad_password_count=0,
        bad_password_time=None,
        resultant_pso=None,
    )

    assert user.locked is False


def test_ad_user_is_locked():
    user = ADUser(
        distinguished_name=(
            "CN=Alice,OU=Users,DC=lab,DC=local"
        ),
        sam_account_name="alice",
        sid="S-1-5-21-1111111111-2222222222-3333333333-1100",
        user_principal_name="alice@lab.local",
        enabled=True,
        lockout_time=133_700_000_000_000_000,
        bad_password_count=0,
        bad_password_time=None,
        resultant_pso=None,
    )

    assert user.locked is True


def test_normalize_ad_user_with_bad_password_count():
    raw_user = {
        "distinguishedName": (
            "CN=Alice,OU=Users,DC=lab,DC=local"
        ),
        "sAMAccountName": "alice",
        "objectSid": "S-1-5-21-1111111111-2222222222-3333333333-1100",
        "userPrincipalName": "alice@lab.local",
        "userAccountControl": 512,
        "lockoutTime": 0,
        "badPwdCount": 3,
    }

    user = normalize_ad_user(raw_user)

    assert user.bad_password_count == 3


def test_normalize_ad_user_with_bad_password_time():
    bad_password_time = datetime(
        2026,
        9,
        1,
        20,
        30,
        0,
    )

    raw_user = {
        "distinguishedName": (
            "CN=Alice,OU=Users,DC=lab,DC=local"
        ),
        "sAMAccountName": "alice",
        "objectSid": "S-1-5-21-1111111111-2222222222-3333333333-1100",
        "userPrincipalName": "alice@lab.local",
        "userAccountControl": 512,
        "lockoutTime": 0,
        "badPwdCount": 2,
        "badPasswordTime": bad_password_time,
    }

    user = normalize_ad_user(raw_user)

    assert user.bad_password_time == bad_password_time


def test_normalize_ad_filetime_datetime():
    value = datetime(
        2026,
        9,
        1,
        20,
        22,
        52,
        tzinfo=timezone.utc,
    )

    assert normalize_ad_filetime_datetime(value) == value


def test_normalize_ad_filetime_datetime_zero_filetime():
    value = datetime(
        1601,
        1,
        1,
        tzinfo=timezone.utc,
    )

    assert normalize_ad_filetime_datetime(value) is None


def test_normalize_ad_user_with_resultant_pso():
    raw_user = {
        "distinguishedName": (
            "CN=Alice,OU=Users,DC=lab,DC=local"
        ),
        "sAMAccountName": "alice",
        "objectSid": "S-1-5-21-1111111111-2222222222-3333333333-1100",
        "userPrincipalName": "alice@lab.local",
        "userAccountControl": 512,
        "lockoutTime": 0,
        "badPwdCount": 0,
        "badPasswordTime": None,
        "msDS-ResultantPSO": (
            "CN=StrictPolicy,CN=Password Settings Container,"
            "CN=System,DC=lab,DC=local"
        ),
    }

    user = normalize_ad_user(raw_user)

    assert user.resultant_pso == (
        "CN=StrictPolicy,CN=Password Settings Container,"
        "CN=System,DC=lab,DC=local"
    )

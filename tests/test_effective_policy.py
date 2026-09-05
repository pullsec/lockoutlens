from lockoutlens.ldap.policy import DomainPolicy

from unittest.mock import MagicMock, patch

from lockoutlens.ldap.effective_policy import (
    EffectivePolicy,
    resolve_effective_policy,
)

from lockoutlens.ldap.pso import PasswordSettingsObject
from lockoutlens.ldap.users import ADUser


def test_effective_policy_domain_source():
    domain_policy = DomainPolicy(
        min_password_length=12,
        password_history_length=24,
        min_password_age_seconds=86400,
        max_password_age_seconds=3628800,
        lockout_threshold=0,
        lockout_duration_seconds=1800,
        lockout_observation_window_seconds=1800,
    )

    effective = EffectivePolicy(
        source="domain",
        policy=domain_policy,
    )

    assert effective.source == "domain"
    assert effective.policy is domain_policy

def make_domain_policy() -> DomainPolicy:
    return DomainPolicy(
        min_password_length=12,
        password_history_length=24,
        min_password_age_seconds=86400,
        max_password_age_seconds=3628800,
        lockout_threshold=0,
        lockout_duration_seconds=1800,
        lockout_observation_window_seconds=1800,
    )


def make_user(
    resultant_pso: str | None,
) -> ADUser:
    return ADUser(
        distinguished_name="CN=test,DC=lab,DC=local",
        sam_account_name="test",
        user_principal_name="test@lab.local",
        enabled=True,
        lockout_time=0,
        bad_password_count=0,
        bad_password_time=None,
        resultant_pso=resultant_pso,
    )


def test_effective_policy_domain_source():
    domain_policy = make_domain_policy()

    effective = EffectivePolicy(
        source="domain",
        policy=domain_policy,
    )

    assert effective.source == "domain"
    assert effective.policy is domain_policy


def test_resolve_effective_policy_uses_domain_policy():
    connection = MagicMock()
    domain_policy = make_domain_policy()
    user = make_user(resultant_pso=None)

    effective = resolve_effective_policy(
        connection,
        user,
        domain_policy,
    )

    assert effective.source == "domain"
    assert effective.policy is domain_policy


def test_resolve_effective_policy_uses_resultant_pso():
    connection = MagicMock()
    domain_policy = make_domain_policy()

    pso_dn = (
        "CN=LockoutLens-Test-PSO,"
        "CN=Password Settings Container,"
        "CN=System,DC=lab,DC=local"
    )

    user = make_user(resultant_pso=pso_dn)

    pso = PasswordSettingsObject(
        distinguished_name=pso_dn,
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

    with patch(
        "lockoutlens.ldap.effective_policy."
        "get_password_settings_object",
        return_value=pso,
    ) as get_pso:
        effective = resolve_effective_policy(
            connection,
            user,
            domain_policy,
        )

    get_pso.assert_called_once_with(
        connection,
        pso_dn,
    )

    assert effective.source == "pso"
    assert effective.policy is pso

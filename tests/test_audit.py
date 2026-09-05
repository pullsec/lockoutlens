from datetime import datetime, timezone

from lockoutlens.audit import audit_account
from lockoutlens.ldap.effective_policy import EffectivePolicy
from lockoutlens.ldap.policy import DomainPolicy
from lockoutlens.ldap.users import ADUser


def test_audit_safe_standard_account_is_planned_for_assessment():
    user = ADUser(
        distinguished_name="CN=auditor,DC=lab,DC=local",
        sam_account_name="auditor",
        sid="S-1-5-21-1111111111-2222222222-3333333333-1103",
        user_principal_name="auditor@lab.local",
        enabled=True,
        lockout_time=0,
        bad_password_count=0,
        bad_password_time=None,
        resultant_pso=None,
    )
    policy = DomainPolicy(
        min_password_length=8,
        password_history_length=24,
        min_password_age_seconds=0,
        max_password_age_seconds=3628800,
        lockout_threshold=0,
        lockout_duration_seconds=1800,
        lockout_observation_window_seconds=1800,
    )
    effective_policy = EffectivePolicy(
        source="domain",
        policy=policy,
    )

    result = audit_account(
        user,
        effective_policy,
        now=datetime(
            2026,
            9,
            5,
            8,
            0,
            tzinfo=timezone.utc,
        ),
    )

    assert result.plan.sam_account_name == "auditor"
    assert result.plan.action == "assess"
    assert result.plan.reason == "safety_assessment_passed"

    assert result.assessment.status == "safe"
    assert result.assessment.reason == "lockout_disabled"
    assert result.assessment.lockout_enabled is False
    assert result.assessment.lockout_threshold == 0
    assert result.assessment.bad_password_count == 0


def test_audit_builtin_administrator_is_skipped_even_when_lockout_disabled():
    user = ADUser(
        distinguished_name="CN=renamed-admin,DC=lab,DC=local",
        sam_account_name="renamed-admin",
        sid="S-1-5-21-1111111111-2222222222-3333333333-500",
        user_principal_name=None,
        enabled=True,
        lockout_time=0,
        bad_password_count=0,
        bad_password_time=None,
        resultant_pso=None,
    )
    policy = DomainPolicy(
        min_password_length=8,
        password_history_length=24,
        min_password_age_seconds=0,
        max_password_age_seconds=3628800,
        lockout_threshold=0,
        lockout_duration_seconds=1800,
        lockout_observation_window_seconds=1800,
    )
    effective_policy = EffectivePolicy(
        source="domain",
        policy=policy,
    )

    result = audit_account(
        user,
        effective_policy,
        now=datetime(
            2026,
            9,
            5,
            8,
            0,
            tzinfo=timezone.utc,
        ),
    )

    assert result.plan.sam_account_name == "renamed-admin"
    assert result.plan.action == "skip"
    assert result.plan.reason == "builtin_administrator"


def test_audit_standard_account_is_skipped_when_locked():
    user = ADUser(
        distinguished_name="CN=auditor,DC=lab,DC=local",
        sam_account_name="auditor",
        sid="S-1-5-21-1111111111-2222222222-3333333333-1103",
        user_principal_name="auditor@lab.local",
        enabled=True,
        lockout_time=1,
        bad_password_count=0,
        bad_password_time=None,
        resultant_pso=None,
    )
    policy = DomainPolicy(
        min_password_length=8,
        password_history_length=24,
        min_password_age_seconds=0,
        max_password_age_seconds=3628800,
        lockout_threshold=5,
        lockout_duration_seconds=1800,
        lockout_observation_window_seconds=1800,
    )
    effective_policy = EffectivePolicy(
        source="domain",
        policy=policy,
    )

    result = audit_account(
        user,
        effective_policy,
        now=datetime(
            2026,
            9,
            5,
            8,
            0,
            tzinfo=timezone.utc,
        ),
    )

    assert result.plan.sam_account_name == "auditor"
    assert result.plan.action == "skip"
    assert result.plan.reason == "account_locked"

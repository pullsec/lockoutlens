from datetime import UTC, datetime
from lockoutlens.ldap.effective_policy import EffectivePolicy
from lockoutlens.ldap.policy import DomainPolicy
from lockoutlens.ldap.users import ADUser
from lockoutlens.safety import (
    LockoutAssessment,
    assess_lockout_risk,
)


NOW = datetime(
    2026,
    9,
    5,
    12,
    0,
    0,
    tzinfo=UTC,
)


def make_user(
    bad_password_count: int = 0,
    *,
    enabled: bool = True,
    lockout_time: int = 0,
    bad_password_time: datetime | None = None,
) -> ADUser:
    return ADUser(
        distinguished_name="CN=test,DC=lab,DC=local",
        sam_account_name="test",
        sid="S-1-5-21-1111111111-2222222222-3333333333-1100",
        user_principal_name="test@lab.local",
        enabled=enabled,
        lockout_time=lockout_time,
        bad_password_count=bad_password_count,
        bad_password_time=bad_password_time,
        resultant_pso=None,
    )


def test_lockout_assessment_safe():
    assessment = LockoutAssessment(
        status="safe",
        reason="no_recent_bad_passwords",
        lockout_enabled=True,
        lockout_threshold=5,
        bad_password_count=0,
    )

    assert assessment.status == "safe"
    assert assessment.safe is True


def test_lockout_assessment_unsafe():
    assessment = LockoutAssessment(
        status="unsafe",
        reason="recent_bad_password_activity",
        lockout_enabled=True,
        lockout_threshold=5,
        bad_password_count=4,
    )

    assert assessment.safe is False


def test_lockout_assessment_unknown():
    assessment = LockoutAssessment(
        status="unknown",
        reason="insufficient_information",
        lockout_enabled=True,
        lockout_threshold=5,
        bad_password_count=1,
    )

    assert assessment.safe is False


def test_assess_lockout_risk_rejects_disabled_account():
    user = make_user(
        enabled=False,
        bad_password_count=0,
    )

    effective_policy = EffectivePolicy(
        source="domain",
        policy=make_domain_policy(lockout_threshold=0),
    )

    assessment = assess_lockout_risk(
        user,
        effective_policy,
        now=NOW,
    )

    assert assessment.status == "unsafe"
    assert assessment.reason == "account_disabled"
    assert assessment.safe is False


def test_assess_lockout_risk_rejects_locked_account():
    user = make_user(
        lockout_time=1,
        bad_password_count=5,
    )

    effective_policy = EffectivePolicy(
        source="domain",
        policy=make_domain_policy(lockout_threshold=5),
    )

    assessment = assess_lockout_risk(
        user,
        effective_policy,
        now=NOW,
    )

    assert assessment.status == "unsafe"
    assert assessment.reason == "account_locked"
    assert assessment.safe is False


def make_domain_policy(
    lockout_threshold: int,
    *,
    lockout_observation_window_seconds: int | None = 1800,
) -> DomainPolicy:
    return DomainPolicy(
        min_password_length=12,
        password_history_length=24,
        min_password_age_seconds=0,
        max_password_age_seconds=3_628_800,
        lockout_threshold=lockout_threshold,
        lockout_duration_seconds=1800,
        lockout_observation_window_seconds=(
            lockout_observation_window_seconds
        ),
    )


def test_assess_lockout_risk_when_lockout_disabled():
    user = make_user(bad_password_count=0)

    effective_policy = EffectivePolicy(
        source="domain",
        policy=make_domain_policy(lockout_threshold=0),
    )

    assessment = assess_lockout_risk(
        user,
        effective_policy,
        now=NOW,
    )

    assert assessment.status == "safe"
    assert assessment.reason == "lockout_disabled"
    assert assessment.lockout_enabled is False
    assert assessment.lockout_threshold == 0
    assert assessment.safe is True


def test_assess_lockout_risk_with_zero_bad_password_count():
    user = make_user(
        bad_password_count=0,
    )

    effective_policy = EffectivePolicy(
        source="domain",
        policy=make_domain_policy(lockout_threshold=5),
    )

    assessment = assess_lockout_risk(
        user,
        effective_policy,
        now=NOW,
    )

    assert assessment.status == "safe"
    assert assessment.reason == "no_bad_passwords"
    assert assessment.safe is True


def test_assess_lockout_risk_with_missing_bad_password_time():
    user = make_user(
        bad_password_count=1,
    )

    effective_policy = EffectivePolicy(
        source="domain",
        policy=make_domain_policy(lockout_threshold=5),
    )

    assessment = assess_lockout_risk(
        user,
        effective_policy,
        now=NOW,
    )

    assert assessment.status == "unknown"
    assert assessment.reason == "missing_bad_password_time"
    assert assessment.safe is False


def test_assess_lockout_risk_with_recent_bad_password():
    user = make_user(
        bad_password_count=1,
        bad_password_time=datetime(
            2026,
            9,
            5,
            11,
            50,
            0,
            tzinfo=UTC,
        ),
    )

    effective_policy = EffectivePolicy(
        source="domain",
        policy=make_domain_policy(lockout_threshold=5),
    )

    assessment = assess_lockout_risk(
        user,
        effective_policy,
        now=NOW,
    )

    assert assessment.status == "unsafe"
    assert assessment.reason == "bad_password_within_observation_window"
    assert assessment.safe is False


def test_assess_lockout_risk_with_bad_password_outside_observation_window():
    user = make_user(
        bad_password_count=1,
        bad_password_time=datetime(
            2026,
            9,
            5,
            11,
            0,
            0,
            tzinfo=UTC,
        ),
    )

    effective_policy = EffectivePolicy(
        source="domain",
        policy=make_domain_policy(lockout_threshold=5),
    )

    assessment = assess_lockout_risk(
        user,
        effective_policy,
        now=NOW,
    )

    assert assessment.status == "unknown"
    assert assessment.reason == "bad_password_outside_observation_window"
    assert assessment.safe is False


def test_assess_lockout_risk_with_future_bad_password_time():
    user = make_user(
        bad_password_count=1,
        bad_password_time=datetime(
            2026,
            9,
            5,
            12,
            5,
            0,
            tzinfo=UTC,
        ),
    )

    effective_policy = EffectivePolicy(
        source="domain",
        policy=make_domain_policy(lockout_threshold=5),
    )

    assessment = assess_lockout_risk(
        user,
        effective_policy,
        now=NOW,
    )

    assert assessment.status == "unknown"
    assert assessment.reason == "future_bad_password_time"
    assert assessment.safe is False


def test_assess_lockout_risk_with_naive_bad_password_time():
    user = make_user(
        bad_password_count=1,
        bad_password_time=datetime(
            2026,
            9,
            5,
            11,
            50,
            0,
        ),
    )

    effective_policy = EffectivePolicy(
        source="domain",
        policy=make_domain_policy(lockout_threshold=5),
    )

    assessment = assess_lockout_risk(
        user,
        effective_policy,
        now=NOW,
    )

    assert assessment.status == "unknown"
    assert assessment.reason == "invalid_bad_password_time"
    assert assessment.safe is False


def test_assess_lockout_risk_with_naive_now():
    user = make_user(
        bad_password_count=1,
        bad_password_time=datetime(
            2026,
            9,
            5,
            11,
            50,
            0,
            tzinfo=UTC,
        ),
    )

    effective_policy = EffectivePolicy(
        source="domain",
        policy=make_domain_policy(lockout_threshold=5),
    )

    assessment = assess_lockout_risk(
        user,
        effective_policy,
        now=datetime(
            2026,
            9,
            5,
            12,
            0,
            0,
        ),
    )

    assert assessment.status == "unknown"
    assert assessment.reason == "invalid_current_time"
    assert assessment.safe is False


def test_assess_lockout_risk_with_missing_observation_window():
    user = make_user(
        bad_password_count=1,
        bad_password_time=datetime(
            2026,
            9,
            5,
            11,
            50,
            0,
            tzinfo=UTC,
        ),
    )

    effective_policy = EffectivePolicy(
        source="domain",
        policy=make_domain_policy(
            lockout_threshold=5,
            lockout_observation_window_seconds=None,
        ),
    )

    assessment = assess_lockout_risk(
        user,
        effective_policy,
        now=NOW,
    )

    assert assessment.status == "unknown"
    assert assessment.reason == "missing_observation_window"
    assert assessment.safe is False

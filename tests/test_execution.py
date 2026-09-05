from lockoutlens.execution import authorize_attempt
from lockoutlens.safety import LockoutAssessment
from lockoutlens.eligibility import AccountEligibility


def test_unknown_lockout_assessment_blocks_attempt():
    assessment = LockoutAssessment(
        status="unknown",
        reason="missing_bad_password_time",
        lockout_enabled=True,
        lockout_threshold=5,
        bad_password_count=1,
    )

    decision = authorize_attempt(assessment)

    assert decision.allowed is False
    assert decision.reason == "lockout_risk_unknown"


def test_unsafe_lockout_assessment_blocks_attempt():
    assessment = LockoutAssessment(
        status="unsafe",
        reason="account_locked",
        lockout_enabled=True,
        lockout_threshold=5,
        bad_password_count=2,
    )

    decision = authorize_attempt(assessment)

    assert decision.allowed is False
    assert decision.reason == "account_locked"


def test_safe_lockout_assessment_allows_attempt():
    assessment = LockoutAssessment(
        status="safe",
        reason="no_bad_passwords",
        lockout_enabled=True,
        lockout_threshold=5,
        bad_password_count=0,
    )

    eligibility = AccountEligibility(
        status="eligible",
        reason="safety_assessment_passed",
    )

    decision = authorize_attempt(
        assessment,
        eligibility,
    )

    assert decision.allowed is True
    assert decision.reason == "lockout_assessment_safe"


def test_ineligible_account_blocks_attempt_even_when_lockout_safe():
    assessment = LockoutAssessment(
        status="safe",
        reason="lockout_disabled",
        lockout_enabled=False,
        lockout_threshold=0,
        bad_password_count=0,
    )

    eligibility = AccountEligibility(
        status="ineligible",
        reason="builtin_administrator",
    )

    decision = authorize_attempt(
        assessment,
        eligibility,
    )

    assert decision.allowed is False
    assert decision.reason == "builtin_administrator"


def test_missing_eligibility_blocks_attempt():
    assessment = LockoutAssessment(
        status="safe",
        reason="no_bad_passwords",
        lockout_enabled=True,
        lockout_threshold=5,
        bad_password_count=0,
    )

    decision = authorize_attempt(assessment)

    assert decision.allowed is False
    assert decision.reason == "eligibility_unknown"

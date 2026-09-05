from lockoutlens.eligibility import (
    AccountEligibility,
    assess_account_eligibility,
)
from lockoutlens.safety import LockoutAssessment

def test_account_eligibility_eligible():
    eligibility = AccountEligibility(
        status="eligible",
        reason="safety_assessment_passed",
    )

    assert eligibility.status == "eligible"
    assert eligibility.reason == "safety_assessment_passed"
    assert eligibility.eligible is True


def test_account_is_eligible_when_lockout_assessment_is_safe():
    assessment = LockoutAssessment(
        status="safe",
        reason="no_bad_passwords",
        lockout_enabled=True,
        lockout_threshold=5,
        bad_password_count=0,
    )

    eligibility = assess_account_eligibility(assessment)

    assert eligibility.status == "eligible"
    assert eligibility.reason == "safety_assessment_passed"
    assert eligibility.eligible is True


def test_account_is_ineligible_when_lockout_assessment_is_unsafe():
    assessment = LockoutAssessment(
        status="unsafe",
        reason="account_locked",
        lockout_enabled=True,
        lockout_threshold=5,
        bad_password_count=5,
    )

    eligibility = assess_account_eligibility(assessment)

    assert eligibility.status == "ineligible"
    assert eligibility.reason == "account_locked"
    assert eligibility.eligible is False


def test_account_is_ineligible_when_lockout_assessment_is_unknown():
    assessment = LockoutAssessment(
        status="unknown",
        reason="missing_bad_password_time",
        lockout_enabled=True,
        lockout_threshold=5,
        bad_password_count=1,
    )

    eligibility = assess_account_eligibility(assessment)

    assert eligibility.status == "ineligible"
    assert eligibility.reason == "missing_bad_password_time"
    assert eligibility.eligible is False

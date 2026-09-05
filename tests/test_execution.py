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
        attempts_for_account=0,
        max_attempts_per_account=1,
        total_attempts=0,
        max_total_attempts=10,
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


def test_exhausted_account_attempt_budget_blocks_attempt():
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
        attempts_for_account=1,
        max_attempts_per_account=1,
    )

    assert decision.allowed is False
    assert decision.reason == "account_attempt_limit_reached"


def test_missing_attempt_budget_blocks_attempt():
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

    assert decision.allowed is False
    assert decision.reason == "attempt_budget_unknown"


def test_negative_account_attempt_count_blocks_attempt():
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
        attempts_for_account=-1,
        max_attempts_per_account=1,
    )

    assert decision.allowed is False
    assert decision.reason == "invalid_attempt_budget"

def test_zero_account_attempt_limit_blocks_attempt_as_invalid():
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
        attempts_for_account=0,
        max_attempts_per_account=0,
    )

    assert decision.allowed is False
    assert decision.reason == "invalid_attempt_budget"


def test_negative_account_attempt_limit_blocks_attempt_as_invalid():
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
        attempts_for_account=0,
        max_attempts_per_account=-1,
    )

    assert decision.allowed is False
    assert decision.reason == "invalid_attempt_budget"


def test_exhausted_global_attempt_budget_blocks_attempt():
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
        attempts_for_account=0,
        max_attempts_per_account=1,
        total_attempts=10,
        max_total_attempts=10,
    )

    assert decision.allowed is False
    assert decision.reason == "global_attempt_limit_reached"


def test_missing_global_attempt_budget_blocks_attempt():
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
        attempts_for_account=0,
        max_attempts_per_account=1,
    )

    assert decision.allowed is False
    assert decision.reason == "global_attempt_budget_unknown"

def test_negative_total_attempt_count_blocks_attempt():
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
        attempts_for_account=0,
        max_attempts_per_account=1,
        total_attempts=-1,
        max_total_attempts=10,
    )

    assert decision.allowed is False
    assert decision.reason == "invalid_global_attempt_budget"

def test_zero_global_attempt_limit_blocks_attempt_as_invalid():
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
        attempts_for_account=0,
        max_attempts_per_account=1,
        total_attempts=0,
        max_total_attempts=0,
    )

    assert decision.allowed is False
    assert decision.reason == "invalid_global_attempt_budget"


def test_negative_global_attempt_limit_blocks_attempt_as_invalid():
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
        attempts_for_account=0,
        max_attempts_per_account=1,
        total_attempts=0,
        max_total_attempts=-1,
    )

    assert decision.allowed is False
    assert decision.reason == "invalid_global_attempt_budget"

def test_attempt_budget_tracks_account_and_global_limits():
    from lockoutlens.execution import AttemptBudget

    budget = AttemptBudget(
        attempts_for_account=0,
        max_attempts_per_account=1,
        total_attempts=0,
        max_total_attempts=10,
    )

    assert budget.attempts_for_account == 0
    assert budget.max_attempts_per_account == 1
    assert budget.total_attempts == 0
    assert budget.max_total_attempts == 10

def test_authorize_attempt_accepts_attempt_budget():
    from lockoutlens.execution import AttemptBudget

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

    budget = AttemptBudget(
        attempts_for_account=0,
        max_attempts_per_account=1,
        total_attempts=0,
        max_total_attempts=10,
    )

    decision = authorize_attempt(
        assessment,
        eligibility,
        budget=budget,
    )

    assert decision.allowed is True
    assert decision.reason == "lockout_assessment_safe"

def test_attempt_budget_conflicts_with_legacy_budget_arguments():
    from lockoutlens.execution import AttemptBudget

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

    budget = AttemptBudget(
        attempts_for_account=0,
        max_attempts_per_account=1,
        total_attempts=0,
        max_total_attempts=10,
    )

    decision = authorize_attempt(
        assessment,
        eligibility,
        attempts_for_account=0,
        budget=budget,
    )

    assert decision.allowed is False
    assert decision.reason == "conflicting_attempt_budget"

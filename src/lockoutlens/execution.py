from dataclasses import dataclass

from lockoutlens.safety import LockoutAssessment
from lockoutlens.eligibility import AccountEligibility


@dataclass(frozen=True)
class ExecutionDecision:
    """Decision controlling whether an authentication attempt is allowed."""

    allowed: bool
    reason: str


def authorize_attempt(
    assessment: LockoutAssessment,
    eligibility: AccountEligibility | None = None,
    *,
    attempts_for_account: int | None = None,
    max_attempts_per_account: int | None = None,
    total_attempts: int | None = None,
    max_total_attempts: int | None = None,
) -> ExecutionDecision:
    """Authorize an attempt only when all execution safety gates pass."""
    if assessment.status == "unknown":
        return ExecutionDecision(
            allowed=False,
            reason="lockout_risk_unknown",
        )

    if assessment.status == "unsafe":
        return ExecutionDecision(
            allowed=False,
            reason=assessment.reason,
        )

    if eligibility is None:
        return ExecutionDecision(
            allowed=False,
            reason="eligibility_unknown",
        )

    if not eligibility.eligible:
        return ExecutionDecision(
            allowed=False,
            reason=eligibility.reason,
        )

    if (
        attempts_for_account is None
        or max_attempts_per_account is None
    ):
        return ExecutionDecision(
            allowed=False,
            reason="attempt_budget_unknown",
        )

    if (
        attempts_for_account < 0
        or max_attempts_per_account <= 0
    ):
        return ExecutionDecision(
            allowed=False,
            reason="invalid_attempt_budget",
        )

    if attempts_for_account >= max_attempts_per_account:
        return ExecutionDecision(
            allowed=False,
            reason="account_attempt_limit_reached",
        )

    if (
        total_attempts is None
        or max_total_attempts is None
    ):
        return ExecutionDecision(
            allowed=False,
            reason="global_attempt_budget_unknown",
        )

    if (
        total_attempts < 0
        or max_total_attempts <= 0
    ):
        return ExecutionDecision(
            allowed=False,
            reason="invalid_global_attempt_budget",
        )

    if total_attempts >= max_total_attempts:
        return ExecutionDecision(
            allowed=False,
            reason="global_attempt_limit_reached",
        )

    return ExecutionDecision(
        allowed=True,
        reason="lockout_assessment_safe",
    )

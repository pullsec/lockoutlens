from dataclasses import dataclass

from lockoutlens.safety import LockoutAssessment
from lockoutlens.eligibility import AccountEligibility


@dataclass(frozen=True)
class AttemptBudget:
    """Attempt limits and counters for an execution campaign."""

    attempts_for_account: int
    max_attempts_per_account: int
    total_attempts: int
    max_total_attempts: int


def consume_attempt(budget: AttemptBudget) -> AttemptBudget:
    """Return a new budget with one account and global attempt consumed."""
    return AttemptBudget(
        attempts_for_account=budget.attempts_for_account + 1,
        max_attempts_per_account=budget.max_attempts_per_account,
        total_attempts=budget.total_attempts + 1,
        max_total_attempts=budget.max_total_attempts,
    )


@dataclass(frozen=True)
class ExecutionDecision:
    """Decision controlling whether an authentication attempt is allowed."""

    allowed: bool
    reason: str


@dataclass(frozen=True)
class ExecutionResult:
    """Result of an authentication attempt."""

    status: str
    username: str
    reason: str


def authorize_attempt(
    assessment: LockoutAssessment,
    eligibility: AccountEligibility | None = None,
    *,
    attempts_for_account: int | None = None,
    max_attempts_per_account: int | None = None,
    total_attempts: int | None = None,
    max_total_attempts: int | None = None,
    budget: AttemptBudget | None = None,
) -> ExecutionDecision:
    """Authorize an attempt only when all execution safety gates pass."""
    if budget is not None and any(
        value is not None
        for value in (
            attempts_for_account,
            max_attempts_per_account,
            total_attempts,
            max_total_attempts,
        )
    ):
        return ExecutionDecision(
            allowed=False,
            reason="conflicting_attempt_budget",
        )

    if budget is not None:
        attempts_for_account = budget.attempts_for_account
        max_attempts_per_account = budget.max_attempts_per_account
        total_attempts = budget.total_attempts
        max_total_attempts = budget.max_total_attempts

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


def execute_attempt(
    *,
    username: str,
    assessment: LockoutAssessment,
    eligibility: AccountEligibility,
    budget: AttemptBudget,
    authenticator,
) -> tuple[ExecutionResult, AttemptBudget]:
    """Execute an authentication attempt only when authorization allows it."""
    decision = authorize_attempt(
        assessment,
        eligibility,
        budget=budget,
    )

    if not decision.allowed:
        return (
            ExecutionResult(
                status="skipped",
                username=username,
                reason=decision.reason,
            ),
            budget,
        )

    authenticated = authenticator(username)

    if authenticated:
        return (
            ExecutionResult(
                status="success",
                username=username,
                reason="authentication_succeeded",
            ),
            consume_attempt(budget),
        )

    return (
        ExecutionResult(
            status="failure",
            username=username,
            reason="authentication_failed",
        ),
        consume_attempt(budget),
    )

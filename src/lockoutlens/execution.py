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
) -> ExecutionDecision:
    """Authorize an attempt only when lockout risk is known to be safe."""
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

    return ExecutionDecision(
        allowed=True,
        reason="lockout_assessment_safe",
    )

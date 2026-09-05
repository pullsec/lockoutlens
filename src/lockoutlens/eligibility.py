from dataclasses import dataclass
from typing import Literal
from lockoutlens.safety import LockoutAssessment
from lockoutlens.classification import AccountClassification


EligibilityStatus = Literal[
    "eligible",
    "ineligible",
]


@dataclass(frozen=True)
class AccountEligibility:
    """Eligibility of an account for a planned assessment."""

    status: EligibilityStatus
    reason: str

    @property
    def eligible(self) -> bool:
        """Return whether the account is eligible for planning."""
        return self.status == "eligible"


def assess_account_eligibility(
    assessment: LockoutAssessment,
    classification: AccountClassification,
) -> AccountEligibility:
    """Assess whether an account is eligible for planning."""
    if classification.kind != "standard":
        return AccountEligibility(
            status="ineligible",
            reason=classification.kind,
        )

    if assessment.safe:
        return AccountEligibility(
            status="eligible",
            reason="safety_assessment_passed",
        )

    return AccountEligibility(
        status="ineligible",
        reason=assessment.reason,
    )

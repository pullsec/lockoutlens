from dataclasses import dataclass
from typing import Literal

from lockoutlens.eligibility import AccountEligibility
from lockoutlens.ldap.users import ADUser


PlanAction = Literal[
    "assess",
    "skip",
]


@dataclass(frozen=True)
class AccountPlan:
    """Planned action for an Active Directory account."""
    sam_account_name: str
    action: PlanAction
    reason: str


def plan_account(
    user: ADUser,
    eligibility: AccountEligibility,
) -> AccountPlan:
    """Build a dry-run assessment plan for an account."""
    action: PlanAction = (
        "assess"
        if eligibility.eligible
        else "skip"
    )

    return AccountPlan(
        sam_account_name=user.sam_account_name,
        action=action,
        reason=eligibility.reason,
    )


def plan_accounts(
    accounts: list[tuple[ADUser, AccountEligibility]],
) -> list[AccountPlan]:
    """Build dry-run assessment plans for multiple accounts."""
    return [
        plan_account(user, eligibility)
        for user, eligibility in accounts
    ]

from dataclasses import dataclass
from datetime import datetime

from lockoutlens.classification import classify_account
from lockoutlens.eligibility import assess_account_eligibility
from lockoutlens.ldap.effective_policy import EffectivePolicy
from lockoutlens.ldap.users import ADUser
from lockoutlens.planner import AccountPlan, plan_account
from lockoutlens.safety import LockoutAssessment, assess_lockout_risk


@dataclass(frozen=True)
class AccountAuditResult:
    """Dry-run audit result for an Active Directory account."""

    plan: AccountPlan
    assessment: LockoutAssessment


def audit_account(
    user: ADUser,
    effective_policy: EffectivePolicy,
    *,
    now: datetime,
) -> AccountAuditResult:
    """Build a dry-run assessment plan for an Active Directory account."""
    classification = classify_account(user)

    assessment = assess_lockout_risk(
        user,
        effective_policy,
        now=now,
    )

    eligibility = assess_account_eligibility(
        assessment,
        classification,
    )

    plan = plan_account(
        user,
        eligibility,
    )

    return AccountAuditResult(
        plan=plan,
        assessment=assessment,
    )

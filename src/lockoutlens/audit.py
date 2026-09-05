from datetime import datetime

from lockoutlens.classification import classify_account
from lockoutlens.eligibility import assess_account_eligibility
from lockoutlens.ldap.effective_policy import EffectivePolicy
from lockoutlens.ldap.users import ADUser
from lockoutlens.planner import AccountPlan, plan_account
from lockoutlens.safety import assess_lockout_risk


def audit_account(
    user: ADUser,
    effective_policy: EffectivePolicy,
    *,
    now: datetime,
) -> AccountPlan:
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

    return plan_account(
        user,
        eligibility,
    )

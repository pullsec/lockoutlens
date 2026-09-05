from lockoutlens.eligibility import AccountEligibility
from lockoutlens.ldap.users import ADUser
from lockoutlens.planner import plan_account, plan_accounts


def test_plan_eligible_account_for_assessment():
    user = ADUser(
        distinguished_name="CN=auditor,DC=lab,DC=local",
        sam_account_name="auditor",
        sid="S-1-5-21-1111111111-2222222222-3333333333-1103",
        user_principal_name="auditor@lab.local",
        enabled=True,
        lockout_time=0,
        bad_password_count=0,
        bad_password_time=None,
        resultant_pso=None,
    )
    eligibility = AccountEligibility(
        status="eligible",
        reason="safety_assessment_passed",
    )

    plan = plan_account(
        user,
        eligibility,
    )

    assert plan.sam_account_name == "auditor"
    assert plan.action == "assess"
    assert plan.reason == "safety_assessment_passed"


def test_plan_ineligible_account_is_skipped():
    user = ADUser(
        distinguished_name="CN=Administrator,DC=lab,DC=local",
        sam_account_name="Administrator",
        sid="S-1-5-21-1111111111-2222222222-3333333333-500",
        user_principal_name=None,
        enabled=True,
        lockout_time=0,
        bad_password_count=0,
        bad_password_time=None,
        resultant_pso=None,
    )
    eligibility = AccountEligibility(
        status="ineligible",
        reason="builtin_administrator",
    )

    plan = plan_account(
        user,
        eligibility,
    )

    assert plan.sam_account_name == "Administrator"
    assert plan.action == "skip"
    assert plan.reason == "builtin_administrator"


def test_plan_multiple_accounts():
    eligible_user = ADUser(
        distinguished_name="CN=auditor,DC=lab,DC=local",
        sam_account_name="auditor",
        sid="S-1-5-21-1111111111-2222222222-3333333333-1103",
        user_principal_name="auditor@lab.local",
        enabled=True,
        lockout_time=0,
        bad_password_count=0,
        bad_password_time=None,
        resultant_pso=None,
    )
    skipped_user = ADUser(
        distinguished_name="CN=Administrator,DC=lab,DC=local",
        sam_account_name="Administrator",
        sid="S-1-5-21-1111111111-2222222222-3333333333-500",
        user_principal_name=None,
        enabled=True,
        lockout_time=0,
        bad_password_count=0,
        bad_password_time=None,
        resultant_pso=None,
    )

    plans = plan_accounts(
        [
            (
                eligible_user,
                AccountEligibility(
                    status="eligible",
                    reason="safety_assessment_passed",
                ),
            ),
            (
                skipped_user,
                AccountEligibility(
                    status="ineligible",
                    reason="builtin_administrator",
                ),
            ),
        ]
    )

    assert [plan.action for plan in plans] == [
        "assess",
        "skip",
    ]
    assert [plan.sam_account_name for plan in plans] == [
        "auditor",
        "Administrator",
    ]

from lockoutlens.classification import classify_account
from lockoutlens.ldap.users import ADUser


def test_classify_builtin_administrator_by_rid():
    user = ADUser(
        distinguished_name="CN=renamed-admin,DC=lab,DC=local",
        sam_account_name="renamed-admin",
        sid="S-1-5-21-1111111111-2222222222-3333333333-500",
        user_principal_name=None,
        enabled=True,
        lockout_time=0,
        bad_password_count=0,
        bad_password_time=None,
        resultant_pso=None,
    )

    classification = classify_account(user)

    assert classification.kind == "builtin_administrator"


def test_classify_builtin_guest_by_rid():
    user = ADUser(
        distinguished_name="CN=renamed-guest,DC=lab,DC=local",
        sam_account_name="renamed-guest",
        sid="S-1-5-21-1111111111-2222222222-3333333333-501",
        user_principal_name=None,
        enabled=False,
        lockout_time=0,
        bad_password_count=0,
        bad_password_time=None,
        resultant_pso=None,
    )

    classification = classify_account(user)

    assert classification.kind == "builtin_guest"


def test_classify_builtin_krbtgt_by_rid():
    user = ADUser(
        distinguished_name="CN=renamed-kdc,DC=lab,DC=local",
        sam_account_name="renamed-kdc",
        sid="S-1-5-21-1111111111-2222222222-3333333333-502",
        user_principal_name=None,
        enabled=False,
        lockout_time=0,
        bad_password_count=0,
        bad_password_time=None,
        resultant_pso=None,
    )

    classification = classify_account(user)

    assert classification.kind == "builtin_krbtgt"


def test_classify_standard_account():
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

    classification = classify_account(user)

    assert classification.kind == "standard"

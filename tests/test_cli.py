import argparse
from unittest.mock import MagicMock, patch

import pytest

from lockoutlens import __version__
from lockoutlens.cli import build_parser, main, run_audit, run_policy
from lockoutlens.ldap.exceptions import LDAPBindError
from lockoutlens.ldap.exceptions import LDAPError

from lockoutlens.ldap.policy import DomainPolicy
from lockoutlens.ldap.users import ADUser

from lockoutlens.ldap.effective_policy import EffectivePolicy
from lockoutlens.audit import AccountAuditResult
from lockoutlens.safety import LockoutAssessment
from lockoutlens.planner import AccountPlan

def test_parser_program_name():
    parser = build_parser()

    assert parser.prog == "lockoutlens"


def test_version(capsys):
    parser = build_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--version"])

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"LockoutLens {__version__}"


def test_help(capsys):
    parser = build_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--help"])

    assert exc_info.value.code == 0

    output = capsys.readouterr().out

    assert "Active Directory" in output
    assert "--version" in output


def test_policy_parser():
    parser = build_parser()

    args = parser.parse_args(
        [
            "policy",
            "--dc",
            "dc01.lab.local",
            "--domain",
            "lab.local",
            "--username",
            "auditor",
        ]
    )

    assert args.command == "policy"
    assert args.dc == "dc01.lab.local"
    assert args.domain == "lab.local"
    assert args.username == "auditor"
    assert args.use_ssl is False


def test_policy_parser_with_ssl():
    parser = build_parser()

    args = parser.parse_args(
        [
            "policy",
            "--dc",
            "dc01.lab.local",
            "--domain",
            "lab.local",
            "--username",
            "auditor",
            "--use-ssl",
        ]
    )

    assert args.command == "policy"
    assert args.use_ssl is True


def test_policy_requires_connection_arguments():
    parser = build_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["policy"])

    assert exc_info.value.code == 2


def test_run_policy_reads_and_displays_domain_policy(capsys):
    args = argparse.Namespace(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        use_ssl=True,
        ca_file="/tmp/lab-ca.pem",
    )

    connection = MagicMock()

    raw_policy = {
        "minPwdLength": 12,
        "pwdHistoryLength": 24,
        "minPwdAge": -864_000_000_000,
        "maxPwdAge": -36_288_000_000_000,
        "lockoutThreshold": 5,
        "lockoutDuration": -18_000_000_000,
        "lockoutObservationWindow": -18_000_000_000,
    }

    with (
        patch(
            "lockoutlens.cli.getpass",
            return_value="secret",
        ),
        patch(
            "lockoutlens.cli.LDAPClient",
        ) as mock_client_class,
        patch(
            "lockoutlens.cli.get_domain_policy",
            return_value=raw_policy,
        ) as mock_get_domain_policy,
    ):
        client = mock_client_class.return_value
        client.bind.return_value = connection
        client.get_default_naming_context.return_value = (
            "DC=lab,DC=local"
        )

        result = run_policy(args)

    assert result == 0

    mock_client_class.assert_called_once_with(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        password="secret",
        use_ssl=True,
        ca_file="/tmp/lab-ca.pem",
    )

    client.bind.assert_called_once_with()
    connection.unbind.assert_called_once_with()
    client.get_default_naming_context.assert_called_once_with(
        connection
    )

    mock_get_domain_policy.assert_called_once_with(
        connection,
        "DC=lab,DC=local",
    )

    output = capsys.readouterr().out

    assert "Domain:              lab.local" in output
    assert "Minimum length:      12" in output
    assert "Password history:    24" in output
    assert "Minimum age:         1 day" in output
    assert "Maximum age:         42 days" in output
    assert "Status:              Enabled" in output
    assert "Threshold:           5" in output
    assert "Observation window:  30 minutes" in output
    assert "Lockout duration:    30 minutes" in output


def test_run_policy_returns_error_on_bind_failure(capsys):
    args = argparse.Namespace(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        use_ssl=True,
        ca_file="/tmp/lab-ca.pem",
    )

    client = MagicMock()
    client.bind.side_effect = LDAPBindError(
        "LDAP bind failed: invalidCredentials"
    )

    with (
        patch(
            "lockoutlens.cli.getpass",
            return_value="secret",
        ),
        patch(
            "lockoutlens.cli.LDAPClient",
            return_value=client,
        ),
    ):
        result = run_policy(args)

    output = capsys.readouterr().out

    assert result == 1
    assert "invalidCredentials" in output


def test_policy_parser_with_ca_file():
    parser = build_parser()

    args = parser.parse_args(
        [
            "policy",
            "--dc",
            "dc01.lab.local",
            "--domain",
            "lab.local",
            "--username",
            "auditor",
            "--use-ssl",
            "--ca-file",
            "/tmp/lab-ca.pem",
        ]
    )

    assert args.use_ssl is True
    assert args.ca_file == "/tmp/lab-ca.pem"

def test_run_policy_unbinds_connection_on_ldap_error(capsys):
    args = argparse.Namespace(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        use_ssl=True,
        ca_file="/tmp/lab-ca.pem",
    )

    connection = MagicMock()

    with (
        patch(
            "lockoutlens.cli.getpass",
            return_value="secret",
        ),
        patch(
            "lockoutlens.cli.LDAPClient",
        ) as mock_client_class,
    ):
        client = mock_client_class.return_value
        client.bind.return_value = connection
        client.get_default_naming_context.side_effect = LDAPError(
            "RootDSE failure"
        )

        result = run_policy(args)

    assert result == 1
    connection.unbind.assert_called_once_with()

    output = capsys.readouterr().out
    assert "Error: RootDSE failure" in output

def test_run_policy_rejects_unencrypted_ldap(capsys):
    args = argparse.Namespace(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        use_ssl=False,
        ca_file=None,
    )

    result = run_policy(args)

    assert result == 1

    output = capsys.readouterr().out
    assert "LDAPS is required" in output


def test_run_policy_displays_disabled_lockout_status(capsys):
    args = argparse.Namespace(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        use_ssl=True,
        ca_file="/tmp/lab-ca.pem",
    )

    connection = MagicMock()

    raw_policy = {
        "minPwdLength": 7,
        "pwdHistoryLength": 24,
        "minPwdAge": -864_000_000_000,
        "maxPwdAge": -36_288_000_000_000,
        "lockoutThreshold": 0,
        "lockoutDuration": -18_000_000_000,
        "lockoutObservationWindow": -18_000_000_000,
    }

    with (
        patch(
            "lockoutlens.cli.getpass",
            return_value="secret",
        ),
        patch(
            "lockoutlens.cli.LDAPClient",
        ) as mock_client_class,
        patch(
            "lockoutlens.cli.get_domain_policy",
            return_value=raw_policy,
        ),
    ):
        client = mock_client_class.return_value
        client.bind.return_value = connection
        client.get_default_naming_context.return_value = (
            "DC=lab,DC=local"
        )

        result = run_policy(args)

    assert result == 0

    output = capsys.readouterr().out

    assert "Status:              Disabled" in output
    assert "Threshold:           0" in output


def test_audit_parser():
    parser = build_parser()

    args = parser.parse_args(
        [
            "audit",
            "--dc",
            "dc01.lab.local",
            "--domain",
            "lab.local",
            "--username",
            "auditor",
        ]
    )

    assert args.command == "audit"
    assert args.dc == "dc01.lab.local"
    assert args.domain == "lab.local"
    assert args.username == "auditor"
    assert args.use_ssl is False


def test_audit_requires_connection_arguments():
    parser = build_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["audit"])

    assert exc_info.value.code == 2


def test_audit_parser_with_ssl_and_ca_file():
    parser = build_parser()

    args = parser.parse_args(
        [
            "audit",
            "--dc",
            "dc01.lab.local",
            "--domain",
            "lab.local",
            "--username",
            "auditor",
            "--use-ssl",
            "--ca-file",
            "/tmp/lab-ca.pem",
        ]
    )

    assert args.command == "audit"
    assert args.use_ssl is True
    assert args.ca_file == "/tmp/lab-ca.pem"


def test_run_audit_rejects_unencrypted_ldap(capsys):
    args = argparse.Namespace(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        use_ssl=False,
        ca_file=None,
    )

    result = run_audit(args)

    assert result == 1
    assert capsys.readouterr().out.strip() == "Error: LDAPS is required"


def test_main_dispatches_audit_command():
    with (
        patch(
            "sys.argv",
            [
                "lockoutlens",
                "audit",
                "--dc",
                "dc01.lab.local",
                "--domain",
                "lab.local",
                "--username",
                "auditor",
                "--use-ssl",
            ],
        ),
        patch(
            "lockoutlens.cli.run_audit",
            return_value=7,
        ) as mock_run_audit,
    ):
        result = main()

    assert result == 7
    mock_run_audit.assert_called_once()

    args = mock_run_audit.call_args.args[0]

    assert args.command == "audit"
    assert args.dc == "dc01.lab.local"
    assert args.domain == "lab.local"
    assert args.username == "auditor"
    assert args.use_ssl is True


def test_run_audit_discovers_domain_policy_and_users(capsys):
    args = argparse.Namespace(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        use_ssl=True,
        ca_file="/tmp/lab-ca.pem",
    )

    connection = MagicMock()

    policy = DomainPolicy(
        min_password_length=8,
        password_history_length=24,
        min_password_age_seconds=0,
        max_password_age_seconds=3628800,
        lockout_threshold=0,
        lockout_duration_seconds=1800,
        lockout_observation_window_seconds=1800,
    )

    users = [
        ADUser(
            distinguished_name="CN=auditor,DC=lab,DC=local",
            sam_account_name="auditor",
            sid="S-1-5-21-1111111111-2222222222-3333333333-1103",
            user_principal_name="auditor@lab.local",
            enabled=True,
            lockout_time=0,
            bad_password_count=0,
            bad_password_time=None,
            resultant_pso=None,
        ),
    ]

    with (
        patch(
            "lockoutlens.cli.getpass",
            return_value="secret",
        ),
        patch("lockoutlens.cli.LDAPClient") as mock_client_class,
        patch(
            "lockoutlens.cli.get_domain_policy",
            return_value={"raw": "policy"},
        ) as mock_get_domain_policy,
        patch(
            "lockoutlens.cli.normalize_domain_policy",
            return_value=policy,
        ) as mock_normalize_domain_policy,
        patch(
            "lockoutlens.cli.get_domain_users",
            return_value=users,
        ) as mock_get_domain_users,
    ):
        client = mock_client_class.return_value
        client.bind.return_value = connection
        client.get_default_naming_context.return_value = (
            "DC=lab,DC=local"
        )

        result = run_audit(args)

    assert result == 0

    mock_get_domain_policy.assert_called_once_with(
        connection,
        "DC=lab,DC=local",
    )
    mock_normalize_domain_policy.assert_called_once_with(
        {"raw": "policy"}
    )
    mock_get_domain_users.assert_called_once_with(
        connection,
        "DC=lab,DC=local",
    )

    connection.unbind.assert_called_once()


def test_run_audit_builds_plan_for_each_user():
    args = argparse.Namespace(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        use_ssl=True,
        ca_file="/tmp/lab-ca.pem",
    )

    connection = MagicMock()

    policy = DomainPolicy(
        min_password_length=8,
        password_history_length=24,
        min_password_age_seconds=0,
        max_password_age_seconds=3628800,
        lockout_threshold=0,
        lockout_duration_seconds=1800,
        lockout_observation_window_seconds=1800,
    )

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

    effective_policy = EffectivePolicy(
        source="domain",
        policy=policy,
    )

    plan = AccountPlan(
        sam_account_name="auditor",
        action="assess",
        reason="safety_assessment_passed",
    )

    assessment = LockoutAssessment(
        status="safe",
        reason="lockout_disabled",
        lockout_enabled=False,
        lockout_threshold=0,
        bad_password_count=0,
    )

    audit_result = AccountAuditResult(
        plan=plan,
        assessment=assessment,
    )

    with (
        patch(
            "lockoutlens.cli.getpass",
            return_value="secret",
        ),
        patch("lockoutlens.cli.LDAPClient") as mock_client_class,
        patch(
            "lockoutlens.cli.get_domain_policy",
            return_value={"raw": "policy"},
        ),
        patch(
            "lockoutlens.cli.normalize_domain_policy",
            return_value=policy,
        ),
        patch(
            "lockoutlens.cli.get_domain_users",
            return_value=[user],
        ),
        patch(
            "lockoutlens.cli.resolve_effective_policy",
            return_value=effective_policy,
        ) as mock_resolve_effective_policy,
        patch(
            "lockoutlens.cli.audit_account",
            return_value=audit_result,
        ) as mock_audit_account,
    ):
        client = mock_client_class.return_value
        client.bind.return_value = connection
        client.get_default_naming_context.return_value = (
            "DC=lab,DC=local"
        )

        result = run_audit(args)

    assert result == 0

    mock_resolve_effective_policy.assert_called_once_with(
        connection,
        user,
        policy,
    )

    mock_audit_account.assert_called_once()

    audit_args = mock_audit_account.call_args

    assert audit_args.args[0] == user
    assert audit_args.args[1] == effective_policy
    assert "now" in audit_args.kwargs

    connection.unbind.assert_called_once()


def test_run_audit_displays_account_plans(capsys):
    args = argparse.Namespace(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        use_ssl=True,
        ca_file="/tmp/lab-ca.pem",
    )

    connection = MagicMock()

    policy = DomainPolicy(
        min_password_length=8,
        password_history_length=24,
        min_password_age_seconds=0,
        max_password_age_seconds=3628800,
        lockout_threshold=0,
        lockout_duration_seconds=1800,
        lockout_observation_window_seconds=1800,
    )

    users = [
        ADUser(
            distinguished_name="CN=auditor,DC=lab,DC=local",
            sam_account_name="auditor",
            sid="S-1-5-21-1-2-3-1103",
            user_principal_name="auditor@lab.local",
            enabled=True,
            lockout_time=0,
            bad_password_count=0,
            bad_password_time=None,
            resultant_pso=None,
        ),
        ADUser(
            distinguished_name="CN=Administrator,DC=lab,DC=local",
            sam_account_name="Administrator",
            sid="S-1-5-21-1-2-3-500",
            user_principal_name=None,
            enabled=True,
            lockout_time=0,
            bad_password_count=0,
            bad_password_time=None,
            resultant_pso=None,
        ),
    ]

    plans = [
        AccountPlan(
            sam_account_name="auditor",
            action="assess",
            reason="safety_assessment_passed",
        ),
        AccountPlan(
            sam_account_name="Administrator",
            action="skip",
            reason="builtin_administrator",
        ),
    ]

    assessments = [
        LockoutAssessment(
            status="safe",
            reason="lockout_disabled",
            lockout_enabled=False,
            lockout_threshold=0,
            bad_password_count=0,
        ),
        LockoutAssessment(
            status="safe",
            reason="lockout_disabled",
            lockout_enabled=False,
            lockout_threshold=0,
            bad_password_count=0,
        ),
    ]

    audit_results = [
        AccountAuditResult(
            plan=plan,
            assessment=assessment,
        )
        for plan, assessment in zip(
            plans,
            assessments,
            strict=True,
        )
    ]

    with (
        patch(
            "lockoutlens.cli.getpass",
            return_value="secret",
        ),
        patch("lockoutlens.cli.LDAPClient") as mock_client_class,
        patch(
            "lockoutlens.cli.get_domain_policy",
            return_value={"raw": "policy"},
        ),
        patch(
            "lockoutlens.cli.normalize_domain_policy",
            return_value=policy,
        ),
        patch(
            "lockoutlens.cli.get_domain_users",
            return_value=users,
        ),
        patch(
            "lockoutlens.cli.resolve_effective_policy",
            side_effect=[
                EffectivePolicy(source="domain", policy=policy),
                EffectivePolicy(source="domain", policy=policy),
            ],
        ),
        patch(
            "lockoutlens.cli.audit_account",
            side_effect=audit_results,
        ),
    ):
        client = mock_client_class.return_value
        client.bind.return_value = connection
        client.get_default_naming_context.return_value = (
            "DC=lab,DC=local"
        )

        result = run_audit(args)

    assert result == 0

    output = capsys.readouterr().out

    assert "Account Assessment Plan" in output
    assert "auditor" in output
    assert "ASSESS" in output
    assert "safety_assessment_passed" in output
    assert "SAFE" in output
    assert "lockout_disabled" in output
    assert "Administrator" in output
    assert "SKIP" in output
    assert "builtin_administrator" in output

    connection.unbind.assert_called_once()


def test_run_audit_unbinds_on_ldap_error(capsys):
    args = argparse.Namespace(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        use_ssl=True,
        ca_file="/tmp/lab-ca.pem",
    )

    connection = MagicMock()

    policy = DomainPolicy(
        min_password_length=8,
        password_history_length=24,
        min_password_age_seconds=0,
        max_password_age_seconds=3628800,
        lockout_threshold=0,
        lockout_duration_seconds=1800,
        lockout_observation_window_seconds=1800,
    )

    user = ADUser(
        distinguished_name="CN=auditor,DC=lab,DC=local",
        sam_account_name="auditor",
        sid="S-1-5-21-1-2-3-1103",
        user_principal_name="auditor@lab.local",
        enabled=True,
        lockout_time=0,
        bad_password_count=0,
        bad_password_time=None,
        resultant_pso=None,
    )

    with (
        patch("lockoutlens.cli.getpass", return_value="secret"),
        patch("lockoutlens.cli.LDAPClient") as mock_client_class,
        patch(
            "lockoutlens.cli.get_domain_policy",
            return_value={"raw": "policy"},
        ),
        patch(
            "lockoutlens.cli.normalize_domain_policy",
            return_value=policy,
        ),
        patch(
            "lockoutlens.cli.get_domain_users",
            return_value=[user],
        ),
        patch(
            "lockoutlens.cli.resolve_effective_policy",
            side_effect=LDAPError("Unable to retrieve PSO"),
        ),
    ):
        client = mock_client_class.return_value
        client.bind.return_value = connection
        client.get_default_naming_context.return_value = (
            "DC=lab,DC=local"
        )

        result = run_audit(args)

    assert result == 1
    assert (
        capsys.readouterr().out.strip()
        == "Error: Unable to retrieve PSO"
    )
    connection.unbind.assert_called_once()


def test_run_audit_displays_effective_policy_source(capsys):
    args = argparse.Namespace(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        use_ssl=True,
        ca_file="/tmp/lab-ca.pem",
    )

    connection = MagicMock()

    domain_policy = DomainPolicy(
        min_password_length=8,
        password_history_length=24,
        min_password_age_seconds=0,
        max_password_age_seconds=3628800,
        lockout_threshold=0,
        lockout_duration_seconds=1800,
        lockout_observation_window_seconds=1800,
    )

    users = [
        ADUser(
            distinguished_name="CN=auditor,DC=lab,DC=local",
            sam_account_name="auditor",
            sid="S-1-5-21-1-2-3-1103",
            user_principal_name="auditor@lab.local",
            enabled=True,
            lockout_time=0,
            bad_password_count=0,
            bad_password_time=None,
            resultant_pso=None,
        ),
        ADUser(
            distinguished_name="CN=pso-test,DC=lab,DC=local",
            sam_account_name="pso-test",
            sid="S-1-5-21-1-2-3-1104",
            user_principal_name="pso-test@lab.local",
            enabled=True,
            lockout_time=0,
            bad_password_count=0,
            bad_password_time=None,
            resultant_pso="CN=LockoutLens-Test-PSO,CN=Password Settings Container,CN=System,DC=lab,DC=local",
        ),
    ]

    effective_policies = [
        EffectivePolicy(
            source="domain",
            policy=domain_policy,
        ),
        EffectivePolicy(
            source="pso",
            policy=domain_policy,
        ),
    ]

    plans = [
        AccountPlan(
            sam_account_name="auditor",
            action="assess",
            reason="safety_assessment_passed",
        ),
        AccountPlan(
            sam_account_name="pso-test",
            action="assess",
            reason="safety_assessment_passed",
        ),
    ]

    assessments = [
        LockoutAssessment(
            status="safe",
            reason="lockout_disabled",
            lockout_enabled=False,
            lockout_threshold=0,
            bad_password_count=0,
        ),
        LockoutAssessment(
            status="safe",
            reason="no_bad_passwords",
            lockout_enabled=True,
            lockout_threshold=5,
            bad_password_count=0,
        ),
    ]

    audit_results = [
         AccountAuditResult(
            plan=plan,
            assessment=assessment,
        )
    for plan, assessment in zip(
        plans,
        assessments,
        strict=True,
    )
]

    with (
        patch("lockoutlens.cli.getpass", return_value="secret"),
        patch("lockoutlens.cli.LDAPClient") as mock_client_class,
        patch(
            "lockoutlens.cli.get_domain_policy",
            return_value={"raw": "policy"},
        ),
        patch(
            "lockoutlens.cli.normalize_domain_policy",
            return_value=domain_policy,
        ),
        patch(
            "lockoutlens.cli.get_domain_users",
            return_value=users,
        ),
        patch(
            "lockoutlens.cli.resolve_effective_policy",
            side_effect=effective_policies,
        ),
        patch(
            "lockoutlens.cli.audit_account",
            side_effect=audit_results,
        ),
    ):
        client = mock_client_class.return_value
        client.bind.return_value = connection
        client.get_default_naming_context.return_value = (
            "DC=lab,DC=local"
        )

        result = run_audit(args)

    assert result == 0

    output = capsys.readouterr().out

    assert "auditor" in output
    assert "DOMAIN" in output

    assert "pso-test" in output
    assert "PSO" in output

    connection.unbind.assert_called_once()

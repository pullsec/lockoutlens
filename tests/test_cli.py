import argparse
from unittest.mock import MagicMock, patch

import pytest

from lockoutlens import __version__
from lockoutlens.cli import build_parser, main, run_policy
from lockoutlens.ldap.exceptions import LDAPBindError


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
    assert "Threshold:           5" in output
    assert "Observation window:  1800 seconds" in output
    assert "Lockout duration:    1800 seconds" in output


def test_run_policy_returns_error_on_bind_failure(capsys):
    args = argparse.Namespace(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        use_ssl=False,
        ca_file=None,
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

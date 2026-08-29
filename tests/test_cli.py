import pytest

from lockoutlens import __version__
from lockoutlens.cli import build_parser


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

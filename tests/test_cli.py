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

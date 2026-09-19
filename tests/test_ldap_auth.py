import pytest

from unittest.mock import MagicMock, patch

from lockoutlens.ldap.auth import LDAPAuthenticator

from lockoutlens.exceptions import AuthenticationError

def test_authenticate_returns_true_when_bind_succeeds():
    authenticator = LDAPAuthenticator(
        dc="dc01.lab.local",
        domain="lab.local",
        password="Password123!",
    )

    connection = MagicMock()
    connection.bind.return_value = True

    with patch.object(
        authenticator,
        "create_connection",
        return_value=connection,
    ) as create_connection:
        result = authenticator.authenticate("alice")

    assert result is True

    create_connection.assert_called_once_with("alice")
    connection.bind.assert_called_once_with()
    connection.unbind.assert_called_once_with()


def test_authenticate_returns_false_when_bind_fails():
    authenticator = LDAPAuthenticator(
        dc="dc01.lab.local",
        domain="lab.local",
        password="Password123!",
    )

    connection = MagicMock()
    connection.bind.return_value = False

    with patch.object(
        authenticator,
        "create_connection",
        return_value=connection,
    ) as create_connection:
        result = authenticator.authenticate("alice")

    assert result is False

    create_connection.assert_called_once_with("alice")
    connection.bind.assert_called_once_with()
    connection.unbind.assert_called_once_with()


def test_authenticate_translates_bind_error_and_unbinds():
    authenticator = LDAPAuthenticator(
        dc="dc01.lab.local",
        domain="lab.local",
        password="Password123!",
    )

    connection = MagicMock()
    connection.bind.side_effect = OSError("connection reset")

    with patch.object(
        authenticator,
        "create_connection",
        return_value=connection,
    ):

        with pytest.raises(
            AuthenticationError,
            match="connection reset",
        ):

            authenticator.authenticate("alice")

    connection.bind.assert_called_once_with()
    connection.unbind.assert_called_once_with()

from unittest.mock import MagicMock, patch

import pytest
import ssl

from lockoutlens.ldap.client import LDAPClient
from lockoutlens.ldap.exceptions import LDAPBindError, LDAPError
from ldap3 import BASE

def test_bind_user_from_short_username():
    client = LDAPClient(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        password="secret",
    )

    assert client.bind_user == "auditor@lab.local"


def test_bind_user_preserves_upn():
    client = LDAPClient(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor@lab.local",
        password="secret",
    )

    assert client.bind_user == "auditor@lab.local"


def test_ldap_server_defaults_to_port_389():
    client = LDAPClient(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        password="secret",
    )

    server = client.create_server()

    assert server.host == "dc01.lab.local"
    assert server.port == 389
    assert server.ssl is False


def test_ldaps_server_uses_port_636():
    client = LDAPClient(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        password="secret",
        use_ssl=True,
    )

    server = client.create_server()

    assert server.port == 636
    assert server.ssl is True


def test_connection_is_not_automatically_bound():
    client = LDAPClient(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        password="secret",
    )

    connection = client.create_connection()

    assert connection.user == "auditor@lab.local"
    assert connection.bound is False

def test_bind_returns_bound_connection():
    client = LDAPClient(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        password="secret",
    )

    connection = MagicMock()
    connection.bind.return_value = True

    with patch.object(
        client,
        "create_connection",
        return_value=connection,
    ):
        result = client.bind()

    connection.bind.assert_called_once_with()
    assert result is connection


def test_bind_raises_on_authentication_failure():
    client = LDAPClient(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        password="secret",
    )

    connection = MagicMock()
    connection.bind.return_value = False
    connection.result = {
        "description": "invalidCredentials",
    }

    with patch.object(
        client,
        "create_connection",
        return_value=connection,
    ):
        with pytest.raises(
            LDAPBindError,        
            match="invalidCredentials",
        ):
            client.bind()


def test_bind_wraps_connection_error():
    client = LDAPClient(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        password="secret",
    )

    with patch.object(
        client,
        "create_connection",
        side_effect=OSError("connection refused"),
    ):
        with pytest.raises(
            LDAPBindError,
            match="Unable to connect",
        ):
            client.bind()

def test_ldaps_requires_certificate_validation(tmp_path):
    ca_file = tmp_path / "lab-ca.pem"
    ca_file.write_text("dummy")

    client = LDAPClient(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        password="secret",
        use_ssl=True,
        ca_file=str(ca_file),
    )

    server = client.create_server()

    assert server.ssl is True
    assert server.port == 636
    assert server.tls is not None
    assert server.tls.validate == ssl.CERT_REQUIRED
    assert server.tls.ca_certs_file == str(ca_file)

def test_get_default_naming_context():
    client = LDAPClient(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        password="secret",
    )

    connection = MagicMock()
    connection.search.return_value = True

    entry = MagicMock()
    entry.defaultNamingContext.value = "DC=lab,DC=local"
    connection.entries = [entry]

    result = client.get_default_naming_context(connection)

    connection.search.assert_called_once_with(
        search_base="",
        search_filter="(objectClass=*)",
        search_scope=BASE,
        attributes=["defaultNamingContext"],
    )

    assert result == "DC=lab,DC=local"

def test_get_default_naming_context_raises_when_search_fails():
    client = LDAPClient(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        password="secret",
    )

    connection = MagicMock()
    connection.search.return_value = False
    connection.entries = []

    with pytest.raises(
        LDAPError,
        match="Unable to retrieve defaultNamingContext",
    ):
        client.get_default_naming_context(connection)


def test_get_default_naming_context_raises_when_value_is_missing():
    client = LDAPClient(
        dc="dc01.lab.local",
        domain="lab.local",
        username="auditor",
        password="secret",
    )

    connection = MagicMock()
    connection.search.return_value = True

    entry = MagicMock()
    entry.defaultNamingContext.value = None
    connection.entries = [entry]

    with pytest.raises(
        LDAPError,
        match="did not return defaultNamingContext",
    ):
        client.get_default_naming_context(connection)

def test_ldap_bind_error_inherits_from_ldap_error():
    assert issubclass(LDAPBindError, LDAPError)

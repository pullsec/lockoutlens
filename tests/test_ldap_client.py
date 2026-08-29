from lockoutlens.ldap.client import LDAPClient


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

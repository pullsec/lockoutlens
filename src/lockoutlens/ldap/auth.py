from ldap3 import Connection, Server

from lockoutlens.exceptions import AuthenticationError

class LDAPAuthenticator:
    """Perform isolated LDAP authentication attempts."""

    def __init__(
        self,
        dc: str,
        domain: str,
        password: str,
    ) -> None:
        self.dc = dc
        self.domain = domain
        self.password = password

    def create_connection(self, username: str) -> Connection:
        """Create an unbound LDAP connection for a target account."""
        bind_user = (
            username
            if "@" in username
            else f"{username}@{self.domain}"
        )

        server = Server(self.dc)

        return Connection(
           server,
            user=bind_user,
            password=self.password,
            auto_bind=False,
        )

    def authenticate(self, username: str) -> bool:
        """Attempt authentication for a target account."""
        connection = self.create_connection(username)

        try:
            return bool(connection.bind())
        except Exception as exc:
            raise AuthenticationError(str(exc)) from exc
        finally:
            connection.unbind()

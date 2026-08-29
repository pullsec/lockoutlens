from ldap3 import Connection, Server

from lockoutlens.ldap.exceptions import LDAPBindError

class LDAPClient:
    """LDAP connection client for Active Directory."""

    def __init__(
        self,
        dc: str,
        domain: str,
        username: str,
        password: str,
        use_ssl: bool = False,
    ) -> None:
        self.dc = dc
        self.domain = domain
        self.username = username
        self.password = password
        self.use_ssl = use_ssl

    @property
    def bind_user(self) -> str:
        """Return the Active Directory UPN used for authentication."""
        if "@" in self.username:
            return self.username

        return f"{self.username}@{self.domain}"

    def create_server(self) -> Server:
        """Create the LDAP server configuration."""
        return Server(
            self.dc,
            port=636 if self.use_ssl else 389,
            use_ssl=self.use_ssl,
        )

    def create_connection(self) -> Connection:
        """Create an LDAP connection without binding to the server."""
        return Connection(
            self.create_server(),
            user=self.bind_user,
            password=self.password,
            auto_bind=False,
        )

    def bind(self) -> Connection:
        """Create and bind an authenticated LDAP connection."""
        try:
            connection = self.create_connection()

            if not connection.bind():
                description = connection.result.get(
                    "description",
                    "unknown LDAP error",
                )
                raise LDAPBindError(
                    f"LDAP bind failed: {description}"
                )

            return connection

        except LDAPBindError:
            raise
        except Exception as exc:
            raise LDAPBindError(
                f"Unable to connect to LDAP server {self.dc}: {exc}"
            ) from exc

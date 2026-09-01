import ssl

from ldap3 import ALL, Connection, Server, Tls

from lockoutlens.ldap.exceptions import LDAPBindError, LDAPError

class LDAPClient:
    """LDAP connection client for Active Directory."""

    def __init__(
        self,
        dc: str,
        domain: str,
        username: str,
        password: str,
        use_ssl: bool = False,
        ca_file: str | None = None,
    ) -> None:
        self.dc = dc
        self.domain = domain
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.ca_file = ca_file

    @property
    def bind_user(self) -> str:
        """Return the Active Directory UPN used for authentication."""
        if "@" in self.username:
            return self.username

        return f"{self.username}@{self.domain}"

    def create_server(self) -> Server:
        """Create the LDAP server configuration."""
        tls = None

        if self.use_ssl:
            tls = Tls(
                validate=ssl.CERT_REQUIRED,
                ca_certs_file=self.ca_file,
            )

        return Server(
            self.dc,
            port=636 if self.use_ssl else 389,
            use_ssl=self.use_ssl,
            tls=tls,
            get_info=ALL,
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


    def get_default_naming_context(
        self,
        connection: Connection,
    ) -> str:
        """Return the Active Directory default naming context."""
        server_info = connection.server.info

        if server_info is None:
            raise LDAPError(
                "LDAP server information is unavailable"
            )

        values = server_info.other.get("defaultNamingContext")

        if not values:
            raise LDAPError(
                "RootDSE did not return defaultNamingContext"
            )

        return str(values[0])

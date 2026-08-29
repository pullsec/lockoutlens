from ldap3 import Connection, Server


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

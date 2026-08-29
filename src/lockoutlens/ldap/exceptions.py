class LDAPError(Exception):
    """Base exception for LDAP operations."""


class LDAPBindError(LDAPError):
    """Raised when authentication to the LDAP server fails."""

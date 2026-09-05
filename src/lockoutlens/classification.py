from dataclasses import dataclass
from typing import Literal

from lockoutlens.ldap.users import ADUser


AccountKind = Literal[
    "builtin_administrator",
    "builtin_guest",
    "builtin_krbtgt",
    "standard",
]


@dataclass(frozen=True)
class AccountClassification:
    """Structural classification of an Active Directory account."""

    kind: AccountKind


def classify_account(user: ADUser) -> AccountClassification:
    """Classify an Active Directory account from structural attributes."""
    if user.rid == 500:
        return AccountClassification(
            kind="builtin_administrator",
        )

    if user.rid == 501:
        return AccountClassification(
            kind="builtin_guest",
        )

    if user.rid == 502:
        return AccountClassification(
            kind="builtin_krbtgt",
        )

    return AccountClassification(
        kind="standard",
    )

from dataclasses import dataclass
from typing import Literal

from lockoutlens.ldap.policy import DomainPolicy
from lockoutlens.ldap.pso import PasswordSettingsObject

from ldap3 import Connection

from lockoutlens.ldap.pso import (
    PasswordSettingsObject,
    get_password_settings_object,
)
from lockoutlens.ldap.users import ADUser

@dataclass(frozen=True)
class EffectivePolicy:
    """Password policy effectively applied to an AD user."""

    source: Literal["domain", "pso"]
    policy: DomainPolicy | PasswordSettingsObject

def resolve_effective_policy(
    connection: Connection,
    user: ADUser,
    domain_policy: DomainPolicy,
) -> EffectivePolicy:
    """Resolve the password policy effectively applied to an AD user."""
    if user.resultant_pso is None:
        return EffectivePolicy(
            source="domain",
            policy=domain_policy,
        )

    pso = get_password_settings_object(
        connection,
        user.resultant_pso,
    )

    return EffectivePolicy(
        source="pso",
        policy=pso,
    )

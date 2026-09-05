from dataclasses import dataclass
from typing import Literal
from datetime import datetime, timedelta

from lockoutlens.ldap.effective_policy import EffectivePolicy
from lockoutlens.ldap.users import ADUser

SafetyStatus = Literal[
    "safe",
    "unsafe",
    "unknown",
]


@dataclass(frozen=True)
class LockoutAssessment:
    """Lockout safety assessment for an Active Directory account."""

    status: SafetyStatus
    reason: str
    lockout_enabled: bool
    lockout_threshold: int
    bad_password_count: int

    @property
    def safe(self) -> bool:
        """Return whether an authentication attempt may be considered safe."""
        return self.status == "safe"


def assess_lockout_risk(
    user: ADUser,
    effective_policy: EffectivePolicy,
    *,
    now: datetime,
) -> LockoutAssessment:
    """Assess account lockout risk without performing authentication."""
    policy = effective_policy.policy

    if not user.enabled:
        return LockoutAssessment(
            status="unsafe",
            reason="account_disabled",
            lockout_enabled=policy.lockout_enabled,
            lockout_threshold=policy.lockout_threshold,
            bad_password_count=user.bad_password_count,
        )

    if user.locked:
        return LockoutAssessment(
            status="unsafe",
            reason="account_locked",
            lockout_enabled=policy.lockout_enabled,
            lockout_threshold=policy.lockout_threshold,
            bad_password_count=user.bad_password_count,
        )

    if not policy.lockout_enabled:
        return LockoutAssessment(
            status="safe",
            reason="lockout_disabled",
            lockout_enabled=False,
            lockout_threshold=policy.lockout_threshold,
            bad_password_count=user.bad_password_count,
        )

    if user.bad_password_count == 0:
        return LockoutAssessment(
            status="safe",
            reason="no_bad_passwords",
            lockout_enabled=True,
            lockout_threshold=policy.lockout_threshold,
            bad_password_count=0,
        )

    if policy.lockout_observation_window_seconds is None:
        return LockoutAssessment(
            status="unknown",
            reason="missing_observation_window",
            lockout_enabled=True,
            lockout_threshold=policy.lockout_threshold,
            bad_password_count=user.bad_password_count,
        )

    if user.bad_password_time is None:
        return LockoutAssessment(
            status="unknown",
            reason="missing_bad_password_time",
            lockout_enabled=True,
            lockout_threshold=policy.lockout_threshold,
            bad_password_count=user.bad_password_count,
        )

    if now.tzinfo is None or now.utcoffset() is None:
        return LockoutAssessment(
            status="unknown",
            reason="invalid_current_time",
            lockout_enabled=True,
            lockout_threshold=policy.lockout_threshold,
            bad_password_count=user.bad_password_count,
        )

    if (
        user.bad_password_time.tzinfo is None
        or user.bad_password_time.utcoffset() is None
    ):
        return LockoutAssessment(
            status="unknown",
            reason="invalid_bad_password_time",
            lockout_enabled=True,
            lockout_threshold=policy.lockout_threshold,
            bad_password_count=user.bad_password_count,
        )

    if user.bad_password_time > now:
        return LockoutAssessment(
            status="unknown",
            reason="future_bad_password_time",
            lockout_enabled=True,
            lockout_threshold=policy.lockout_threshold,
            bad_password_count=user.bad_password_count,
        )

    observation_window = timedelta(
        seconds=policy.lockout_observation_window_seconds,
    )

    if now - user.bad_password_time <= observation_window:
        return LockoutAssessment(
            status="unsafe",
            reason="bad_password_within_observation_window",
            lockout_enabled=True,
            lockout_threshold=policy.lockout_threshold,
            bad_password_count=user.bad_password_count,
        )

    return LockoutAssessment(
        status="unknown",
        reason="bad_password_outside_observation_window",
        lockout_enabled=True,
        lockout_threshold=policy.lockout_threshold,
        bad_password_count=user.bad_password_count,
    )

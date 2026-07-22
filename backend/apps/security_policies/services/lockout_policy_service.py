import logging
from typing import Any, Optional
from django.utils import timezone
from django.core.exceptions import ValidationError

from apps.security_policies.models import SecurityPolicy
from apps.security_policies.selectors import get_user_effective_policy
from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService

logger = logging.getLogger(__name__)


class LockoutPolicyService:
    """
    Enterprise Account Lockout Policy Enforcement Service.
    
    Evaluates failed login attempts, handles automatic lockout, manages lockout durations,
    evaluates auto-unlock eligibility, and provides manual admin unlock mechanisms.
    """

    @classmethod
    def evaluate_failed_login(cls, user: Any, organization: Any = None) -> bool:
        """
        Increments user failed_login_attempts. If threshold is exceeded, locks the account.
        
        Returns:
            True if account was newly locked by this attempt, False otherwise.
        """
        effective_policy = get_user_effective_policy(user, organization)
        max_attempts = effective_policy.max_failed_login_attempts
        lockout_mins = effective_policy.lockout_duration_minutes

        user.failed_login_attempts = getattr(user, "failed_login_attempts", 0) + 1
        is_locked = False

        if user.failed_login_attempts >= max_attempts:
            user.is_locked = True
            user.locked_until = timezone.now() + timezone.timedelta(minutes=lockout_mins)
            is_locked = True
            logger.warning(
                "Account locked for user %s after %d failed attempts (Lockout duration: %d mins).",
                user.email,
                user.failed_login_attempts,
                lockout_mins,
            )

            AuditLogService.log(
                event_type=AuditLog.EventType.ACCOUNT_LOCKED,
                status=AuditLog.Status.WARNING,
                description=f"Account locked after {user.failed_login_attempts} failed login attempts.",
                user=user,
                resource="User",
                resource_id=str(user.id),
                metadata={
                    "failed_attempts": user.failed_login_attempts,
                    "lockout_duration_minutes": lockout_mins,
                },
            )

        update_fields = ["failed_login_attempts", "is_locked"]
        if hasattr(user, "locked_until"):
            update_fields.append("locked_until")
        user.save(update_fields=update_fields)
        return is_locked

    @classmethod
    def evaluate_account_lockout_status(cls, user: Any, organization: Any = None) -> None:
        """
        Checks if account is locked. Automatically unlocks if auto_unlock_enabled is True
        and lockout_duration_minutes has elapsed.
        
        Raises:
            ValidationError if account remains locked.
        """
        if not getattr(user, "is_locked", False):
            return

        effective_policy = get_user_effective_policy(user, organization)
        auto_unlock = effective_policy.auto_unlock_enabled

        locked_until = getattr(user, "locked_until", None)
        if auto_unlock and locked_until:
            if timezone.now() >= locked_until:
                cls.reset_failed_login_attempts(user)
                logger.info("Account auto-unlocked for user %s after lockout duration expired.", user.email)
                return

        raise ValidationError({"account": f"Account is locked due to consecutive failed login attempts. Try again later or contact your administrator."})

    @classmethod
    def reset_failed_login_attempts(cls, user: Any) -> None:
        """
        Resets failed_login_attempts counter and unlocks user upon successful authentication.
        """
        if getattr(user, "failed_login_attempts", 0) > 0 or getattr(user, "is_locked", False):
            user.failed_login_attempts = 0
            user.is_locked = False
            if hasattr(user, "locked_until"):
                user.locked_until = None
            
            update_fields = ["failed_login_attempts", "is_locked"]
            if hasattr(user, "locked_until"):
                update_fields.append("locked_until")
            user.save(update_fields=update_fields)
            logger.info("Reset failed login attempts and unlocked account for user %s", user.email)

    @classmethod
    def manual_admin_unlock(cls, user: Any, admin_actor: Any = None) -> None:
        """
        Manually unlocks an account by an administrator.
        """
        cls.reset_failed_login_attempts(user)

        AuditLogService.log(
            event_type=AuditLog.EventType.USER_UNLOCKED,
            status=AuditLog.Status.SUCCESS,
            description=f"Account manually unlocked by admin.",
            user=admin_actor,
            resource="User",
            resource_id=str(user.id),
            metadata={"target_user_id": str(user.id)},
        )
        logger.info("Admin %s manually unlocked user account %s", getattr(admin_actor, "email", "system"), user.email)

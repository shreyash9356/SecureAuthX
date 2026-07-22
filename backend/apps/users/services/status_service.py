import logging
from django.db import transaction
from rest_framework.exceptions import NotFound

from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService
from apps.organizations.constants import OrganizationStatus
from apps.users.exceptions import SelfOperationException, OwnerDeactivationException
from apps.users.selectors import UserSelector

logger = logging.getLogger(__name__)


class UserStatusService:
    """
    Business logic for user account state transitions (activate, deactivate, lock, unlock).
    """

    @staticmethod
    def activate_user(user_id, actor) -> None:
        """
        Activates a user account.
        """
        user = UserSelector.get_user_by_id(user_id)
        if not user:
            raise NotFound("User not found.")

        with transaction.atomic():
            user.is_active = True
            user.save()

            AuditLogService.log(
                event_type=AuditLog.EventType.USER_ACTIVATED,
                status=AuditLog.Status.SUCCESS,
                description=f"User account {user.email} activated.",
                user=actor,
                resource="User",
                resource_id=str(user.id),
                metadata={"target_user_email": user.email},
            )
            logger.info("User %s activated by actor %s", user.email, actor.email)

    @staticmethod
    def deactivate_user(user_id, actor) -> None:
        """
        Deactivates a user account. Prevents self-deactivation and owner lockout.
        """
        user = UserSelector.get_user_by_id(user_id)
        if not user:
            raise NotFound("User not found.")

        # Guard: Prevent self-deactivation
        if str(user.id) == str(actor.id):
            raise SelfOperationException("You cannot deactivate your own account.")

        # Guard: Prevent owner lockout (check owned active organizations)
        if user.owned_organizations.filter(status=OrganizationStatus.ACTIVE).exists():
            raise OwnerDeactivationException(
                "This user is the owner of an active organization. Transfer ownership before deactivating."
            )

        with transaction.atomic():
            user.is_active = False
            user.save()

            AuditLogService.log(
                event_type=AuditLog.EventType.USER_DEACTIVATED,
                status=AuditLog.Status.SUCCESS,
                description=f"User account {user.email} deactivated.",
                user=actor,
                resource="User",
                resource_id=str(user.id),
                metadata={"target_user_email": user.email},
            )
            logger.warning("User %s deactivated by actor %s", user.email, actor.email)

    @staticmethod
    def lock_user(user_id, locked_until, actor) -> None:
        """
        Locks a user account administratively. Prevents self-locking.
        """
        user = UserSelector.get_user_by_id(user_id)
        if not user:
            raise NotFound("User not found.")

        # Guard: Prevent self-locking
        if str(user.id) == str(actor.id):
            raise SelfOperationException("You cannot lock your own account.")

        with transaction.atomic():
            user.is_locked = True
            user.locked_until = locked_until
            user.save()

            AuditLogService.log(
                event_type=AuditLog.EventType.ACCOUNT_LOCKED,
                status=AuditLog.Status.SUCCESS,
                description=f"User account {user.email} locked until {locked_until}.",
                user=actor,
                resource="User",
                resource_id=str(user.id),
                metadata={
                    "target_user_email": user.email,
                    "locked_until": str(locked_until) if locked_until else None,
                },
            )
            logger.warning("User %s locked by actor %s until %s", user.email, actor.email, locked_until)

    @staticmethod
    def unlock_user(user_id, actor) -> None:
        """
        Unlocks a user account.
        """
        user = UserSelector.get_user_by_id(user_id)
        if not user:
            raise NotFound("User not found.")

        with transaction.atomic():
            user.is_locked = False
            user.locked_until = None
            user.failed_login_attempts = 0
            user.save()

            AuditLogService.log(
                event_type=AuditLog.EventType.ACCOUNT_UNLOCKED,
                status=AuditLog.Status.SUCCESS,
                description=f"User account {user.email} unlocked.",
                user=actor,
                resource="User",
                resource_id=str(user.id),
                metadata={"target_user_email": user.email},
            )
            logger.info("User %s unlocked by actor %s", user.email, actor.email)

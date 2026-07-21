"""
Service module for administrative controls over Multi-Factor Authentication.
"""

from django.db import transaction

from apps.audit_logs.services import AuditLogService
from apps.audit_logs.models import AuditLog
from apps.mfa.exceptions import MFANotEnabledException
from apps.mfa.selectors.mfa_selector import MFASelector


class MFAAdminService:
    """
    Provides administrative controls for MFA devices, unlocking, and resets.
    """

    @staticmethod
    @transaction.atomic
    def admin_disable_mfa(admin_user, target_user) -> None:
        """
        Administratively reset/disable a target user's MFA device configuration.
        """
        device = MFASelector.get_device_by_user(target_user)
        if not device:
            raise MFANotEnabledException("Target user does not have MFA configured.")

        device_id = str(device.pk)
        device.delete()

        # Log administrative action
        AuditLogService.log(
            event_type=AuditLog.EventType.MFA_DISABLED,
            status=AuditLog.Status.SUCCESS,
            description=f"MFA administratively disabled by admin: {admin_user.email}",
            user=target_user,
            resource="MFADevice",
            resource_id=device_id,
            metadata={"admin_user_id": str(admin_user.pk)},
        )

    @staticmethod
    @transaction.atomic
    def admin_unlock_mfa(admin_user, target_user) -> None:
        """
        Administratively unlock a target user's locked MFA device configuration.
        """
        device = MFASelector.get_device_by_user(target_user)
        if not device:
            raise MFANotEnabledException("Target user does not have MFA configured.")

        device.failed_attempts = 0
        device.locked_until = None
        device.save(update_fields=["failed_attempts", "locked_until", "updated_at"])

        # Log administrative action
        AuditLogService.log(
            event_type=AuditLog.EventType.ACCOUNT_UNLOCKED,
            status=AuditLog.Status.SUCCESS,
            description=f"MFA lockout administratively cleared by admin: {admin_user.email}",
            user=target_user,
            resource="MFADevice",
            resource_id=str(device.pk),
            metadata={"admin_user_id": str(admin_user.pk)},
        )

"""
Service module for managing and verifying MFA recovery codes.
"""

from django.db import transaction
from django.utils import timezone

from apps.audit_logs.services import AuditLogService
from apps.audit_logs.models import AuditLog
from apps.mfa.exceptions import (
    MFANotEnabledException,
    InvalidRecoveryCodeException,
)
from apps.mfa.models import MFARecoveryCode
from apps.mfa.selectors.mfa_selector import MFASelector
from apps.mfa.utils.recovery_codes import (
    check_recovery_code,
    generate_recovery_codes,
    hash_recovery_code,
)


class MFARecoveryService:
    """
    Handles verification of one-time recovery codes and code regeneration.
    """

    @staticmethod
    @transaction.atomic
    def verify_and_use_recovery_code(user, plaintext_code: str) -> bool:
        """
        Verify and consume a one-time recovery code. Clears device lockout on success.

        Raises:
            MFANotEnabledException:       If user does not have MFA active.
            InvalidRecoveryCodeException: If the recovery code is invalid/already used.
        """
        device = MFASelector.get_active_device_by_user(user)
        if not device:
            raise MFANotEnabledException()

        active_codes = MFASelector.list_active_recovery_codes(device)
        matched_code_obj = None

        # Verify plaintext_code against the hashed values in DB
        for code_obj in active_codes:
            if check_recovery_code(plaintext_code, code_obj.code_hash):
                matched_code_obj = code_obj
                break

        if not matched_code_obj:
            # Audit log failure
            AuditLogService.log(
                event_type=AuditLog.EventType.LOGIN_FAILED,
                status=AuditLog.Status.FAILURE,
                description="Failed recovery code verification attempt.",
                user=user,
                resource="MFADevice",
                resource_id=str(device.pk),
            )
            raise InvalidRecoveryCodeException()

        # Mark code as consumed
        matched_code_obj.is_used = True
        matched_code_obj.used_at = timezone.now()
        matched_code_obj.save(update_fields=["is_used", "used_at"])

        # Reset failed verification lockout counters on successful recovery bypass
        device.failed_attempts = 0
        device.locked_until = None
        device.save(update_fields=["failed_attempts", "locked_until"])

        # Audit log success
        AuditLogService.log(
            event_type=AuditLog.EventType.LOGIN_SUCCESS,
            status=AuditLog.Status.SUCCESS,
            description="MFA bypassed successfully using recovery code.",
            user=user,
            resource="MFADevice",
            resource_id=str(device.pk),
        )

        return True

    @staticmethod
    @transaction.atomic
    def regenerate_recovery_codes(user) -> list[str]:
        """
        Invalidate all existing recovery codes and generate a fresh batch of 10 codes.

        Returns:
            list[str]: The new batch of plaintext recovery codes.
        """
        device = MFASelector.get_active_device_by_user(user)
        if not device:
            raise MFANotEnabledException()

        # Clear existing recovery codes
        device.recovery_codes.all().delete()

        # Generate a new batch of 10 recovery codes
        raw_recovery_codes = generate_recovery_codes(count=10)
        recovery_code_objects = []

        for code in raw_recovery_codes:
            hashed_val = hash_recovery_code(code)
            recovery_code_objects.append(
                MFARecoveryCode(mfa_device=device, code_hash=hashed_val)
            )

        MFARecoveryCode.objects.bulk_create(recovery_code_objects)

        # Audit log code regeneration
        AuditLogService.log(
            event_type=AuditLog.EventType.MFA_ENABLED,
            status=AuditLog.Status.SUCCESS,
            description="MFA recovery codes regenerated.",
            user=user,
            resource="MFADevice",
            resource_id=str(device.pk),
        )

        return raw_recovery_codes

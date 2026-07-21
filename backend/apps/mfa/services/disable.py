"""
Service module for disabling Multi-Factor Authentication.
"""

from django.db import transaction

from apps.audit_logs.services import AuditLogService
from apps.audit_logs.models import AuditLog
from apps.authentication.exceptions import InvalidCredentialsException
from apps.mfa.exceptions import MFANotEnabledException, InvalidOTPException
from apps.mfa.selectors.mfa_selector import MFASelector
from apps.mfa.services.verification import MFAVerificationService
from apps.mfa.services.recovery import MFARecoveryService


class MFADisableService:
    """
    Handles verifying credentials and disabling multi-factor authentication.
    """

    @staticmethod
    @transaction.atomic
    def disable_mfa(
        user,
        password_confirmation: str,
        otp_code: str | None = None,
        recovery_code: str | None = None,
    ) -> None:
        """
        Verify the user's password and either a valid OTP or a recovery code to disable MFA.

        Removes the MFADevice configuration and recovery codes from the database.
        """
        device = MFASelector.get_active_device_by_user(user)
        if not device:
            raise MFANotEnabledException()

        # 1. Verify password confirmation
        if not user.check_password(password_confirmation):
            raise InvalidCredentialsException("Invalid password confirmation.")

        # 2. Verify either OTP code or Recovery code
        if otp_code:
            # Reuses verification service (handles attempts, lockout)
            MFAVerificationService.verify_otp_login(user, otp_code)
        elif recovery_code:
            # Reuses recovery service (consumes the recovery code)
            MFARecoveryService.verify_and_use_recovery_code(user, recovery_code)
        else:
            raise InvalidOTPException("Either OTP or recovery code is required.")

        # 3. Disable and clear database records
        # Deleting the device cascades to delete all associated MFARecoveryCode instances
        device_id = str(device.pk)
        device.delete()

        # Log audit event
        AuditLogService.log(
            event_type=AuditLog.EventType.MFA_DISABLED,
            status=AuditLog.Status.SUCCESS,
            description="MFA disabled and secrets purged.",
            user=user,
            resource="MFADevice",
            resource_id=device_id,
        )

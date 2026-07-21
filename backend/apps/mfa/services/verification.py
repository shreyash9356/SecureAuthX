"""
Service module for executing active MFA code checks (TOTP) and lockout tracking.
"""

from datetime import timedelta
from django.db import transaction
from django.utils import timezone

from apps.audit_logs.services import AuditLogService
from apps.audit_logs.models import AuditLog
from apps.mfa.exceptions import (
    MFANotEnabledException,
    MFALockoutException,
    InvalidOTPException,
)
from apps.mfa.selectors.mfa_selector import MFASelector
from apps.mfa.utils.crypto import decrypt_secret
from apps.mfa.utils.totp import verify_otp


class MFAVerificationService:
    """
    Handles verifying user-submitted OTP tokens with lockout and replay protection.
    """

    @staticmethod
    def verify_otp_login(user, otp_code: str) -> bool:
        """
        Verify a user's TOTP token. Handles failure tracking, lockout thresholds, and replay attacks.

        Raises:
            MFANotEnabledException: If the user does not have MFA configured/enabled.
            MFALockoutException:    If the device is locked out due to consecutive failures.
            InvalidOTPException:    If the submitted token is incorrect.
        """
        device = MFASelector.get_active_device_by_user(user)
        if not device:
            raise MFANotEnabledException()

        # Enforce Lockout Check
        if device.is_locked:
            raise MFALockoutException()

        raw_secret = decrypt_secret(device.secret)
        is_valid, step = verify_otp(
            raw_secret,
            otp_code,
            last_used_time_step=device.last_used_time_step,
        )

        if is_valid:
            # Verification Success path
            device.failed_attempts = 0
            device.locked_until = None
            device.last_verified_at = timezone.now()
            device.last_used_time_step = step
            device.save(
                update_fields=[
                    "failed_attempts",
                    "locked_until",
                    "last_verified_at",
                    "last_used_time_step",
                    "updated_at",
                ]
            )

            # Audit log success
            AuditLogService.log(
                event_type=AuditLog.EventType.LOGIN_SUCCESS,
                status=AuditLog.Status.SUCCESS,
                description="MFA TOTP code verified successfully.",
                user=user,
                resource="MFADevice",
                resource_id=str(device.pk),
            )
            return True

        else:
            # Verification Failure path: Increment attempts
            device.failed_attempts += 1
            now = timezone.now()

            # Enforce lockout if max attempts exceeded (e.g. 5 failed attempts)
            MAX_ATTEMPTS = 5
            LOCKOUT_MINUTES = 15

            if device.failed_attempts >= MAX_ATTEMPTS:
                device.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
                device.save(
                    update_fields=["failed_attempts", "locked_until", "updated_at"]
                )

                # Audit log lockout event
                AuditLogService.log(
                    event_type=AuditLog.EventType.ACCOUNT_LOCKED,
                    status=AuditLog.Status.FAILURE,
                    description=f"MFA locked out for {LOCKOUT_MINUTES} minutes due to {MAX_ATTEMPTS} failed attempts.",
                    user=user,
                    resource="MFADevice",
                    resource_id=str(device.pk),
                )
                raise MFALockoutException()

            device.save(update_fields=["failed_attempts", "updated_at"])

            # Audit log generic verification failure
            AuditLogService.log(
                event_type=AuditLog.EventType.LOGIN_FAILED,
                status=AuditLog.Status.FAILURE,
                description="Invalid MFA TOTP code verification attempt.",
                user=user,
                resource="MFADevice",
                resource_id=str(device.pk),
            )
            raise InvalidOTPException()

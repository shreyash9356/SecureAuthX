"""
Service module for initiating and activating Multi-Factor Authentication.
"""

from django.db import transaction
from django.utils import timezone

from apps.audit_logs.services import AuditLogService
from apps.audit_logs.models import AuditLog
from apps.mfa.exceptions import (
    MFAAlreadyEnabledException,
    MFANotEnabledException,
    InvalidOTPException,
)
from apps.mfa.models import MFADevice, MFARecoveryCode
from apps.mfa.selectors.mfa_selector import MFASelector
from apps.mfa.utils.crypto import encrypt_secret, decrypt_secret
from apps.mfa.utils.totp import (
    generate_totp_secret,
    get_totp_uri,
    verify_otp,
    generate_qr_code_data_uri,
)
from apps.mfa.utils.recovery_codes import generate_recovery_codes, hash_recovery_code


class MFASetupService:
    """
    Handles MFA device registration, initial setup verification, and activation.
    """

    @staticmethod
    @transaction.atomic
    def initiate_mfa_setup(user) -> tuple[str, str, str]:
        """
        Prepare MFA configuration by generating a TOTP secret, provisioning URI, and QR code Data URI.

        If a non-activated device already exists, it regenerates the secret.
        """
        device = MFASelector.get_device_by_user(user)
        if device and device.is_enabled:
            raise MFAAlreadyEnabledException()

        # Generate a new random base32 TOTP secret
        raw_secret = generate_totp_secret()
        encrypted = encrypt_secret(raw_secret)

        if not device:
            device = MFADevice(user=user)

        device.secret = encrypted
        device.is_enabled = False
        device.verified_at = None
        device.failed_attempts = 0
        device.locked_until = None
        device.save()

        # Provisioning URI and QR code generation
        provisioning_uri = get_totp_uri(raw_secret, user.email)
        qr_code = generate_qr_code_data_uri(provisioning_uri)

        # Audit log registration
        AuditLogService.log(
            event_type=AuditLog.EventType.MFA_DISABLED,  # Setup initiated but not yet active
            status=AuditLog.Status.SUCCESS,
            description="MFA configuration setup initiated.",
            user=user,
            resource="MFADevice",
            resource_id=str(device.pk),
        )

        return raw_secret, provisioning_uri, qr_code

    @staticmethod
    @transaction.atomic
    def activate_mfa(user, otp_code: str) -> list[str]:
        """
        Verify the initial OTP code, activate the device, and generate recovery codes.

        Returns:
            list[str]: The plaintext recovery codes to present to the user.
        """
        device = MFASelector.get_device_by_user(user)
        if not device:
            raise MFANotEnabledException("No MFA setup has been initiated.")
        if device.is_enabled:
            raise MFAAlreadyEnabledException()

        # Decrypt secret and verify initial OTP
        raw_secret = decrypt_secret(device.secret)
        is_valid, step = verify_otp(raw_secret, otp_code)

        if not is_valid:
            raise InvalidOTPException("Invalid initial verification code.")

        now = timezone.now()
        device.is_enabled = True
        device.verified_at = now
        device.last_verified_at = now
        device.last_used_time_step = step
        device.failed_attempts = 0
        device.locked_until = None
        device.save()

        # Generate a batch of 10 recovery codes
        raw_recovery_codes = generate_recovery_codes(count=10)
        recovery_code_objects = []

        for code in raw_recovery_codes:
            hashed_val = hash_recovery_code(code)
            recovery_code_objects.append(
                MFARecoveryCode(mfa_device=device, code_hash=hashed_val)
            )

        MFARecoveryCode.objects.bulk_create(recovery_code_objects)

        # Log MFA activation success
        AuditLogService.log(
            event_type=AuditLog.EventType.MFA_ENABLED,
            status=AuditLog.Status.SUCCESS,
            description="MFA successfully activated for this account.",
            user=user,
            resource="MFADevice",
            resource_id=str(device.pk),
        )

        return raw_recovery_codes

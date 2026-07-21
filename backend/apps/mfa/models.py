import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class MFADevice(models.Model):
    """
    Represents a user's Time-based One-Time Password (TOTP) Multi-Factor
    Authentication (MFA) configuration.

    This model is responsible only for storing MFA-related data.
    Business logic such as TOTP verification, secret encryption/decryption,
    QR code generation, replay protection, lockout handling, and recovery
    code management must remain in the Service layer.
    """

    # Primary key for the MFA device.
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    # Each user can have only one MFA device configuration.
    # Deleting the user automatically removes the associated MFA device.
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="mfa_device",
    )

    # Encrypted TOTP secret.
    # Never store the raw Base32 secret in the database.
    secret = models.TextField(
        blank=True,
        default="",
        help_text="Encrypted TOTP secret.",
    )

    # Indicates whether MFA has been successfully activated.
    # This becomes True only after successful verification of the initial OTP.
    is_enabled = models.BooleanField(
        default=False,
    )

    # Timestamp when MFA was successfully enabled.
    verified_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    # Stores the last accepted TOTP time-step to prevent OTP replay attacks.
    last_used_time_step = models.BigIntegerField(
        null=True,
        blank=True,
        help_text="Last accepted TOTP timestep for replay protection.",
    )

    # Number of consecutive failed OTP verification attempts.
    # Used to enforce temporary account lockout.
    failed_attempts = models.PositiveSmallIntegerField(
        default=0,
    )

    # OTP verification is blocked until this timestamp if the user
    # exceeds the maximum allowed failed attempts.
    locked_until = models.DateTimeField(
        null=True,
        blank=True,
    )

    # Timestamp of the most recent successful OTP verification.
    last_verified_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    # Audit fields.
    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    class Meta:
        db_table = "mfa_devices"
        ordering = ("-created_at",)
        verbose_name = "MFA Device"
        verbose_name_plural = "MFA Devices"

    def __str__(self) -> str:
        """
        Return a human-readable representation of the MFA device.
        """
        return f"MFA<{self.user.email}>"

    @property
    def is_locked(self) -> bool:
        """
        Determine whether the MFA device is currently locked due to
        excessive failed OTP verification attempts.

        Returns:
            bool: True if the lock period has not expired, otherwise False.
        """
        return (
            self.locked_until is not None
            and self.locked_until > timezone.now()
        )


class MFARecoveryCode(models.Model):
    """
    Represents a cryptographically hashed, one-time use recovery code.
    Used to bypass MFA if the user loses access to their TOTP device.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    mfa_device = models.ForeignKey(
        MFADevice,
        on_delete=models.CASCADE,
        related_name="recovery_codes",
    )

    # Cryptographically hashed recovery code.
    # Never store raw recovery codes in the database.
    code_hash = models.CharField(
        max_length=255,
        help_text="Hashed recovery code.",
    )

    is_used = models.BooleanField(
        default=False,
    )

    used_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    class Meta:
        db_table = "mfa_recovery_codes"
        ordering = ("-created_at",)
        verbose_name = "MFA Recovery Code"
        verbose_name_plural = "MFA Recovery Codes"

    def __str__(self) -> str:
        return f"RecoveryCode<{self.mfa_device.user.email}>"
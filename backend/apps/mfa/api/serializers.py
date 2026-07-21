"""
Serializers for the Multi-Factor Authentication (MFA) module.
Perform input validation only.
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from apps.mfa.validators import validate_otp_code, validate_recovery_code_format
from apps.mfa.models import MFADevice

User = get_user_model()


class MFADeviceSerializer(serializers.ModelSerializer):
    """
    Exposes MFA status and locking configurations safely.
    """

    class Meta:
        model = MFADevice
        fields = [
            "id",
            "is_enabled",
            "verified_at",
            "failed_attempts",
            "locked_until",
            "last_verified_at",
        ]
        read_only_fields = fields


class MFASetupInitiateSerializer(serializers.Serializer):
    """
    Serializer to return TOTP configuration details for setup initiation.
    """

    manual_key = serializers.CharField(
        read_only=True,
        help_text="Base32 manual setup key.",
    )
    provisioning_uri = serializers.CharField(
        read_only=True,
        help_text="Standard otpauth:// provisioning URI.",
    )
    qr_code = serializers.CharField(
        read_only=True,
        help_text="Base64 PNG Data URI of the QR Code (data:image/png;base64,...).",
    )


class MFAActivationSerializer(serializers.Serializer):
    """
    Serializer to verify initial OTP code and return recovery codes.
    """

    otp_code = serializers.CharField(
        required=True,
        validators=[validate_otp_code],
        help_text="The initial 6-digit verification code from the TOTP app.",
    )
    recovery_codes = serializers.ListField(
        child=serializers.CharField(),
        read_only=True,
        help_text="Unused one-time recovery codes generated upon activation.",
    )


class MFALoginVerificationSerializer(serializers.Serializer):
    """
    Serializer to verify TOTP code during login.
    """

    otp_code = serializers.CharField(
        required=True,
        validators=[validate_otp_code],
        help_text="6-digit numeric OTP code.",
    )


class MFARecoveryCodeVerificationSerializer(serializers.Serializer):
    """
    Serializer to verify recovery code during login.
    """

    recovery_code = serializers.CharField(
        required=True,
        validators=[validate_recovery_code_format],
        help_text="12-character alphanumeric recovery code.",
    )


class MFADisableSerializer(serializers.Serializer):
    """
    Serializer to disable MFA requiring password and OTP/Recovery confirmation.
    """

    password = serializers.CharField(
        required=True,
        write_only=True,
        style={"input_type": "password"},
        help_text="Confirm account password.",
    )
    otp_code = serializers.CharField(
        required=False,
        validators=[validate_otp_code],
        help_text="MFA OTP code.",
    )
    recovery_code = serializers.CharField(
        required=False,
        validators=[validate_recovery_code_format],
        help_text="MFA one-time recovery code.",
    )

    def validate(self, attrs):
        if not attrs.get("otp_code") and not attrs.get("recovery_code"):
            raise serializers.ValidationError(
                "Either otp_code or recovery_code must be provided."
            )
        return attrs

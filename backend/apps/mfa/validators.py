"""
Validators for the Multi-Factor Authentication (MFA) module.
"""

import re
from django.core.exceptions import ValidationError


def validate_otp_code(value: str) -> None:
    """
    Validate that the OTP is a 6-digit numeric string.
    """
    if not isinstance(value, str) or not re.match(r"^\d{6}$", value):
        raise ValidationError("OTP must be a 6-digit numeric string.")


def validate_recovery_code_format(value: str) -> None:
    """
    Validate that the recovery code format is exactly 12 alphanumeric characters.
    """
    if not isinstance(value, str) or not re.match(r"^[a-zA-Z0-9]{12}$", value):
        raise ValidationError(
            "Recovery code must be exactly 12 alphanumeric characters."
        )

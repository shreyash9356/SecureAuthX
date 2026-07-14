"""
Enterprise password validator for SecureAuthX.

This module centralizes password policy enforcement for all
authentication-related operations.

Used by:
- Registration
- Change Password
- Reset Password
"""

import re

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError


class EnterprisePasswordValidator:
    """
    Enterprise password policy validator.
    """

    MIN_LENGTH = 12
    MAX_LENGTH = 128

    def validate(self, password: str, user=None) -> None:
        """
        Validate password against enterprise password policy.

        Raises:
            ValidationError: If the password does not satisfy policy.
        """

        errors = []

        # Django built-in validators
        try:
            validate_password(password, user=user)
        except ValidationError as exc:
            errors.extend(exc.messages)

        # Minimum length
        if len(password) < self.MIN_LENGTH:
            errors.append(
                f"Password must be at least {self.MIN_LENGTH} characters long."
            )

        # Maximum length
        if len(password) > self.MAX_LENGTH:
            errors.append(f"Password cannot exceed {self.MAX_LENGTH} characters.")

        # Uppercase
        if not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter.")

        # Lowercase
        if not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter.")

        # Number
        if not re.search(r"\d", password):
            errors.append("Password must contain at least one numeric digit.")

        # Special character
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
            errors.append("Password must contain at least one special character.")

        # Sequential numbers
        if "123456" in password:
            errors.append("Password must not contain sequential numbers.")

        # Sequential letters
        if "abcdef" in password.lower():
            errors.append("Password must not contain sequential letters.")

        # Keyboard pattern
        if "qwerty" in password.lower():
            errors.append("Password must not contain keyboard patterns.")

        # Repeated characters
        if re.search(r"(.)\1{4,}", password):
            errors.append("Password contains too many repeated characters.")

        if errors:
            raise ValidationError(errors)

    @staticmethod
    def get_help_text() -> str:
        """
        Help text displayed by Django.
        """

        return (
            "Password must be at least 12 characters long and contain "
            "uppercase, lowercase, numeric, and special characters."
        )

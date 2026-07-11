"""
Token utilities for the SecureAuthX authentication module.

This module is responsible for generating and validating secure,
time-limited tokens used for:

- Email verification
- Password reset

JWT access and refresh tokens are handled by Simple JWT.
"""

from django.core.signing import BadSignature
from django.core.signing import SignatureExpired
from django.core.signing import TimestampSigner

from .exceptions import (
    InvalidPasswordResetTokenException,
    InvalidVerificationTokenException,
)


class TokenService:
    """
    Handles secure token generation and validation.
    """

    EMAIL_VERIFICATION_SALT = "email-verification"
    PASSWORD_RESET_SALT = "password-reset"

    EMAIL_VERIFICATION_MAX_AGE = 60 * 60 * 24  # 24 hours
    PASSWORD_RESET_MAX_AGE = 60 * 30  # 30 minutes

    signer = TimestampSigner()

    @classmethod
    def generate_email_verification_token(cls, user_id):
        """
        Generate a signed email verification token.
        """
        return cls.signer.sign(f"{cls.EMAIL_VERIFICATION_SALT}:{user_id}")

    @classmethod
    def verify_email_verification_token(cls, token):
        """
        Validate an email verification token.

        Returns:
            user_id
        """
        try:
            value = cls.signer.unsign(
                token,
                max_age=cls.EMAIL_VERIFICATION_MAX_AGE,
            )

            prefix, user_id = value.split(":", 1)

            if prefix != cls.EMAIL_VERIFICATION_SALT:
                raise InvalidVerificationTokenException()

            return user_id

        except SignatureExpired as exc:
            raise InvalidVerificationTokenException() from exc

        except BadSignature as exc:
            raise InvalidVerificationTokenException() from exc

    @classmethod
    def generate_password_reset_token(cls, user_id):
        """
        Generate a signed password reset token.
        """
        return cls.signer.sign(f"{cls.PASSWORD_RESET_SALT}:{user_id}")

    @classmethod
    def verify_password_reset_token(cls, token):
        """
        Validate a password reset token.

        Returns:
            user_id
        """
        try:
            value = cls.signer.unsign(
                token,
                max_age=cls.PASSWORD_RESET_MAX_AGE,
            )

            prefix, user_id = value.split(":", 1)

            if prefix != cls.PASSWORD_RESET_SALT:
                raise InvalidPasswordResetTokenException()

            return user_id

        except SignatureExpired as exc:
            raise InvalidPasswordResetTokenException() from exc

        except BadSignature as exc:
            raise InvalidPasswordResetTokenException() from exc

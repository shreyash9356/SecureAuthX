"""
Password reset service for the SecureAuthX authentication module.

Verifies the signed reset token, enforces the enterprise password policy,
updates the user's password, and records the change timestamp.
"""

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from apps.authentication.exceptions import (
    InvalidPasswordResetTokenException,
    PasswordMismatchException,
    WeakPasswordException,
)
from apps.authentication.tokens import TokenService
from apps.authentication.validators.password_validator import (
    EnterprisePasswordValidator,
)

User = get_user_model()


class PasswordResetService:
    """
    Service responsible for resetting a user's password via a signed token.
    """

    @staticmethod
    @transaction.atomic
    def reset_password(
        *,
        token: str,
        password: str,
        confirm_password: str,
    ) -> None:
        """
        Reset the user's password using a valid signed reset token.

        Steps
        -----
        1. Verify the signed token and extract the user ID.
        2. Confirm the passwords match.
        3. Validate the new password against the enterprise policy.
        4. Ensure the new password differs from the current one.
        5. Hash and persist the new password.
        6. Update ``password_changed_at`` to the current timestamp.

        Args:
            token:            Signed password reset token.
            password:         New plaintext password.
            confirm_password: Confirmation of the new password.

        Raises:
            InvalidPasswordResetTokenException: Token is invalid or expired.
            PasswordMismatchException:          Passwords do not match.
            WeakPasswordException:              Password fails policy checks.
        """

        # ── Step 1: Verify token ───────────────────────────────────────────
        user_id = TokenService.verify_password_reset_token(token)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist as exc:
            raise InvalidPasswordResetTokenException() from exc

        # ── Step 2: Password confirmation ──────────────────────────────────
        if password != confirm_password:
            raise PasswordMismatchException()

        # ── Step 3: Enterprise password policy ────────────────────────────
        try:
            EnterprisePasswordValidator().validate(password, user=user)
        except ValidationError as exc:
            raise WeakPasswordException(
                message=" ".join(exc.messages)
            ) from exc

        # ── Step 4: Prevent password reuse ────────────────────────────────
        if user.check_password(password):
            raise WeakPasswordException(
                message=(
                    "New password must differ from your current password."
                )
            )

        # ── Step 5 & 6: Persist new password and timestamp ────────────────
        user.set_password(password)
        user.password_changed_at = timezone.now()
        user.save(update_fields=["password", "password_changed_at"])

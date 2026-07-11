"""
Change password service for the SecureAuthX authentication module.

Allows an authenticated user to change their own password by verifying
the current password, enforcing the enterprise policy on the new password,
and persisting the change.
"""

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from apps.authentication.exceptions import (
    InvalidCredentialsException,
    PasswordMismatchException,
    WeakPasswordException,
)
from apps.authentication.validators.password_validator import (
    EnterprisePasswordValidator,
)


class PasswordChangeService:
    """
    Service responsible for changing an authenticated user's password.
    """

    @staticmethod
    @transaction.atomic
    def change_password(
        *,
        user,
        current_password: str,
        new_password: str,
        confirm_password: str,
    ) -> None:
        """
        Change the authenticated user's password.

        Steps
        -----
        1. Verify the current password.
        2. Confirm the new passwords match.
        3. Validate the new password against the enterprise policy.
        4. Ensure the new password differs from the current one.
        5. Hash and persist the new password.
        6. Update ``password_changed_at`` to the current timestamp.

        Args:
            user:             The authenticated User instance.
            current_password: The user's existing plaintext password.
            new_password:     The desired new plaintext password.
            confirm_password: Confirmation of the new password.

        Raises:
            InvalidCredentialsException: Current password is incorrect.
            PasswordMismatchException:   New passwords do not match.
            WeakPasswordException:       New password fails policy checks.
        """

        # ── Step 1: Verify current password ───────────────────────────────
        if not user.check_password(current_password):
            raise InvalidCredentialsException(
                "Current password is incorrect."
            )

        # ── Step 2: Password confirmation ──────────────────────────────────
        if new_password != confirm_password:
            raise PasswordMismatchException()

        # ── Step 3: Enterprise password policy ────────────────────────────
        try:
            EnterprisePasswordValidator().validate(new_password, user=user)
        except ValidationError as exc:
            raise WeakPasswordException(
                message=" ".join(exc.messages)
            ) from exc

        # ── Step 4: Prevent password reuse ────────────────────────────────
        if user.check_password(new_password):
            raise WeakPasswordException(
                message=(
                    "New password must differ from your current password."
                )
            )

        # ── Step 5 & 6: Persist new password and timestamp ────────────────
        user.set_password(new_password)
        user.password_changed_at = timezone.now()
        user.save(update_fields=["password", "password_changed_at"])

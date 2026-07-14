"""
Change password service for the SecureAuthX authentication module.
"""

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService
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
        request=None,
    ) -> None:
        """
        Change the authenticated user's password.

        Args:
            user:             The authenticated User instance.
            current_password: The user's existing plaintext password.
            new_password:     The desired new plaintext password.
            confirm_password: Confirmation of the new password.
            request:          HTTP request for IP/UA extraction.

        Raises:
            InvalidCredentialsException
            PasswordMismatchException
            WeakPasswordException
        """

        if not user.check_password(current_password):
            raise InvalidCredentialsException("Current password is incorrect.")

        if new_password != confirm_password:
            raise PasswordMismatchException()

        try:
            EnterprisePasswordValidator().validate(new_password, user=user)
        except ValidationError as exc:
            raise WeakPasswordException(message=" ".join(exc.messages)) from exc

        if user.check_password(new_password):
            raise WeakPasswordException(
                message="New password must differ from your current password."
            )

        user.set_password(new_password)
        user.password_changed_at = timezone.now()
        user.save(update_fields=["password", "password_changed_at"])

        AuditLogService.log(
            event_type=AuditLog.EventType.PASSWORD_CHANGED,
            status=AuditLog.Status.SUCCESS,
            description=f"Password changed successfully for {user.email}.",
            user=user,
            request=request,
            resource="User",
            resource_id=str(user.id),
        )

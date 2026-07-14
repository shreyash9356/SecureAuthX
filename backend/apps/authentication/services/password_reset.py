"""
Password reset service for the SecureAuthX authentication module.
"""

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService
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
        request=None,
    ) -> None:
        """
        Reset the user's password using a valid signed reset token.

        Args:
            token:            Signed password reset token.
            password:         New plaintext password.
            confirm_password: Confirmation of the new password.
            request:          HTTP request for IP/UA extraction.

        Raises:
            InvalidPasswordResetTokenException
            PasswordMismatchException
            WeakPasswordException
        """

        user_id = TokenService.verify_password_reset_token(token)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist as exc:
            raise InvalidPasswordResetTokenException() from exc

        if password != confirm_password:
            raise PasswordMismatchException()

        try:
            EnterprisePasswordValidator().validate(password, user=user)
        except ValidationError as exc:
            raise WeakPasswordException(message=" ".join(exc.messages)) from exc

        if user.check_password(password):
            raise WeakPasswordException(
                message="New password must differ from your current password."
            )

        user.set_password(password)
        user.password_changed_at = timezone.now()
        user.save(update_fields=["password", "password_changed_at"])

        AuditLogService.log(
            event_type=AuditLog.EventType.PASSWORD_RESET,
            status=AuditLog.Status.SUCCESS,
            description=f"Password reset successfully for {user.email}.",
            user=user,
            request=request,
            resource="User",
            resource_id=str(user.id),
        )

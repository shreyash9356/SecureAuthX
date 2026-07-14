"""
Forgot password service for the SecureAuthX authentication module.

Generates a signed password reset token and dispatches a reset email.

Security notes
--------------
- A generic success response is always returned regardless of whether
  the email exists in the database, preventing account enumeration.
- The reset token is time-limited (30 minutes) and signed using
  Django's ``TimestampSigner``.
"""

from django.contrib.auth import get_user_model

from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService
from apps.authentication.emails.password_reset import PasswordResetEmailService
from apps.authentication.tokens import TokenService

User = get_user_model()


class ForgotPasswordService:
    """
    Service responsible for initiating the password reset flow.
    """

    @staticmethod
    def send_reset_link(*, email: str, request=None) -> None:
        """
        Generate a password reset token and send the reset email.

        Always returns silently — callers must not rely on the return
        value to infer whether the email address exists.

        Args:
            email:   The email address submitted by the user.
            request: HTTP request for IP/UA extraction.
        """

        email = email.lower().strip()

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return

        if not user.is_active or user.is_locked:
            return

        token = TokenService.generate_password_reset_token(user.id)
        PasswordResetEmailService.send(user, token)

        AuditLogService.log(
            event_type=AuditLog.EventType.PASSWORD_RESET_REQUESTED,
            status=AuditLog.Status.INFO,
            description=f"Password reset link requested for {user.email}.",
            user=user,
            request=request,
            resource="User",
            resource_id=str(user.id),
        )

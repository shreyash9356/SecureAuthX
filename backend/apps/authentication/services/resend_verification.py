"""
Resend email verification service for the SecureAuthX authentication module.
"""

from django.contrib.auth import get_user_model

from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService
from apps.authentication.emails.verification import VerificationEmailService
from apps.authentication.tokens import TokenService

User = get_user_model()


class ResendVerificationService:
    """
    Service responsible for resending email verification links.
    """

    @staticmethod
    def resend(*, email: str, request=None) -> None:
        """
        Generate a new verification token and resend the verification email.

        Always returns silently — callers must not rely on the return
        value to determine whether the email exists (anti-enumeration).

        Args:
            email:   The email address submitted by the user.
            request: HTTP request for IP/UA extraction.
        """

        email = email.lower().strip()

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return

        if user.is_verified:
            return

        token = TokenService.generate_email_verification_token(user.id)
        VerificationEmailService.send(user=user, token=token)

        AuditLogService.log(
            event_type=AuditLog.EventType.EMAIL_VERIFICATION_SENT,
            status=AuditLog.Status.INFO,
            description=f"Verification email resent to {user.email}.",
            user=user,
            request=request,
            resource="User",
            resource_id=str(user.id),
        )

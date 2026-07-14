"""
Email verification service for the SecureAuthX authentication module.
"""

from django.contrib.auth import get_user_model
from django.db import transaction

from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService
from apps.authentication.exceptions import InvalidVerificationTokenException
from apps.authentication.tokens import TokenService

User = get_user_model()


class EmailVerificationService:
    """
    Service responsible for verifying user email addresses.
    """

    @staticmethod
    @transaction.atomic
    def verify(*, token: str, request=None) -> None:
        """
        Verify a user's email address using a signed token.

        Args:
            token:   Signed email verification token.
            request: HTTP request for IP/UA extraction.

        Raises:
            InvalidVerificationTokenException: Token is invalid or expired.
        """

        # Validate token and extract user ID
        user_id = TokenService.verify_email_verification_token(token)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist as exc:
            raise InvalidVerificationTokenException() from exc

        if user.is_verified:
            # Already verified — idempotent, no error raised
            return

        user.is_verified = True
        user.save(update_fields=["is_verified"])

        AuditLogService.log(
            event_type=AuditLog.EventType.EMAIL_VERIFIED,
            status=AuditLog.Status.SUCCESS,
            description=f"Email address verified for {user.email}.",
            user=user,
            request=request,
            resource="User",
            resource_id=str(user.id),
        )

"""
Logout service for the SecureAuthX authentication module.
"""

from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService
from apps.authentication.exceptions import InvalidCredentialsException


class LogoutService:
    """
    Service responsible for logging out users by blacklisting
    their refresh token.
    """

    @staticmethod
    def logout(
        *,
        refresh_token: str,
        user=None,
        request=None,
    ) -> None:
        """
        Blacklist the supplied refresh token.

        Args:
            refresh_token: JWT refresh token.
            user:          The authenticated User instance (for audit log).
            request:       HTTP request for IP/UA extraction.

        Raises:
            InvalidCredentialsException: Token is invalid or expired.
        """

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()

        except TokenError as exc:
            raise InvalidCredentialsException(
                "Refresh token is invalid or expired."
            ) from exc

        AuditLogService.log(
            event_type=AuditLog.EventType.LOGOUT,
            status=AuditLog.Status.SUCCESS,
            description="User logged out and refresh token blacklisted.",
            user=user,
            request=request,
            resource="User",
            resource_id=str(user.id) if user else "",
        )

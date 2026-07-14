"""
Token refresh service for the SecureAuthX authentication module.
"""

from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService
from apps.authentication.exceptions import InvalidCredentialsException


class RefreshTokenService:
    """
    Service responsible for refreshing JWT access tokens.
    """

    @staticmethod
    def refresh(*, refresh_token: str, user=None, request=None) -> dict:
        """
        Validate the refresh token and generate a new access token.

        Args:
            refresh_token: JWT refresh token.
            user:          Authenticated user (for audit log).
            request:       HTTP request for IP/UA extraction.

        Returns:
            Dictionary containing the new access token.

        Raises:
            InvalidCredentialsException
        """

        try:
            token = RefreshToken(refresh_token)
            access_token = str(token.access_token)

        except TokenError as exc:
            raise InvalidCredentialsException(
                "Refresh token is invalid or expired."
            ) from exc

        AuditLogService.log(
            event_type=AuditLog.EventType.TOKEN_REFRESHED,
            status=AuditLog.Status.SUCCESS,
            description="JWT access token refreshed.",
            user=user,
            request=request,
            resource="User",
            resource_id=str(user.id) if user else "",
        )

        return {"access": access_token}

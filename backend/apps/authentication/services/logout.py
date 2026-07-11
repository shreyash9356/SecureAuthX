"""
Logout service for the SecureAuthX authentication module.
"""

from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from apps.authentication.exceptions import InvalidCredentialsException


class LogoutService:
    """
    Service responsible for logging out users by blacklisting
    their refresh token.
    """

    @staticmethod
    def logout(*, refresh_token: str) -> None:
        """
        Blacklist the supplied refresh token.

        Args:
            refresh_token: JWT refresh token.

        Raises:
            InvalidCredentialsException:
                If the refresh token is invalid or expired.
        """

        try:
            token = RefreshToken(refresh_token)

            # Blacklist the refresh token
            token.blacklist()

        except TokenError as exc:
            raise InvalidCredentialsException(
                "Refresh token is invalid or expired."
            ) from exc
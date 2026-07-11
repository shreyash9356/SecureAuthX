"""
Token refresh service for the SecureAuthX authentication module.
"""

from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from apps.authentication.exceptions import InvalidCredentialsException


class RefreshTokenService:
    """
    Service responsible for refreshing JWT access tokens.
    """

    @staticmethod
    def refresh(*, refresh_token: str) -> dict:
        """
        Validate the refresh token and generate a new access token.

        Args:
            refresh_token: JWT refresh token.

        Returns:
            Dictionary containing the new access token.

        Raises:
            InvalidCredentialsException
        """

        try:
            token = RefreshToken(refresh_token)

            access_token = str(token.access_token)

            return {
                "access": access_token,
            }

        except TokenError as exc:
            raise InvalidCredentialsException(
                "Refresh token is invalid or expired."
            ) from exc
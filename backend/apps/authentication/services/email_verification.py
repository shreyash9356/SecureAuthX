"""
Email verification service for the SecureAuthX authentication module.
"""

from django.contrib.auth import get_user_model
from django.db import transaction

from apps.authentication.tokens import TokenService

User = get_user_model()


class EmailVerificationService:
    """
    Service responsible for verifying user email addresses.
    """

    @staticmethod
    @transaction.atomic
    def verify(*, token: str) -> None:
        """
        Verify a user's email address.

        Args:
            token: Email verification token.

        Raises:
            InvalidVerificationTokenException
        """

        # Implementation will be added next.
        pass
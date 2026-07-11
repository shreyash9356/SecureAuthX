"""
Login service for the SecureAuthX authentication module.
"""

from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.db import transaction
from rest_framework_simplejwt.tokens import RefreshToken

from apps.authentication.exceptions import (
    AccountInactiveException,
    EmailNotVerifiedException,
    InvalidCredentialsException,
)

User = get_user_model()


class LoginService:
    """
    Service responsible for authenticating users.
    """

    @staticmethod
    @transaction.atomic
    def login(
        *,
        email: str,
        password: str,
    ) -> dict:
        """
        Authenticate a user and generate JWT tokens.

        Returns:
            Dictionary containing the authenticated user
            and JWT tokens.

        Raises:
            InvalidCredentialsException
            EmailNotVerifiedException
            AccountInactiveException
        """

        email = email.lower().strip()

        user = authenticate(
            username=email,
            password=password,
        )

        if user is None:
            raise InvalidCredentialsException()

        if not user.is_active:
            raise AccountInactiveException()

        if not user.is_verified:
            raise EmailNotVerifiedException()

        if user.is_locked:
            raise AccountInactiveException(
                "Your account has been locked."
            )

        refresh = RefreshToken.for_user(user)

        return {
            "user": user,
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        }
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

from apps.authentication.emails.password_reset import PasswordResetEmailService
from apps.authentication.tokens import TokenService

User = get_user_model()


class ForgotPasswordService:
    """
    Service responsible for initiating the password reset flow.
    """

    @staticmethod
    def send_reset_link(*, email: str) -> None:
        """
        Generate a password reset token and send the reset email.

        Always returns silently — callers must not rely on the return
        value to infer whether the email address exists.

        Args:
            email: The email address submitted by the user.
        """

        email = email.lower().strip()

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Prevent account enumeration — no exception is raised.
            return

        # Only active, non-locked accounts receive the reset email.
        if not user.is_active or user.is_locked:
            return

        token = TokenService.generate_password_reset_token(user.id)

        PasswordResetEmailService.send(user, token)

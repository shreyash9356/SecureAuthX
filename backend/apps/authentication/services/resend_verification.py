"""
Resend email verification service.
"""

from django.contrib.auth import get_user_model

from apps.authentication.tokens import TokenService

User = get_user_model()


class ResendVerificationService:
    """
    Service responsible for resending email verification links.
    """

    @staticmethod
    def resend(*, email: str) -> bool:
        """
        Generate a new verification token for an unverified user.

        Returns:
            bool:
                True if an email should be sent.
                False if nothing should be sent.
        """

        email = email.lower().strip()

        try:
            user = User.objects.get(email=email)

        except User.DoesNotExist:
            # Generic response to prevent user enumeration
            return False

        if user.is_verified:
            return False

        token = TokenService.generate_email_verification_token(user.id)

        # Email sending will be implemented later
        # VerificationEmailService.send(user, token)

        return True
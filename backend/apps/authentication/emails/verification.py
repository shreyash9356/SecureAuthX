"""
Email verification service for the SecureAuthX authentication module.
"""


from apps.authentication.emails.base import BaseEmailService


class VerificationEmailService:
    """
    Service responsible for sending email verification messages.
    """

    SUBJECT = "Verify your SecureAuthX account"

    TEMPLATE_NAME = "emails/verification_email.html"

    @classmethod
    def send(
        cls,
        user,
        token: str,
    ) -> None:
        """
        Send an email verification message.

        Args:
            user:
                User instance.

            token:
                Signed verification token.
        """

        verification_url = (
            f"http://127.0.0.1:8000/api/v1/auth/verify-email/" f"?token={token}"
        )

        context = {
            "user": user,
            "verification_url": verification_url,
            "project_name": "SecureAuthX",
        }

        BaseEmailService.send_email(
            subject=cls.SUBJECT,
            recipient=user.email,
            template_name=cls.TEMPLATE_NAME,
            context=context,
        )

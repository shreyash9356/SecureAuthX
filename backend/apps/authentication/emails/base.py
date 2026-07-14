"""
Base email service for the SecureAuthX authentication module.
"""

import logging

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

logger = logging.getLogger(__name__)


class BaseEmailService:
    """
    Base service for sending HTML emails.
    """

    @staticmethod
    def send_email(
        *,
        subject: str,
        recipient: str,
        template_name: str,
        context: dict,
    ) -> None:
        """
        Send an HTML email with a plain-text fallback.

        Args:
            subject:
                Email subject.

            recipient:
                Recipient email address.

            template_name:
                Django template path.

            context:
                Template rendering context.
        """

        html_message = render_to_string(
            template_name,
            context,
        )

        plain_message = strip_tags(html_message)

        email = EmailMultiAlternatives(
            subject=subject,
            body=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[recipient],
        )

        email.attach_alternative(
            html_message,
            "text/html",
        )

        try:
            email.send()

            logger.info(
                "Email sent successfully to %s",
                recipient,
            )

        except Exception:
            logger.exception(
                "Failed to send email to %s",
                recipient,
            )

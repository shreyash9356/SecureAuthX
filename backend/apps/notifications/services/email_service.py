import logging
from typing import Any, Dict
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone

from apps.notifications.services.template_service import TemplateService

logger = logging.getLogger(__name__)


class EmailService:
    """
    Enterprise Email Delivery Service.
    
    Coordinates HTML and plain-text email generation using Django's EmailMultiAlternatives engine.
    Supports transactional authentication, security alerts, and organizational dispatches.
    """

    @classmethod
    def send_email(
        cls,
        *,
        recipient_email: str,
        subject: str,
        html_content: str,
        text_content: str = None,
        from_email: str = None,
    ) -> bool:
        """
        Sends an HTML/text email using Django's EmailMultiAlternatives.
        
        Args:
            recipient_email: Target email address.
            subject: Subject header text.
            html_content: HTML body content.
            text_content: Plaintext body (auto-stripped from HTML if omitted).
            from_email: Sender address (defaults to settings.DEFAULT_FROM_EMAIL).
            
        Returns:
            True if mail was dispatched successfully, False otherwise.
        """
        if not text_content:
            text_content = strip_tags(html_content)

        sender = from_email or getattr(settings, "DEFAULT_FROM_EMAIL", "webmaster@localhost")

        try:
            msg = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=sender,
                to=[recipient_email],
            )
            msg.attach_alternative(html_content, "text/html")
            sent_count = msg.send(fail_silently=False)
            logger.info("Sent email '%s' to %s (status=%d)", subject, recipient_email, sent_count)
            return sent_count > 0
        except Exception as e:
            logger.error("Failed to send email '%s' to %s: %s", subject, recipient_email, str(e))
            return False

    @classmethod
    def render_and_send(
        cls,
        *,
        recipient_email: str,
        template_name: str,
        default_subject: str,
        context: Dict[str, Any],
        html_template_path: str = None,
    ) -> bool:
        """
        Helper method that attempts DB template lookup first, falls back to static HTML file.
        """
        db_rendered = TemplateService.get_and_render_template(
            name=template_name,
            context=context,
            default_subject=default_subject,
        )

        subject = db_rendered["subject"] or default_subject

        if html_template_path:
            try:
                html_content = render_to_string(html_template_path, context)
            except Exception:
                html_content = db_rendered["body"] or f"<p>{subject}</p>"
        else:
            html_content = db_rendered["body"] or f"<p>{subject}</p>"

        return cls.send_email(
            recipient_email=recipient_email,
            subject=subject,
            html_content=html_content,
        )

    # --------------------------------------------------------------------------
    # Specialized Email Dispatch Methods
    # --------------------------------------------------------------------------

    @classmethod
    def send_verification_email(cls, *, user, token_or_url: str) -> bool:
        """
        Sends an email verification link to a newly registered user.
        """
        verification_url = token_or_url if token_or_url.startswith("http") else f"{getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')}/verify-email?token={token_or_url}"
        context = {
            "first_name": getattr(user, "first_name", "") or user.email.split("@")[0],
            "verification_url": verification_url,
        }
        return cls.render_and_send(
            recipient_email=user.email,
            template_name="verification_email",
            default_subject="Verify Your Email Address - SecureAuthX",
            context=context,
            html_template_path="emails/verification_email.html",
        )

    @classmethod
    def send_password_reset_email(cls, *, user, token_or_url: str) -> bool:
        """
        Sends a password reset link to a user.
        """
        reset_url = token_or_url if token_or_url.startswith("http") else f"{getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')}/reset-password?token={token_or_url}"
        context = {
            "first_name": getattr(user, "first_name", "") or user.email.split("@")[0],
            "reset_url": reset_url,
        }
        return cls.render_and_send(
            recipient_email=user.email,
            template_name="password_reset",
            default_subject="Reset Your Password - SecureAuthX",
            context=context,
            html_template_path="emails/password_reset.html",
        )

    @classmethod
    def send_mfa_enabled_email(cls, *, user) -> bool:
        """
        Notifies a user that Multi-Factor Authentication (MFA) was activated on their account.
        """
        context = {
            "first_name": getattr(user, "first_name", "") or user.email.split("@")[0],
            "alert_title": "Multi-Factor Authentication Enabled",
            "details": "Multi-Factor Authentication (TOTP) has been successfully activated for your SecureAuthX identity.",
        }
        return cls.render_and_send(
            recipient_email=user.email,
            template_name="mfa_enabled",
            default_subject="MFA Enabled - SecureAuthX",
            context=context,
            html_template_path="emails/security_alert.html",
        )

    @classmethod
    def send_mfa_disabled_email(cls, *, user) -> bool:
        """
        Notifies a user that Multi-Factor Authentication (MFA) was deactivated on their account.
        """
        context = {
            "first_name": getattr(user, "first_name", "") or user.email.split("@")[0],
            "alert_title": "Multi-Factor Authentication Disabled",
            "details": "Multi-Factor Authentication has been deactivated for your account. If you did not make this change, please contact security immediately.",
        }
        return cls.render_and_send(
            recipient_email=user.email,
            template_name="mfa_disabled",
            default_subject="MFA Disabled Warning - SecureAuthX",
            context=context,
            html_template_path="emails/security_alert.html",
        )

    @classmethod
    def send_login_alert_email(
        cls,
        *,
        user,
        ip_address: str,
        user_agent: str,
        location: str = None
    ) -> bool:
        """
        Sends an alert email for a new successful login session.
        """
        context = {
            "first_name": getattr(user, "first_name", "") or user.email.split("@")[0],
            "ip_address": ip_address,
            "user_agent": user_agent,
            "timestamp": timezone.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "location": location or "Unknown",
        }
        return cls.render_and_send(
            recipient_email=user.email,
            template_name="login_alert",
            default_subject="Security Alert: New Login to SecureAuthX",
            context=context,
            html_template_path="emails/login_alert.html",
        )

    @classmethod
    def send_new_device_login_email(
        cls,
        *,
        user,
        device: str,
        ip_address: str,
        location: str = None
    ) -> bool:
        """
        Sends an alert email for an authentication session from a previously unrecognized device.
        """
        context = {
            "first_name": getattr(user, "first_name", "") or user.email.split("@")[0],
            "device": device,
            "ip_address": ip_address,
            "location": location or "Unknown",
        }
        return cls.render_and_send(
            recipient_email=user.email,
            template_name="new_device",
            default_subject="Security Alert: New Device Sign-In - SecureAuthX",
            context=context,
            html_template_path="emails/new_device.html",
        )

    @classmethod
    def send_organization_invitation_email(
        cls,
        *,
        recipient_email: str,
        organization_name: str,
        inviter_name: str,
        invitation_url: str
    ) -> bool:
        """
        Dispatches an organization invitation email to a prospective member.
        """
        context = {
            "organization_name": organization_name,
            "inviter_name": inviter_name,
            "invitation_url": invitation_url,
        }
        return cls.render_and_send(
            recipient_email=recipient_email,
            template_name="organization_invitation",
            default_subject=f"Invitation to join {organization_name} on SecureAuthX",
            context=context,
            html_template_path="emails/organization_invitation.html",
        )

    @classmethod
    def send_security_alert_email(cls, *, user, alert_title: str, details: str) -> bool:
        """
        Dispatches a generic critical security alert to a user.
        """
        context = {
            "first_name": getattr(user, "first_name", "") or user.email.split("@")[0],
            "alert_title": alert_title,
            "details": details,
        }
        return cls.render_and_send(
            recipient_email=user.email,
            template_name="security_alert",
            default_subject=f"Security Alert: {alert_title} - SecureAuthX",
            context=context,
            html_template_path="emails/security_alert.html",
        )

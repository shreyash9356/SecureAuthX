from django.core import mail
from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.notifications.services.email_service import EmailService

User = get_user_model()


class EmailServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="email_user",
            email="emailuser@example.com",
            password="Password123!",
            first_name="John",
        )

    def test_send_generic_email(self):
        success = EmailService.send_email(
            recipient_email="target@example.com",
            subject="Test Subject",
            html_content="<p>Test Body</p>",
        )

        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, "Test Subject")
        self.assertIn("target@example.com", mail.outbox[0].to)

    def test_send_verification_email(self):
        success = EmailService.send_verification_email(
            user=self.user,
            token_or_url="http://localhost:3000/verify-email?token=xyz",
        )
        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Verify Your Email Address", mail.outbox[0].subject)

    def test_send_password_reset_email(self):
        success = EmailService.send_password_reset_email(
            user=self.user,
            token_or_url="http://localhost:3000/reset-password?token=abc",
        )
        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Reset Your Password", mail.outbox[0].subject)

    def test_send_mfa_enabled_email(self):
        success = EmailService.send_mfa_enabled_email(user=self.user)
        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("MFA Enabled", mail.outbox[0].subject)

    def test_send_mfa_disabled_email(self):
        success = EmailService.send_mfa_disabled_email(user=self.user)
        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("MFA Disabled Warning", mail.outbox[0].subject)

    def test_send_login_alert_email(self):
        success = EmailService.send_login_alert_email(
            user=self.user,
            ip_address="127.0.0.1",
            user_agent="Chrome/100",
        )
        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Security Alert", mail.outbox[0].subject)

    def test_send_new_device_login_email(self):
        success = EmailService.send_new_device_login_email(
            user=self.user,
            device="iPhone 15",
            ip_address="192.168.1.1",
        )
        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("New Device Sign-In", mail.outbox[0].subject)

    def test_send_organization_invitation_email(self):
        success = EmailService.send_organization_invitation_email(
            recipient_email="invitee@example.com",
            organization_name="Acme Corp",
            inviter_name="Alice Admin",
            invitation_url="http://localhost:3000/invite/accept",
        )
        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Acme Corp", mail.outbox[0].subject)

    def test_send_security_alert_email(self):
        success = EmailService.send_security_alert_email(
            user=self.user,
            alert_title="Multiple Failed Attempts",
            details="Account locked after 5 failed logins.",
        )
        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Multiple Failed Attempts", mail.outbox[0].subject)

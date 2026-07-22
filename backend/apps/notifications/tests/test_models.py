import uuid
from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.notifications.models import (
    Notification,
    NotificationPreference,
    NotificationTemplate,
    NotificationCategory,
    NotificationPriority,
    NotificationChannel,
)

User = get_user_model()


class NotificationModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="notif_user",
            email="notifuser@example.com",
            password="Password123!",
        )

    def test_create_notification(self):
        notif = Notification.objects.create(
            user=self.user,
            title="Test Title",
            message="Test message content.",
            category=NotificationCategory.SECURITY,
            priority=NotificationPriority.HIGH,
            channel=NotificationChannel.IN_APP,
            metadata={"ip": "127.0.0.1"},
        )

        self.assertIsInstance(notif.id, uuid.UUID)
        self.assertEqual(notif.user, self.user)
        self.assertFalse(notif.is_read)
        self.assertFalse(notif.is_deleted)
        self.assertIn("notifuser@example.com", str(notif))

    def test_notification_preference_creation(self):
        pref = NotificationPreference.objects.create(user=self.user)
        self.assertTrue(pref.email_notifications)
        self.assertTrue(pref.in_app_notifications)
        self.assertTrue(pref.security_notifications)
        self.assertIn("notifuser@example.com", str(pref))

    def test_notification_template_creation(self):
        template = NotificationTemplate.objects.create(
            name="test_template",
            category=NotificationCategory.GENERAL,
            channel=NotificationChannel.EMAIL,
            subject="Welcome {{ first_name }}",
            title="Hello {{ first_name }}",
            body="Your email is {{ email }}.",
        )

        self.assertTrue(template.is_active)
        self.assertIn("test_template", str(template))

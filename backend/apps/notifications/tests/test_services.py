from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.notifications.models import (
    Notification,
    NotificationCategory,
    NotificationPriority,
)
from apps.notifications.services.notification_service import NotificationService
from apps.notifications.services.template_service import TemplateService
from apps.organizations.models import Organization

User = get_user_model()


class NotificationServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="srv_user",
            email="srvuser@example.com",
            password="Password123!",
        )
        self.org = Organization.objects.create(
            name="Test Org",
            slug="test-org",
            owner=self.user,
        )

    def test_create_notification(self):
        notif = NotificationService.create_notification(
            user=self.user,
            title="Service Alert",
            message="Service notification message",
            category=NotificationCategory.SYSTEM,
            priority=NotificationPriority.HIGH,
        )

        self.assertIsNotNone(notif)
        self.assertEqual(notif.user, self.user)
        self.assertEqual(notif.title, "Service Alert")

    def test_mark_as_read(self):
        notif = NotificationService.create_notification(
            user=self.user,
            title="Unread Alert",
            message="Read me",
        )
        self.assertFalse(notif.is_read)

        updated = NotificationService.mark_as_read(notification_id=notif.id, user=self.user)
        self.assertTrue(updated.is_read)
        self.assertIsNotNone(updated.read_at)

    def test_mark_all_as_read(self):
        NotificationService.create_notification(user=self.user, title="N1", message="M1")
        NotificationService.create_notification(user=self.user, title="N2", message="M2")

        count = NotificationService.mark_all_as_read(user=self.user)
        self.assertEqual(count, 2)

        unread_count = Notification.objects.filter(user=self.user, is_read=False).count()
        self.assertEqual(unread_count, 0)

    def test_soft_delete_notification(self):
        notif = NotificationService.create_notification(user=self.user, title="Del", message="Delete me")
        deleted = NotificationService.soft_delete_notification(notification_id=notif.id, user=self.user)

        self.assertTrue(deleted.is_deleted)
        self.assertIsNotNone(deleted.deleted_at)

    def test_create_security_notification(self):
        notif = NotificationService.create_security_notification(
            user=self.user,
            title="Security Alert",
            message="Suspicious activity detected.",
            send_email=False,
        )
        self.assertEqual(notif.category, NotificationCategory.SECURITY)

    def test_create_login_alert(self):
        notif = NotificationService.create_login_alert(
            user=self.user,
            ip_address="192.168.1.50",
            user_agent="Firefox/100",
            send_email=False,
        )
        self.assertEqual(notif.category, NotificationCategory.AUTHENTICATION)
        self.assertEqual(notif.metadata["ip_address"], "192.168.1.50")

    def test_create_new_device_notification(self):
        notif = NotificationService.create_new_device_notification(
            user=self.user,
            device="MacBook Pro",
            ip_address="10.0.0.5",
            send_email=False,
        )
        self.assertEqual(notif.category, NotificationCategory.SECURITY)
        self.assertEqual(notif.metadata["device"], "MacBook Pro")

    def test_create_organization_notification(self):
        notif = NotificationService.create_organization_notification(
            user=self.user,
            organization=self.org,
            title="Tenant Joined",
            message="You joined Test Org",
            send_email=False,
        )
        self.assertEqual(notif.category, NotificationCategory.ORGANIZATION)
        self.assertEqual(notif.organization, self.org)

    def test_template_service_rendering(self):
        rendered = TemplateService.render_template_string(
            "Hello {{ first_name }}, welcome to {{ organization }}!",
            {"first_name": "Alice", "organization": "SecureAuthX"},
        )
        self.assertEqual(rendered, "Hello Alice, welcome to SecureAuthX!")

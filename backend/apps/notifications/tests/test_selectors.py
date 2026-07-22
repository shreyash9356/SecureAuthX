from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.notifications.models import (
    Notification,
    NotificationPreference,
    NotificationTemplate,
    NotificationCategory,
    NotificationChannel,
)
from apps.notifications.selectors import (
    get_notification_by_id,
    get_user_notifications,
    get_unread_notifications,
    get_notification_preferences,
    get_notification_template,
    list_active_templates,
)

User = get_user_model()


class NotificationSelectorTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="sel_user",
            email="seluser@example.com",
            password="Password123!",
        )
        self.notif1 = Notification.objects.create(
            user=self.user,
            title="Title 1",
            message="Message 1",
            category=NotificationCategory.SECURITY,
            is_read=False,
        )
        self.notif2 = Notification.objects.create(
            user=self.user,
            title="Title 2",
            message="Message 2",
            category=NotificationCategory.ORGANIZATION,
            is_read=True,
        )
        self.deleted_notif = Notification.objects.create(
            user=self.user,
            title="Deleted",
            message="Deleted content",
            is_deleted=True,
        )

    def test_get_notification_by_id(self):
        fetched = get_notification_by_id(self.notif1.id, self.user)
        self.assertEqual(fetched, self.notif1)

    def test_get_user_notifications(self):
        all_notifs = get_user_notifications(self.user)
        self.assertEqual(all_notifs.count(), 2)
        self.assertNotIn(self.deleted_notif, all_notifs)

    def test_get_user_notifications_filtered(self):
        sec_notifs = get_user_notifications(self.user, category=NotificationCategory.SECURITY)
        self.assertEqual(sec_notifs.count(), 1)
        self.assertEqual(sec_notifs.first(), self.notif1)

    def test_get_unread_notifications(self):
        unread = get_unread_notifications(self.user)
        self.assertEqual(unread.count(), 1)
        self.assertEqual(unread.first(), self.notif1)

    def test_get_notification_preferences(self):
        prefs = get_notification_preferences(self.user)
        self.assertIsInstance(prefs, NotificationPreference)
        self.assertEqual(prefs.user, self.user)

    def test_get_notification_template(self):
        template = NotificationTemplate.objects.create(
            name="welcome",
            channel=NotificationChannel.EMAIL,
            title="Welcome",
            body="Body",
        )
        fetched = get_notification_template("welcome", NotificationChannel.EMAIL)
        self.assertEqual(fetched, template)

    def test_list_active_templates(self):
        NotificationTemplate.objects.create(name="t1", channel=NotificationChannel.EMAIL, title="t1", body="b1")
        NotificationTemplate.objects.create(name="t2", channel=NotificationChannel.EMAIL, title="t2", body="b2", is_active=False)
        active = list_active_templates()
        self.assertEqual(active.count(), 1)
        self.assertEqual(active.first().name, "t1")

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from apps.notifications.models import (
    Notification,
    NotificationCategory,
    NotificationPreference,
)

User = get_user_model()


class NotificationAPITests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="api_user",
            email="apiuser@example.com",
            password="Password123!",
        )
        self.other_user = User.objects.create_user(
            username="other_user",
            email="otheruser@example.com",
            password="Password123!",
        )
        self.notif1 = Notification.objects.create(
            user=self.user,
            title="Notification 1",
            message="Message 1",
            category=NotificationCategory.SECURITY,
        )
        self.notif2 = Notification.objects.create(
            user=self.user,
            title="Notification 2",
            message="Message 2",
            category=NotificationCategory.GENERAL,
        )
        self.other_notif = Notification.objects.create(
            user=self.other_user,
            title="Other Notification",
            message="Other Message",
        )

    def test_list_notifications_unauthenticated(self):
        url = reverse("notifications:list")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_list_notifications_authenticated(self):
        self.client.force_authenticate(user=self.user)
        url = reverse("notifications:list")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 2)

    def test_get_notification_detail(self):
        self.client.force_authenticate(user=self.user)
        url = reverse("notifications:detail", kwargs={"pk": self.notif1.id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["success"])
        self.assertEqual(response.data["data"]["title"], "Notification 1")

    def test_get_other_user_notification_denied(self):
        self.client.force_authenticate(user=self.user)
        url = reverse("notifications:detail", kwargs={"pk": self.other_notif.id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_mark_notification_as_read(self):
        self.client.force_authenticate(user=self.user)
        url = reverse("notifications:mark_as_read", kwargs={"pk": self.notif1.id})
        response = self.client.patch(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["data"]["is_read"])

        self.notif1.refresh_from_db()
        self.assertTrue(self.notif1.is_read)

    def test_mark_all_as_read(self):
        self.client.force_authenticate(user=self.user)
        url = reverse("notifications:mark_all_as_read")
        response = self.client.patch(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 2)

        unread_count = Notification.objects.filter(user=self.user, is_read=False).count()
        self.assertEqual(unread_count, 0)

    def test_delete_notification(self):
        self.client.force_authenticate(user=self.user)
        url = reverse("notifications:detail", kwargs={"pk": self.notif1.id})
        response = self.client.delete(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.notif1.refresh_from_db()
        self.assertTrue(self.notif1.is_deleted)

    def test_get_notification_preferences(self):
        self.client.force_authenticate(user=self.user)
        url = reverse("notifications:preferences")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["data"]["email_notifications"])

    def test_update_notification_preferences(self):
        self.client.force_authenticate(user=self.user)
        url = reverse("notifications:preferences")
        data = {"marketing_notifications": True, "email_notifications": False}
        response = self.client.patch(url, data=data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["data"]["marketing_notifications"])
        self.assertFalse(response.data["data"]["email_notifications"])

        pref = NotificationPreference.objects.get(user=self.user)
        self.assertTrue(pref.marketing_notifications)
        self.assertFalse(pref.email_notifications)

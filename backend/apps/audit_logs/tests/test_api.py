from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from apps.audit_logs.models import AuditLog

User = get_user_model()


class AuditLogAPITests(APITestCase):
    def setUp(self):
        self.staff_user = User.objects.create_user(
            username="staff_user",
            email="staff@test.com",
            password="password123",
            is_staff=True,
        )
        self.regular_user = User.objects.create_user(
            username="regular_user",
            email="regular@test.com",
            password="password123",
            is_staff=False,
        )
        self.log = AuditLog.objects.create(
            user=self.regular_user,
            event_type=AuditLog.EventType.LOGIN_SUCCESS,
            status=AuditLog.Status.SUCCESS,
            description="Regular login",
            ip_address="127.0.0.1",
        )

    def test_list_audit_logs_staff(self):
        self.client.force_authenticate(user=self.staff_user)
        url = reverse("audit_logs:list")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["results"]["success"])
        self.assertIn("count", response.data)

    def test_list_audit_logs_regular_denied(self):
        self.client.force_authenticate(user=self.regular_user)
        url = reverse("audit_logs:list")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_get_audit_log_detail_staff(self):
        self.client.force_authenticate(user=self.staff_user)
        url = reverse("audit_logs:detail", kwargs={"pk": self.log.id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["success"])
        self.assertEqual(response.data["data"]["event_type"], "LOGIN_SUCCESS")

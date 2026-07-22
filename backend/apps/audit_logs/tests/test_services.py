from unittest.mock import MagicMock, patch
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIRequestFactory

from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService

User = get_user_model()


class AuditLogServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="serviceuser",
            email="service@example.com",
            password="Password123!",
        )
        self.factory = APIRequestFactory()

    def test_log_success_with_request(self):
        request = self.factory.post(
            "/api/v1/auth/login/",
            HTTP_X_FORWARDED_FOR="203.0.113.195, 70.41.3.18",
            HTTP_USER_AGENT="TestAgent/1.0",
        )

        log = AuditLogService.log(
            event_type=AuditLog.EventType.LOGIN_SUCCESS,
            status=AuditLog.Status.SUCCESS,
            description="User logged in via test.",
            user=self.user,
            request=request,
            metadata={"ip_type": "ipv4"},
            resource="UserSession",
            resource_id="12345",
        )

        self.assertIsNotNone(log)
        self.assertEqual(log.user, self.user)
        self.assertEqual(log.event_type, AuditLog.EventType.LOGIN_SUCCESS)
        self.assertEqual(log.ip_address, "203.0.113.195")
        self.assertEqual(log.user_agent, "TestAgent/1.0")
        self.assertEqual(log.metadata, {"ip_type": "ipv4"})
        self.assertEqual(log.resource, "UserSession")
        self.assertEqual(log.resource_id, "12345")

    def test_log_success_without_request(self):
        log = AuditLogService.log(
            event_type=AuditLog.EventType.USER_ACTIVATED,
            status=AuditLog.Status.SUCCESS,
            description="User activated via background process.",
            user=self.user,
            request=None,
            resource="User",
            resource_id=str(self.user.id),
        )

        self.assertIsNotNone(log)
        self.assertIsNone(log.ip_address)
        self.assertEqual(log.user_agent, "")

    def test_log_swallows_exception(self):
        with patch.object(AuditLog.objects, "create", side_effect=Exception("Database error")):
            log = AuditLogService.log(
                event_type=AuditLog.EventType.LOGIN_FAILED,
                status=AuditLog.Status.FAILURE,
                description="Should fail silently.",
                user=self.user,
            )

            self.assertIsNone(log)

import uuid
from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.audit_logs.models import AuditLog

User = get_user_model()


class AuditLogModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser",
            email="testuser@example.com",
            password="Password123!",
        )

    def test_create_audit_log_authenticated(self):
        log = AuditLog.objects.create(
            user=self.user,
            event_type=AuditLog.EventType.LOGIN_SUCCESS,
            status=AuditLog.Status.SUCCESS,
            description="User logged in successfully.",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            metadata={"device": "desktop"},
            resource="User",
            resource_id=str(self.user.id),
        )

        self.assertIsInstance(log.id, uuid.UUID)
        self.assertEqual(log.user, self.user)
        self.assertEqual(log.event_type, AuditLog.EventType.LOGIN_SUCCESS)
        self.assertEqual(log.status, AuditLog.Status.SUCCESS)
        self.assertEqual(log.ip_address, "192.168.1.1")
        self.assertEqual(log.user_agent, "Mozilla/5.0")
        self.assertEqual(log.metadata, {"device": "desktop"})
        self.assertEqual(log.resource, "User")
        self.assertEqual(log.resource_id, str(self.user.id))
        self.assertIsNotNone(log.created_at)

    def test_create_audit_log_anonymous(self):
        log = AuditLog.objects.create(
            user=None,
            event_type=AuditLog.EventType.LOGIN_FAILED,
            status=AuditLog.Status.FAILURE,
            description="Failed login attempt for unknown user.",
            ip_address="10.0.0.1",
        )

        self.assertNil = self.assertIsNone(log.user)
        self.assertEqual(log.event_type, AuditLog.EventType.LOGIN_FAILED)
        self.assertIn("anonymous", str(log))

    def test_str_representation(self):
        log = AuditLog.objects.create(
            user=self.user,
            event_type=AuditLog.EventType.PASSWORD_CHANGED,
            status=AuditLog.Status.SUCCESS,
            description="Password changed.",
        )
        self.assertIn("PASSWORD_CHANGED", str(log))
        self.assertIn("testuser@example.com", str(log))

    def test_user_deletion_preserves_audit_log(self):
        log = AuditLog.objects.create(
            user=self.user,
            event_type=AuditLog.EventType.ACCOUNT_LOCKED,
            status=AuditLog.Status.WARNING,
            description="Account locked.",
        )

        self.user.delete()
        log.refresh_from_db()

        self.assertIsNone(log.user)
        self.assertEqual(log.event_type, AuditLog.EventType.ACCOUNT_LOCKED)

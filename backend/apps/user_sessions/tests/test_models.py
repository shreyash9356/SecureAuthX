from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from apps.user_sessions.models import UserSession

User = get_user_model()


class UserSessionModelTests(TestCase):
    """
    Model level tests for UserSession constraints and status helper properties.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            email="testuser@secureauthx.com",
            password="SecurePassword123!",
            is_verified=True,
        )

    def test_session_creation_with_defaults(self):
        now = timezone.now()
        expires_at = now + timedelta(days=7)
        session = UserSession.objects.create(
            user=self.user,
            ip_address="127.0.0.1",
            user_agent="Mozilla/5.0",
            login_time=now,
            last_activity=now,
            expires_at=expires_at,
            status=UserSession.Status.ACTIVE,
        )

        self.assertEqual(session.status, UserSession.Status.ACTIVE)
        self.assertTrue(session.is_active)
        self.assertFalse(session.is_expired)
        self.assertIn("ACTIVE", str(session))
        self.assertIn("testuser@secureauthx.com", str(session))

    def test_logout_time_constraint_violated(self):
        # Database constraint chk_usess_logout_time_requires_logged_out
        # should fail if logout_time is populated on an active session
        now = timezone.now()
        with self.assertRaises(IntegrityError):
            UserSession.objects.create(
                user=self.user,
                ip_address="127.0.0.1",
                login_time=now,
                last_activity=now,
                expires_at=now + timedelta(days=7),
                logout_time=now,  # Invalid: status is ACTIVE by default
            )

    def test_revoked_at_constraint_violated(self):
        # Database constraint chk_usess_revoked_at_requires_revoked
        # should fail if revoked_at is populated on an active session
        now = timezone.now()
        with self.assertRaises(IntegrityError):
            UserSession.objects.create(
                user=self.user,
                ip_address="127.0.0.1",
                login_time=now,
                last_activity=now,
                expires_at=now + timedelta(days=7),
                revoked_at=now,  # Invalid: status is ACTIVE by default
            )

    def test_last_activity_before_login_constraint_violated(self):
        # Database constraint chk_usess_last_activity_not_before_login
        now = timezone.now()
        with self.assertRaises(IntegrityError):
            UserSession.objects.create(
                user=self.user,
                ip_address="127.0.0.1",
                login_time=now,
                last_activity=now - timedelta(seconds=1),  # Invalid: before login
                expires_at=now + timedelta(days=7),
            )

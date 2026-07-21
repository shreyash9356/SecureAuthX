from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.authentication.exceptions import AuthenticationException
from apps.user_sessions.models import UserSession
from apps.user_sessions.services.session_service import SessionService

User = get_user_model()


class UserSessionServiceTests(TestCase):
    """
    Service level tests for session lifecycle and transitions.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            email="serviceuser@secureauthx.com",
            password="SecurePassword123!",
            is_verified=True,
        )

    def test_create_session(self):
        session = SessionService.create_session(
            user=self.user,
            ip_address="192.168.1.1",
            user_agent="Firefox",
            device_type="DESKTOP",
            browser="Firefox",
            operating_system="Linux",
        )

        self.assertEqual(session.user, self.user)
        self.assertEqual(session.status, UserSession.Status.ACTIVE)
        self.assertEqual(session.ip_address, "192.168.1.1")
        self.assertEqual(session.device_type, "DESKTOP")

    def test_update_last_activity_success(self):
        session = SessionService.create_session(
            user=self.user, ip_address="127.0.0.1"
        )
        initial_activity = session.last_activity

        updated_session = SessionService.update_last_activity(session)
        self.assertGreaterEqual(updated_session.last_activity, initial_activity)

    def test_update_last_activity_expired(self):
        session = SessionService.create_session(
            user=self.user, ip_address="127.0.0.1"
        )
        session.expires_at = timezone.now() - timedelta(seconds=1)
        session.save()

        with self.assertRaises(AuthenticationException) as context:
            SessionService.update_last_activity(session)
        self.assertIn("expired", str(context.exception))

        session.refresh_from_db()
        self.assertEqual(session.status, UserSession.Status.EXPIRED)

    def test_logout_session_success(self):
        session = SessionService.create_session(
            user=self.user, ip_address="127.0.0.1"
        )
        logged_out = SessionService.logout_session(session)
        self.assertEqual(logged_out.status, UserSession.Status.LOGGED_OUT)
        self.assertIsNotNone(logged_out.logout_time)

    def test_logout_session_already_inactive(self):
        session = SessionService.create_session(
            user=self.user, ip_address="127.0.0.1"
        )
        SessionService.logout_session(session)

        # Voluntarily logging out twice is rejected
        with self.assertRaises(AuthenticationException):
            SessionService.logout_session(session)

    def test_logout_all_sessions(self):
        s1 = SessionService.create_session(user=self.user, ip_address="127.0.0.1")
        s2 = SessionService.create_session(user=self.user, ip_address="127.0.0.2")
        s3 = SessionService.create_session(user=self.user, ip_address="127.0.0.3")

        terminated = SessionService.logout_all_sessions(
            self.user, exclude_session=s1
        )
        self.assertEqual(terminated, 2)

        s1.refresh_from_db()
        s2.refresh_from_db()
        s3.refresh_from_db()

        self.assertEqual(s1.status, UserSession.Status.ACTIVE)
        self.assertEqual(s2.status, UserSession.Status.LOGGED_OUT)
        self.assertEqual(s3.status, UserSession.Status.LOGGED_OUT)

    def test_revoke_session(self):
        admin = User.objects.create_user(
            email="admin@secureauthx.com",
            password="AdminPassword123!",
            is_verified=True,
            is_staff=True,
        )
        session = SessionService.create_session(
            user=self.user, ip_address="127.0.0.1"
        )

        revoked = SessionService.revoke_session(
            session, revoked_by=admin, revocation_reason="Compromised credentials"
        )
        self.assertEqual(revoked.status, UserSession.Status.REVOKED)
        self.assertEqual(revoked.revoked_by, admin)
        self.assertEqual(revoked.revocation_reason, "Compromised credentials")

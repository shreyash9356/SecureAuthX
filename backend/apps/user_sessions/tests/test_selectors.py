from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.organizations.models import Organization
from apps.user_sessions.models import UserSession
from apps.user_sessions.selectors.session_selector import SessionSelector

User = get_user_model()


class UserSessionSelectorTests(TestCase):
    """
    Selector level tests for querying UserSessions.
    """

    def setUp(self):
        self.user1 = User.objects.create_user(
            email="user1@secureauthx.com",
            password="Password123!",
            is_verified=True,
        )
        self.user2 = User.objects.create_user(
            email="user2@secureauthx.com",
            password="Password123!",
            is_verified=True,
        )
        self.org = Organization.objects.create(
            name="Test Org",
            slug="test-org",
            owner=self.user1,
        )

        now = timezone.now()

        # Active session for user1
        self.session_active = UserSession.objects.create(
            user=self.user1,
            ip_address="127.0.0.1",
            login_time=now,
            last_activity=now,
            expires_at=now + timedelta(days=7),
            status=UserSession.Status.ACTIVE,
        )

        # Expired session for user1
        self.session_expired = UserSession.objects.create(
            user=self.user1,
            ip_address="127.0.0.1",
            login_time=now - timedelta(days=2),
            last_activity=now - timedelta(days=1),
            expires_at=now - timedelta(seconds=1),  # logically expired
            status=UserSession.Status.ACTIVE,
        )

        # Logged out session for user1
        self.session_logged_out = UserSession.objects.create(
            user=self.user1,
            ip_address="127.0.0.1",
            login_time=now,
            last_activity=now,
            expires_at=now + timedelta(days=7),
            logout_time=now,
            status=UserSession.Status.LOGGED_OUT,
        )

        # Active session for user1 with organization context
        self.session_org = UserSession.objects.create(
            user=self.user1,
            organization=self.org,
            ip_address="127.0.0.1",
            login_time=now,
            last_activity=now,
            expires_at=now + timedelta(days=7),
            status=UserSession.Status.ACTIVE,
        )

    def test_get_session_by_id(self):
        session = SessionSelector.get_session_by_id(self.session_active.id)
        self.assertEqual(session, self.session_active)

    def test_get_active_session_by_id(self):
        session = SessionSelector.get_active_session_by_id(self.session_active.id)
        self.assertEqual(session, self.session_active)

        with self.assertRaises(UserSession.DoesNotExist):
            SessionSelector.get_active_session_by_id(self.session_expired.id)

        with self.assertRaises(UserSession.DoesNotExist):
            SessionSelector.get_active_session_by_id(self.session_logged_out.id)

    def test_list_active_sessions_for_user(self):
        active_sessions = SessionSelector.list_active_sessions_for_user(self.user1)
        self.assertEqual(active_sessions.count(), 2)
        self.assertIn(self.session_active, active_sessions)
        self.assertIn(self.session_org, active_sessions)
        self.assertNotIn(self.session_expired, active_sessions)
        self.assertNotIn(self.session_logged_out, active_sessions)

        self.assertEqual(
            SessionSelector.list_active_sessions_for_user(self.user2).count(), 0
        )

    def test_list_active_sessions_for_organization(self):
        active_org_sessions = (
            SessionSelector.list_active_sessions_for_organization(self.org.id)
        )
        self.assertEqual(active_org_sessions.count(), 1)
        self.assertIn(self.session_org, active_org_sessions)

    def test_get_active_session_by_id_and_user(self):
        session = SessionSelector.get_active_session_by_id_and_user(
            self.session_active.id, self.user1
        )
        self.assertEqual(session, self.session_active)

        # IDOR protection: user2 tries to access user1's session
        with self.assertRaises(UserSession.DoesNotExist):
            SessionSelector.get_active_session_by_id_and_user(
                self.session_active.id, self.user2
            )

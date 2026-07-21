from datetime import timedelta

from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.constants import MembershipStatus
from apps.organizations.models import Organization, OrganizationMembership
from apps.user_sessions.models import UserSession
from apps.user_sessions.services.session_service import SessionService

User = get_user_model()


class UserSessionIntegrationTests(APITestCase):
    """
    End-to-end integration tests for user session validation, activity tracking, and tenant isolation.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            email="integrationuser@secureauthx.com",
            password="Password123!",
            is_verified=True,
        )

        self.org1 = Organization.objects.create(
            name="Org One", slug="org-one", owner=self.user
        )
        self.org2 = Organization.objects.create(
            name="Org Two", slug="org-two", owner=self.user
        )

        from apps.authorization.models import Role
        from apps.authorization.constants import RoleSlugs

        self.role = Role.objects.create(
            name="Employee",
            slug=RoleSlugs.EMPLOYEE,
        )

        OrganizationMembership.objects.create(
            user=self.user,
            organization=self.org1,
            status=MembershipStatus.ACTIVE,
            role=self.role,
        )

    def test_login_flow_creates_session_and_attaches_claim(self):
        url = reverse("authentication:login")
        response = self.client.post(
            url,
            {
                "email": "integrationuser@secureauthx.com",
                "password": "Password123!",
            },
            HTTP_USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            REMOTE_ADDR="192.168.1.100",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertIn("access", response.data["data"])
        self.assertIn("refresh", response.data["data"])

        sessions = UserSession.objects.filter(user=self.user)
        self.assertEqual(sessions.count(), 1)
        session = sessions.first()
        self.assertEqual(session.status, UserSession.Status.ACTIVE)
        self.assertEqual(session.ip_address, "192.168.1.100")
        self.assertEqual(session.device_type, "DESKTOP")
        self.assertEqual(session.browser, "Chrome")
        self.assertEqual(session.operating_system, "Windows")
        self.assertEqual(session.organization, self.org1)

        refresh_token = RefreshToken(response.data["data"]["refresh"])
        self.assertEqual(refresh_token.get("session_id"), str(session.id))

    def test_authenticated_request_updates_last_activity_and_validates(self):
        session = SessionService.create_session(
            user=self.user, ip_address="127.0.0.1", user_agent="Mozilla"
        )
        refresh = RefreshToken.for_user(self.user)
        refresh["session_id"] = str(session.id)
        access_token = str(refresh.access_token)

        initial_activity = session.last_activity

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        url = reverse("user_sessions:session-list")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        session.refresh_from_db()
        self.assertGreaterEqual(session.last_activity, initial_activity)

    def test_revoked_session_access_denied(self):
        session = SessionService.create_session(
            user=self.user, ip_address="127.0.0.1", user_agent="Mozilla"
        )
        refresh = RefreshToken.for_user(self.user)
        refresh["session_id"] = str(session.id)
        access_token = str(refresh.access_token)

        session.status = UserSession.Status.REVOKED
        session.revoked_at = timezone.now()
        session.save(update_fields=["status", "revoked_at"])

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        url = reverse("user_sessions:session-list")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("no longer active", response.data["errors"]["detail"].lower())

    def test_expired_session_access_denied_and_persisted(self):
        session = SessionService.create_session(
            user=self.user, ip_address="127.0.0.1", user_agent="Mozilla"
        )
        refresh = RefreshToken.for_user(self.user)
        refresh["session_id"] = str(session.id)
        access_token = str(refresh.access_token)

        session.expires_at = timezone.now() - timedelta(seconds=1)
        session.save(update_fields=["expires_at"])

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        url = reverse("user_sessions:session-list")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("expired", response.data["errors"]["detail"].lower())

        session.refresh_from_db()
        self.assertEqual(session.status, UserSession.Status.EXPIRED)

    def test_tenant_isolation_checks(self):
        session = SessionService.create_session(
            user=self.user, ip_address="127.0.0.1", user_agent="Mozilla"
        )
        refresh = RefreshToken.for_user(self.user)
        refresh["session_id"] = str(session.id)
        access_token = str(refresh.access_token)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")

        url = reverse("user_sessions:session-list")
        response = self.client.get(url, {"organization_id": str(self.org2.id)})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

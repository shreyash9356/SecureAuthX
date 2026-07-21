from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from apps.authorization.constants import RoleSlugs
from apps.authorization.models import Role, UserRole
from apps.user_sessions.models import UserSession
from apps.user_sessions.services.session_service import SessionService

User = get_user_model()


class UserSessionAPITests(APITestCase):
    """
    API level tests for User Sessions endpoints.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            email="apiuser@secureauthx.com",
            password="SecurePassword123!",
            is_verified=True,
        )
        self.other_user = User.objects.create_user(
            email="otheruser@secureauthx.com",
            password="SecurePassword123!",
            is_verified=True,
        )

        # Create session and get access token for self.user
        self.session = SessionService.create_session(
            user=self.user, ip_address="127.0.0.1", user_agent="Mozilla"
        )
        refresh = RefreshToken.for_user(self.user)
        refresh["session_id"] = str(self.session.id)
        self.access_token = str(refresh.access_token)

        # Create session and token for other_user
        self.other_session = SessionService.create_session(
            user=self.other_user, ip_address="127.0.0.1", user_agent="Mozilla"
        )
        other_refresh = RefreshToken.for_user(self.other_user)
        other_refresh["session_id"] = str(self.other_session.id)
        self.other_access_token = str(other_refresh.access_token)

    def test_list_sessions_unauthenticated_fails(self):
        url = reverse("user_sessions:session-list")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_list_sessions_success(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        url = reverse("user_sessions:session-list")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["success"])
        self.assertEqual(len(response.data["data"]["results"]), 1)
        self.assertEqual(
            response.data["data"]["results"][0]["id"], str(self.session.id)
        )

    def test_session_detail_owner_success(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        url = reverse(
            "user_sessions:session-detail", kwargs={"session_id": self.session.id}
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["data"]["id"], str(self.session.id))

    def test_session_detail_idor_protection(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        url = reverse(
            "user_sessions:session-detail",
            kwargs={"session_id": self.other_session.id},
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_logout_current_session_success(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        url = reverse("user_sessions:logout-current")
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.session.refresh_from_db()
        self.assertEqual(self.session.status, UserSession.Status.LOGGED_OUT)

    def test_logout_all_sessions(self):
        s2 = SessionService.create_session(
            user=self.user, ip_address="127.0.0.2"
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")

        url = reverse("user_sessions:logout-all")
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.session.refresh_from_db()
        self.assertEqual(self.session.status, UserSession.Status.ACTIVE)

        s2.refresh_from_db()
        self.assertEqual(s2.status, UserSession.Status.LOGGED_OUT)

    def test_admin_revoke_session_success(self):
        admin = User.objects.create_user(
            email="admin@secureauthx.com",
            password="AdminPassword123!",
            is_verified=True,
        )
        admin_role = Role.objects.create(
            name="Administrator",
            slug=RoleSlugs.ADMIN,
        )
        UserRole.objects.create(user=admin, role=admin_role)

        admin_refresh = RefreshToken.for_user(admin)
        admin_session = SessionService.create_session(
            user=admin, ip_address="127.0.0.1"
        )
        admin_refresh["session_id"] = str(admin_session.id)
        admin_token = str(admin_refresh.access_token)

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {admin_token}")
        url = reverse(
            "user_sessions:session-revoke", kwargs={"session_id": self.session.id}
        )
        response = self.client.post(
            url, {"revocation_reason": "Suspicious login pattern detected"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.session.refresh_from_db()
        self.assertEqual(self.session.status, UserSession.Status.REVOKED)
        self.assertEqual(
            self.session.revocation_reason, "Suspicious login pattern detected"
        )

    def test_non_admin_cannot_revoke_session(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        url = reverse(
            "user_sessions:session-revoke",
            kwargs={"session_id": self.other_session.id},
        )
        response = self.client.post(url, {"revocation_reason": "Hacking"})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

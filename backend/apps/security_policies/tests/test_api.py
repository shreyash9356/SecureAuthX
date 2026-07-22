from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from apps.security_policies.models import SecurityPolicy

User = get_user_model()


class SecurityPolicyAPITests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="normaluser",
            email="normal@example.com",
            password="Password123!",
            is_staff=False,
        )
        self.admin_user = User.objects.create_user(
            username="adminuser",
            email="admin@example.com",
            password="Password123!",
            is_staff=True,
        )

    def test_get_effective_policy_authenticated(self):
        self.client.force_authenticate(user=self.user)
        url = reverse("security_policies:effective_policy")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["success"])
        self.assertEqual(response.data["data"]["min_password_length"], 12)

    def test_get_global_policy_admin_only(self):
        # Non-admin denied
        self.client.force_authenticate(user=self.user)
        url = reverse("security_policies:global_policy")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # Admin allowed
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_patch_global_policy_admin(self):
        self.client.force_authenticate(user=self.admin_user)
        url = reverse("security_policies:global_policy")
        data = {"min_password_length": 15, "require_special_char": True}
        response = self.client.patch(url, data=data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["data"]["min_password_length"], 15)

    def test_validate_password_endpoint(self):
        self.client.force_authenticate(user=self.user)
        url = reverse("security_policies:validate_password")
        
        # Valid password
        response = self.client.post(url, data={"password": "ValidP@ssword123!"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Invalid password
        response = self.client.post(url, data={"password": "short"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

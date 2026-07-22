import uuid
from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.security_policies.models import SecurityPolicy, PasswordHistory
from apps.organizations.models import Organization

User = get_user_model()


class SecurityPolicyModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="policyuser",
            email="policyuser@example.com",
            password="Password123!",
        )
        self.org = Organization.objects.create(
            name="Policy Org",
            slug="policy-org",
            owner=self.user,
        )

    def test_create_global_security_policy(self):
        policy = SecurityPolicy.objects.create(
            name="Global Security Policy",
            min_password_length=14,
            require_uppercase=True,
            require_lowercase=True,
            require_numeric=True,
            require_special_char=True,
            password_history_count=10,
            max_failed_login_attempts=3,
            lockout_duration_minutes=30,
        )

        self.assertIsInstance(policy.id, uuid.UUID)
        self.assertIsNone(policy.organization)
        self.assertTrue(policy.is_active)
        self.assertEqual(policy.min_password_length, 14)
        self.assertEqual(policy.password_history_count, 10)
        self.assertIn("Global Security Policy", str(policy))
        self.assertIn("Global Default", str(policy))

    def test_create_tenant_security_policy(self):
        policy = SecurityPolicy.objects.create(
            name="Acme Corp Policy",
            organization=self.org,
            require_mfa_for_all_org_members=True,
            ip_allowlist=["192.168.1.0/24"],
            ip_denylist=["10.0.0.1"],
            country_denylist=["CN", "RU"],
        )

        self.assertEqual(policy.organization, self.org)
        self.assertTrue(policy.require_mfa_for_all_org_members)
        self.assertEqual(policy.ip_allowlist, ["192.168.1.0/24"])
        self.assertIn("policy-org", str(policy))

    def test_password_history_creation(self):
        history = PasswordHistory.objects.create(
            user=self.user,
            password_hash="argon2$argon2id$v=19$m=65536,t=3,p=4$dummyhash",
        )

        self.assertIsInstance(history.id, uuid.UUID)
        self.assertEqual(history.user, self.user)
        self.assertIn("policyuser@example.com", str(history))

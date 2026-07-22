from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.security_policies.models import SecurityPolicy, PasswordHistory
from apps.security_policies.selectors import (
    get_global_security_policy,
    get_organization_security_policy,
    get_user_effective_policy,
    get_policy_by_id,
    get_user_password_history,
)
from apps.organizations.models import Organization, OrganizationMembership
from apps.organizations.constants import MembershipStatus
from apps.authorization.models import Role
from apps.authorization.constants import RoleSlugs

User = get_user_model()


class SecurityPolicySelectorTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="sel_policy_user",
            email="selpolicy@example.com",
            password="Password123!",
        )
        self.org = Organization.objects.create(
            name="Selector Org",
            slug="selector-org",
            owner=self.user,
        )

    def test_get_global_security_policy(self):
        policy = get_global_security_policy()
        self.assertIsNotNone(policy)
        self.assertEqual(policy.name, "Global Default Security Policy")
        self.assertIsNone(policy.organization)

    def test_get_organization_security_policy(self):
        org_policy = SecurityPolicy.objects.create(
            name="Org Policy",
            organization=self.org,
            min_password_length=16,
        )
        fetched = get_organization_security_policy(self.org)
        self.assertEqual(fetched, org_policy)
        self.assertEqual(fetched.min_password_length, 16)

    def test_get_user_effective_policy_fallback_to_global(self):
        effective = get_user_effective_policy(self.user)
        self.assertEqual(effective.name, "Global Default Security Policy")

    def test_get_user_effective_policy_with_tenant(self):
        org_policy = SecurityPolicy.objects.create(
            name="Tenant Custom Policy",
            organization=self.org,
            min_password_length=18,
        )
        effective = get_user_effective_policy(self.user, organization=self.org)
        self.assertEqual(effective, org_policy)
        self.assertEqual(effective.min_password_length, 18)

    def test_get_policy_by_id(self):
        policy = get_global_security_policy()
        fetched = get_policy_by_id(policy.id)
        self.assertEqual(fetched, policy)

    def test_get_user_password_history(self):
        h1 = PasswordHistory.objects.create(user=self.user, password_hash="hash1")
        h2 = PasswordHistory.objects.create(user=self.user, password_hash="hash2")

        history = get_user_password_history(self.user, limit=5)
        self.assertEqual(history.count(), 2)
        self.assertEqual(history[0], h2)

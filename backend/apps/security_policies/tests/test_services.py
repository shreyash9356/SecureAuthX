from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.security_policies.models import SecurityPolicy
from apps.security_policies.services.password_policy_service import PasswordPolicyService
from apps.security_policies.services.lockout_policy_service import LockoutPolicyService
from apps.security_policies.services.session_policy_service import SessionPolicyService
from apps.security_policies.services.mfa_policy_service import MFAPolicyService
from apps.security_policies.services.login_policy_service import LoginPolicyService
from apps.security_policies.services.security_policy_service import SecurityPolicyService
from apps.organizations.models import Organization

User = get_user_model()


class SecurityPolicyServicesTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="srv_policy_user",
            email="srvpolicy@example.com",
            password="Password123!",
            is_staff=True,
        )
        self.org = Organization.objects.create(
            name="Service Policy Org",
            slug="service-policy-org",
            owner=self.user,
        )

    def test_password_policy_validation_success(self):
        PasswordPolicyService.validate_password_against_policy("StrongP@ssword123", user=self.user)

    def test_password_policy_validation_failure_short(self):
        with self.assertRaises(ValidationError) as ctx:
            PasswordPolicyService.validate_password_against_policy("Short1!", user=self.user)
        self.assertIn("password", ctx.exception.message_dict)

    def test_password_history_recording_and_reuse_prevention(self):
        raw_pw = "InitialSecret123!"
        PasswordPolicyService.record_password_history(self.user, raw_pw)

        with self.assertRaises(ValidationError) as ctx:
            PasswordPolicyService.check_password_history_reuse(raw_pw, self.user)
        self.assertIn("password", ctx.exception.message_dict)

    def test_lockout_policy_service_failed_attempts(self):
        for _ in range(4):
            is_locked = LockoutPolicyService.evaluate_failed_login(self.user)
            self.assertFalse(is_locked)

        # 5th attempt triggers lockout
        is_locked = LockoutPolicyService.evaluate_failed_login(self.user)
        self.assertTrue(is_locked)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_locked)

    def test_lockout_policy_service_reset(self):
        LockoutPolicyService.evaluate_failed_login(self.user)
        LockoutPolicyService.reset_failed_login_attempts(self.user)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)

    def test_mfa_policy_service_requirements(self):
        req = MFAPolicyService.is_mfa_required_for_user(self.user)
        self.assertTrue(req)  # Admin staff user requires MFA by global policy

    def test_login_policy_service_ip_denylist(self):
        policy = SecurityPolicy.objects.create(
            name="IP Policy",
            ip_denylist=["10.0.0.0/8"],
        )
        with self.assertRaises(ValidationError):
            LoginPolicyService.validate_ip_address("10.0.0.5", policy=policy)

    def test_login_policy_service_ip_allowlist(self):
        policy = SecurityPolicy.objects.create(
            name="IP Allow Policy",
            ip_allowlist=["192.168.1.0/24"],
        )
        LoginPolicyService.validate_ip_address("192.168.1.10", policy=policy)

        with self.assertRaises(ValidationError):
            LoginPolicyService.validate_ip_address("172.16.0.1", policy=policy)

    def test_security_policy_service_update(self):
        policy = SecurityPolicyService.create_or_update_policy(
            name="Updated Global",
            actor=self.user,
            min_password_length=16,
        )
        self.assertEqual(policy.min_password_length, 16)

from datetime import timedelta
import time

from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
import pyotp

from apps.authentication.exceptions import InvalidCredentialsException
from apps.mfa.exceptions import (
    MFAAlreadyEnabledException,
    MFALockoutException,
    InvalidOTPException,
    InvalidRecoveryCodeException,
)
from apps.mfa.models import MFADevice, MFARecoveryCode
from apps.mfa.selectors.mfa_selector import MFASelector
from apps.mfa.services.admin import MFAAdminService
from apps.mfa.services.disable import MFADisableService
from apps.mfa.services.recovery import MFARecoveryService
from apps.mfa.services.setup import MFASetupService
from apps.mfa.services.verification import MFAVerificationService
from apps.mfa.utils.crypto import encrypt_secret, decrypt_secret
from apps.mfa.utils.recovery_codes import check_recovery_code

from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class MFATests(APITestCase):
    """
    Comprehensive test suite covering Multi-Factor Authentication (MFA) models,
    utils, services, API endpoints, integration flows, and security constraints.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            email="mfauser@secureauthx.com",
            password="SecurePassword123!",
            is_verified=True,
        )
        self.admin = User.objects.create_user(
            email="mfaadmin@secureauthx.com",
            password="SecurePassword123!",
            is_verified=True,
            is_staff=True,
        )

    def authenticate_user(self, user):
        from apps.user_sessions.services.session_service import SessionService
        session = SessionService.create_session(
            user=user,
            ip_address="127.0.0.1",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )
        refresh = RefreshToken.for_user(user)
        refresh["session_id"] = str(session.pk)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
        return session

    # ===========================================================================
    # 1. Models & Utilities
    # ===========================================================================

    def test_mfa_device_creation_and_properties(self):
        device = MFADevice.objects.create(
            user=self.user,
            secret="some-encrypted-secret",
            is_enabled=False,
        )
        self.assertEqual(str(device), "MFA<mfauser@secureauthx.com>")
        self.assertFalse(device.is_locked)

        # Enforce lock
        device.locked_until = timezone.now() + timedelta(minutes=15)
        device.save()
        self.assertTrue(device.is_locked)

    def test_mfa_recovery_code_creation(self):
        device = MFADevice.objects.create(user=self.user, secret="secret")
        code = MFARecoveryCode.objects.create(
            mfa_device=device,
            code_hash="some-hash",
            is_used=False,
        )
        self.assertEqual(str(code), "RecoveryCode<mfauser@secureauthx.com>")

    def test_crypto_encryption_decryption(self):
        secret = pyotp.random_base32()
        ciphertext = encrypt_secret(secret)
        self.assertNotEqual(secret, ciphertext)

        decrypted = decrypt_secret(ciphertext)
        self.assertEqual(secret, decrypted)

    # ===========================================================================
    # 2. Services
    # ===========================================================================

    def test_initiate_and_activate_mfa_service(self):
        # 1. Initiate setup
        secret, uri, qr_code = MFASetupService.initiate_mfa_setup(self.user)
        self.assertIsNotNone(secret)
        self.assertIn("mfauser", uri)
        self.assertTrue(qr_code.startswith("data:image/png;base64,"))

        device = MFASelector.get_device_by_user(self.user)
        self.assertIsNotNone(device)
        self.assertFalse(device.is_enabled)

        # Trying to initiate again raises exception
        with self.assertRaises(MFAAlreadyEnabledException):
            # First, activate it
            totp = pyotp.TOTP(secret)
            otp = totp.now()
            MFASetupService.activate_mfa(self.user, otp)

            # Re-initiate should be blocked
            MFASetupService.initiate_mfa_setup(self.user)

    def test_activate_mfa_invalid_otp(self):
        secret, *_ = MFASetupService.initiate_mfa_setup(self.user)
        with self.assertRaises(InvalidOTPException):
            MFASetupService.activate_mfa(self.user, "000000")

    def test_recovery_code_verification_and_regeneration(self):
        secret, *_ = MFASetupService.initiate_mfa_setup(self.user)
        totp = pyotp.TOTP(secret)
        raw_codes = MFASetupService.activate_mfa(self.user, totp.now())

        # Test verification of valid recovery code
        self.assertTrue(
            MFARecoveryService.verify_and_use_recovery_code(self.user, raw_codes[0])
        )

        # Re-using the same code is denied
        with self.assertRaises(InvalidRecoveryCodeException):
            MFARecoveryService.verify_and_use_recovery_code(self.user, raw_codes[0])

        # Regenerate codes
        new_codes = MFARecoveryService.regenerate_recovery_codes(self.user)
        self.assertEqual(len(new_codes), 10)
        self.assertNotEqual(new_codes, raw_codes)

    def test_otp_lockout_and_replay_protection(self):
        secret, *_ = MFASetupService.initiate_mfa_setup(self.user)
        totp = pyotp.TOTP(secret)
        MFASetupService.activate_mfa(self.user, totp.now())
        device = MFASelector.get_device_by_user(self.user)
        device.last_used_time_step -= 1
        device.save()

        # 1. Lockout protection (5 failed attempts)
        for _ in range(4):
            with self.assertRaises(InvalidOTPException):
                MFAVerificationService.verify_otp_login(self.user, "000000")

        # 5th attempt locks the device
        with self.assertRaises(MFALockoutException):
            MFAVerificationService.verify_otp_login(self.user, "000000")

        device = MFASelector.get_device_by_user(self.user)
        self.assertTrue(device.is_locked)

        # 2. Replay protection
        # Clear lockout administratively
        MFAAdminService.admin_unlock_mfa(self.admin, self.user)
        device.refresh_from_db()
        self.assertFalse(device.is_locked)

        otp = totp.now()
        # First verification succeeds
        self.assertTrue(MFAVerificationService.verify_otp_login(self.user, otp))

        # Replayed verification within same time step fails
        with self.assertRaises(InvalidOTPException):
            MFAVerificationService.verify_otp_login(self.user, otp)

    def test_disable_mfa(self):
        secret, *_ = MFASetupService.initiate_mfa_setup(self.user)
        totp = pyotp.TOTP(secret)
        MFASetupService.activate_mfa(self.user, totp.now())
        device = MFASelector.get_device_by_user(self.user)
        device.last_used_time_step -= 1
        device.save()

        # Disable using password and OTP
        MFADisableService.disable_mfa(
            self.user, password_confirmation="SecurePassword123!", otp_code=totp.now()
        )
        device = MFASelector.get_device_by_user(self.user)
        self.assertNil(device)  # Row is deleted

    def test_disable_mfa_invalid_password(self):
        secret, *_ = MFASetupService.initiate_mfa_setup(self.user)
        totp = pyotp.TOTP(secret)
        MFASetupService.activate_mfa(self.user, totp.now())
        device = MFASelector.get_device_by_user(self.user)
        device.last_used_time_step -= 1
        device.save()

        with self.assertRaises(InvalidCredentialsException):
            MFADisableService.disable_mfa(
                self.user, password_confirmation="WrongPassword!", otp_code=totp.now()
            )

    # ===========================================================================
    # 3. API & Integration
    # ===========================================================================

    def test_login_flow_redirects_to_mfa_and_authenticates(self):
        # 1. Enable MFA for the user
        secret, *_ = MFASetupService.initiate_mfa_setup(self.user)
        totp = pyotp.TOTP(secret)
        MFASetupService.activate_mfa(self.user, totp.now())
        device = MFASelector.get_device_by_user(self.user)
        device.last_used_time_step -= 1
        device.save()

        # 2. Login attempt step 1: Enter password credentials
        login_url = reverse("authentication:login")
        response = self.client.post(
            login_url,
            {"email": "mfauser@secureauthx.com", "password": "SecurePassword123!"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["success"])
        self.assertTrue(response.data["data"]["mfa_required"])
        mfa_token = response.data["data"]["mfa_token"]
        self.assertIsNotNone(mfa_token)

        # 3. Login attempt step 2: Submit OTP code along with the mfa_token
        verify_url = reverse("mfa:mfa-login-verify")
        verify_response = self.client.post(
            f"{verify_url}?mfa_token={mfa_token}",
            {"otp_code": totp.now()},
        )
        self.assertEqual(verify_response.status_code, status.HTTP_200_OK)
        self.assertIn("access", verify_response.data["data"])
        self.assertIn("refresh", verify_response.data["data"])

    def test_mfa_admin_actions(self):
        # Enable MFA
        secret, *_ = MFASetupService.initiate_mfa_setup(self.user)
        totp = pyotp.TOTP(secret)
        MFASetupService.activate_mfa(self.user, totp.now())
        device = MFASelector.get_device_by_user(self.user)
        device.last_used_time_step -= 1
        device.save()

        # Admin login
        from apps.authorization.models import Role, UserRole
        from apps.authorization.constants import RoleSlugs
        admin_role, _ = Role.objects.get_or_create(
            slug=RoleSlugs.ADMIN,
            defaults={"name": "Administrator"}
        )
        UserRole.objects.create(user=self.admin, role=admin_role)
        self.authenticate_user(self.admin)

        admin_url = reverse("mfa:mfa-admin-action")

        # Admin disables MFA for target user
        response = self.client.post(
            f"{admin_url}?action=disable&user_id={self.user.id}"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNil(MFASelector.get_device_by_user(self.user))

    # Helper assertion alias
    def assertNil(self, val):
        self.assertIsNone(val)

    def test_mfa_api_setup_and_activation(self):
        # 1. Authenticate user
        self.authenticate_user(self.user)

        # 2. Initiate setup via API
        init_url = reverse("mfa:mfa-setup-initiate")
        response = self.client.post(init_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        secret = response.data["data"]["manual_key"]
        qr_code = response.data["data"]["qr_code"]
        self.assertIsNotNone(secret)
        self.assertTrue(qr_code.startswith("data:image/png;base64,"))

        # 3. Get status via API
        status_url = reverse("mfa:mfa-status")
        status_response = self.client.get(status_url)
        self.assertEqual(status_response.status_code, status.HTTP_200_OK)
        self.assertFalse(status_response.data["data"]["is_enabled"])

        # 4. Activate MFA via API
        totp = pyotp.TOTP(secret)
        activate_url = reverse("mfa:mfa-setup-activate")
        activate_response = self.client.post(activate_url, {"otp_code": totp.now()})
        self.assertEqual(activate_response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(activate_response.data["data"]["recovery_codes"]), 10)

        # Status is now enabled
        status_response2 = self.client.get(status_url)
        self.assertTrue(status_response2.data["data"]["is_enabled"])

        # 5. Regenerate recovery codes via API
        regen_url = reverse("mfa:mfa-recovery-regenerate")
        regen_response = self.client.post(regen_url)
        self.assertEqual(regen_response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(regen_response.data["data"]["recovery_codes"]), 10)

        # 6. Disable MFA via API
        # We need to decrement step to allow TOTP reuse
        device = MFASelector.get_device_by_user(self.user)
        device.last_used_time_step -= 1
        device.save()

        disable_url = reverse("mfa:mfa-disable")
        disable_response = self.client.post(
            disable_url,
            {"password": "SecurePassword123!", "otp_code": totp.now()}
        )
        self.assertEqual(disable_response.status_code, status.HTTP_200_OK)
        self.assertIsNone(MFASelector.get_device_by_user(self.user))

    def test_dev_qr_code_export_and_endpoint(self):
        from apps.mfa.utils.totp import save_dev_qr_code, generate_qr_code_data_uri

        dev_qr_url = reverse("mfa:mfa-dev-qr")

        # 1. Non-DEBUG mode safety check
        with self.settings(DEBUG=False):
            self.assertIsNone(save_dev_qr_code("data:image/png;base64,1234"))
            res = self.client.get(dev_qr_url)
            self.assertEqual(res.status_code, status.HTTP_404_NOT_FOUND)

        # 2. DEBUG mode export and serving test
        with self.settings(DEBUG=True):
            data_uri = generate_qr_code_data_uri("otpauth://totp/Test:dev@example.com?secret=JBSWY3DPEHPK3PXP")
            file_path = save_dev_qr_code(data_uri)
            self.assertIsNotNone(file_path)

            res = self.client.get(dev_qr_url)
            self.assertEqual(res.status_code, status.HTTP_200_OK)
            self.assertEqual(res["Content-Type"], "image/png")

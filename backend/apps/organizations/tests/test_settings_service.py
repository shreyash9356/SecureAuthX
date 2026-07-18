from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from apps.organizations.models import Organization, OrganizationSettings
from apps.organizations.constants import OrganizationStatus
from apps.organizations.services.settings_service import SettingsService
from apps.organizations.exceptions import OrganizationNotFoundException

User = get_user_model()


class SettingsServiceTests(TestCase):
    """
    Unit tests for SettingsService.
    """

    def setUp(self):
        self.owner = User.objects.create_user(
            username="owner_pref",
            email="owner@example.com",
            password="password123"
        )
        self.org = Organization.objects.create(
            name="Alpha Tenant",
            slug="alpha-tenant",
            owner=self.owner,
            status=OrganizationStatus.ACTIVE
        )
        self.settings = OrganizationSettings.objects.create(
            organization=self.org,
            timezone="UTC",
            country="US",
            branding_name="Alpha Tenant",
            session_timeout_minutes=60
        )

    def test_get_settings_success(self):
        resolved = SettingsService.get_settings(self.org.id)
        self.assertEqual(resolved, self.settings)

    def test_get_settings_missing_raises_exception(self):
        with self.assertRaises(OrganizationNotFoundException):
            SettingsService.get_settings("99999999-9999-9999-9999-999999999999")

    def test_update_settings_success(self):
        updated = SettingsService.update_settings(
            self.org.id,
            timezone_str="GMT",
            country="GB",
            branding_name="Branded Alpha",
            session_timeout_minutes=30
        )
        self.assertEqual(updated.timezone, "GMT")
        self.assertEqual(updated.country, "GB")
        self.assertEqual(updated.branding_name, "Branded Alpha")
        self.assertEqual(updated.session_timeout_minutes, 30)

    def test_update_settings_invalid_timeout_raises_validation_error(self):
        # session_timeout_minutes is PositiveIntegerField, so negative values violate constraint
        with self.assertRaises(ValidationError):
            SettingsService.update_settings(
                self.org.id,
                session_timeout_minutes=-10
            )

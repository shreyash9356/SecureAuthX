from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from apps.authorization.models import Role
from apps.authorization.constants import RoleSlugs
from apps.organizations.models import Organization, OrganizationMembership, OrganizationSettings
from apps.organizations.constants import OrganizationStatus, MembershipStatus
from apps.organizations.services.organization_service import OrganizationService
from apps.organizations.exceptions import (
    OrganizationNotFoundException,
    OrganizationAlreadyExistsException,
)

User = get_user_model()


class OrganizationServiceTests(TestCase):
    """
    Unit tests for OrganizationService.
    """

    def setUp(self):
        self.owner = User.objects.create_user(
            username="org_owner",
            email="owner@test.com",
            password="password123"
        )
        self.admin_role = Role.objects.create(
            name="Administrator",
            slug=RoleSlugs.ADMIN,
            priority=800
        )

    def test_create_organization_success(self):
        org = OrganizationService.create_organization(
            name="Alpha Corp",
            owner=self.owner,
            description="Leading AI tenant"
        )
        self.assertEqual(org.name, "Alpha Corp")
        self.assertEqual(org.slug, "alpha-corp")
        self.assertEqual(org.owner, self.owner)
        self.assertEqual(org.status, OrganizationStatus.ACTIVE)

        # Verify settings initialized
        settings = OrganizationSettings.objects.get(organization=org)
        self.assertEqual(settings.timezone, "UTC")
        self.assertEqual(settings.branding_name, "Alpha Corp")

        # Verify owner membership initialized
        membership = OrganizationMembership.objects.get(organization=org, user=self.owner)
        self.assertEqual(membership.role, self.admin_role)
        self.assertEqual(membership.status, MembershipStatus.ACTIVE)

    def test_create_organization_duplicate_name_raises_exception(self):
        OrganizationService.create_organization(
            name="Unique Name",
            owner=self.owner
        )
        # Duplicate case-insensitive check
        with self.assertRaises(OrganizationAlreadyExistsException):
            OrganizationService.create_organization(
                name="unique name",
                owner=self.owner
            )

    def test_create_organization_automatic_slug_collision_resolution(self):
        org1 = OrganizationService.create_organization(
            name="Collision Test",
            owner=self.owner
        )
        self.assertEqual(org1.slug, "collision-test")

        # Creating organization with similar name that slugifies to the same base
        org2 = OrganizationService.create_organization(
            name="Collision Test!",
            owner=self.owner
        )
        self.assertEqual(org2.slug, "collision-test-1")

    def test_update_organization_success(self):
        org = OrganizationService.create_organization(
            name="Beta Corp",
            owner=self.owner
        )
        updated = OrganizationService.update_organization(
            org.id,
            name="Gamma Corp",
            description="Updated beta"
        )
        self.assertEqual(updated.name, "Gamma Corp")
        self.assertEqual(updated.description, "Updated beta")

    def test_update_organization_duplicate_name_raises_exception(self):
        org1 = OrganizationService.create_organization(
            name="Org One",
            owner=self.owner
        )
        org2 = OrganizationService.create_organization(
            name="Org Two",
            owner=self.owner
        )
        with self.assertRaises(OrganizationAlreadyExistsException):
            OrganizationService.update_organization(
                org2.id,
                name="org one"
            )

    def test_delete_organization_soft_deletes_roster(self):
        org = OrganizationService.create_organization(
            name="Soft Delete Corp",
            owner=self.owner
        )
        OrganizationService.delete_organization(org.id)

        # Verify org status
        org.refresh_from_db()
        self.assertEqual(org.status, OrganizationStatus.DELETED)

        # Verify memberships soft-deleted
        membership = OrganizationMembership.objects.get(organization=org, user=self.owner)
        self.assertEqual(membership.status, MembershipStatus.REMOVED)

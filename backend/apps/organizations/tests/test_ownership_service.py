from django.test import TestCase
from django.contrib.auth import get_user_model

from apps.authorization.models import Role
from apps.authorization.constants import RoleSlugs
from apps.organizations.models import Organization, OrganizationMembership
from apps.organizations.constants import OrganizationStatus, MembershipStatus
from apps.organizations.services.ownership_service import OwnershipService
from apps.organizations.exceptions import (
    OrganizationNotFoundException,
    OwnershipTransferException,
)

User = get_user_model()


class OwnershipServiceTests(TestCase):
    """
    Unit tests for OwnershipService.
    """

    def setUp(self):
        self.owner = User.objects.create_user(
            username="current_owner",
            email="current@example.com",
            password="password123"
        )
        self.new_owner = User.objects.create_user(
            username="new_owner",
            email="new@example.com",
            password="password123"
        )
        self.org = Organization.objects.create(
            name="Tenant One",
            slug="tenant-one",
            owner=self.owner,
            status=OrganizationStatus.ACTIVE
        )
        self.admin_role = Role.objects.create(
            name="Administrator",
            slug=RoleSlugs.ADMIN,
            priority=800
        )
        # Setup memberships
        self.owner_membership = OrganizationMembership.objects.create(
            organization=self.org,
            user=self.owner,
            role=self.admin_role,
            status=MembershipStatus.ACTIVE
        )
        self.new_owner_membership = OrganizationMembership.objects.create(
            organization=self.org,
            user=self.new_owner,
            role=self.admin_role,
            status=MembershipStatus.ACTIVE
        )

    def test_transfer_ownership_success(self):
        updated_org = OwnershipService.transfer_ownership(
            organization_id=self.org.id,
            current_owner=self.owner,
            new_owner=self.new_owner
        )
        self.assertEqual(updated_org.owner, self.new_owner)

        # Verify old owner retains admin membership
        self.owner_membership.refresh_from_db()
        self.assertEqual(self.owner_membership.role, self.admin_role)
        self.assertEqual(self.owner_membership.status, MembershipStatus.ACTIVE)

        # Verify new owner elevated to admin role
        self.new_owner_membership.refresh_from_db()
        self.assertEqual(self.new_owner_membership.role, self.admin_role)

    def test_transfer_ownership_not_current_owner_raises_exception(self):
        wrong_user = User.objects.create_user(
            username="wrong_initiator",
            email="wrong@example.com",
            password="password123"
        )
        with self.assertRaises(OwnershipTransferException):
            OwnershipService.transfer_ownership(
                organization_id=self.org.id,
                current_owner=wrong_user,
                new_owner=self.new_owner
            )

    def test_transfer_ownership_to_self_raises_exception(self):
        with self.assertRaises(OwnershipTransferException):
            OwnershipService.transfer_ownership(
                organization_id=self.org.id,
                current_owner=self.owner,
                new_owner=self.owner
            )

    def test_transfer_ownership_to_inactive_member_raises_exception(self):
        self.new_owner_membership.status = MembershipStatus.SUSPENDED
        self.new_owner_membership.save()

        with self.assertRaises(OwnershipTransferException):
            OwnershipService.transfer_ownership(
                organization_id=self.org.id,
                current_owner=self.owner,
                new_owner=self.new_owner
            )

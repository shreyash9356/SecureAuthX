from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from apps.authorization.models import Role
from apps.authorization.constants import RoleSlugs
from apps.organizations.models import Organization, OrganizationMembership
from apps.organizations.constants import OrganizationStatus, MembershipStatus
from apps.organizations.services.membership_service import MembershipService
from apps.organizations.exceptions import (
    MembershipAlreadyExistsException,
    MembershipNotFoundException,
    InvalidMembershipException,
)

User = get_user_model()


class MembershipServiceTests(TestCase):
    """
    Unit tests for MembershipService.
    """

    def setUp(self):
        self.owner = User.objects.create_user(
            username="owner_user",
            email="owner@example.com",
            password="password123"
        )
        self.user = User.objects.create_user(
            username="member_user",
            email="member@example.com",
            password="password123"
        )
        self.org = Organization.objects.create(
            name="Alpha Org",
            slug="alpha-org",
            owner=self.owner,
            status=OrganizationStatus.ACTIVE
        )
        self.admin_role = Role.objects.create(
            name="Administrator",
            slug=RoleSlugs.ADMIN,
            priority=800
        )
        self.employee_role = Role.objects.create(
            name="Employee",
            slug=RoleSlugs.EMPLOYEE,
            priority=100
        )
        # Owner membership setup
        self.owner_membership = OrganizationMembership.objects.create(
            organization=self.org,
            user=self.owner,
            role=self.admin_role,
            status=MembershipStatus.ACTIVE
        )

    def test_add_member_success(self):
        membership = MembershipService.add_member(
            organization_id=self.org.id,
            user_id=self.user.id,
            role_slug=RoleSlugs.EMPLOYEE
        )
        self.assertEqual(membership.user, self.user)
        self.assertEqual(membership.role, self.employee_role)
        self.assertEqual(membership.status, MembershipStatus.ACTIVE)

    def test_add_member_duplicate_raises_exception(self):
        MembershipService.add_member(
            organization_id=self.org.id,
            user_id=self.user.id,
            role_slug=RoleSlugs.EMPLOYEE
        )
        with self.assertRaises(MembershipAlreadyExistsException):
            MembershipService.add_member(
                organization_id=self.org.id,
                user_id=self.user.id,
                role_slug=RoleSlugs.EMPLOYEE
            )

    def test_add_member_reactivates_removed_membership(self):
        membership = OrganizationMembership.objects.create(
            organization=self.org,
            user=self.user,
            role=self.employee_role,
            status=MembershipStatus.REMOVED
        )
        reactivated = MembershipService.add_member(
            organization_id=self.org.id,
            user_id=self.user.id,
            role_slug=RoleSlugs.EMPLOYEE
        )
        self.assertEqual(reactivated.id, membership.id)
        self.assertEqual(reactivated.status, MembershipStatus.ACTIVE)

    def test_update_membership_role_success(self):
        membership = OrganizationMembership.objects.create(
            organization=self.org,
            user=self.user,
            role=self.employee_role,
            status=MembershipStatus.ACTIVE
        )
        updated = MembershipService.update_membership_role(
            membership_id=membership.id,
            role_slug=RoleSlugs.ADMIN,
            actor=self.owner
        )
        self.assertEqual(updated.role, self.admin_role)

    def test_update_membership_role_demote_owner_raises_exception(self):
        with self.assertRaises(InvalidMembershipException):
            MembershipService.update_membership_role(
                membership_id=self.owner_membership.id,
                role_slug=RoleSlugs.EMPLOYEE,
                actor=self.owner
            )

    def test_update_membership_status_success(self):
        membership = OrganizationMembership.objects.create(
            organization=self.org,
            user=self.user,
            role=self.employee_role,
            status=MembershipStatus.ACTIVE
        )
        updated = MembershipService.update_membership_status(
            membership_id=membership.id,
            status=MembershipStatus.SUSPENDED,
            actor=self.owner
        )
        self.assertEqual(updated.status, MembershipStatus.SUSPENDED)

    def test_update_membership_status_suspend_owner_raises_exception(self):
        with self.assertRaises(InvalidMembershipException):
            MembershipService.update_membership_status(
                membership_id=self.owner_membership.id,
                status=MembershipStatus.SUSPENDED,
                actor=self.owner
            )

    def test_remove_member_success(self):
        membership = OrganizationMembership.objects.create(
            organization=self.org,
            user=self.user,
            role=self.employee_role,
            status=MembershipStatus.ACTIVE
        )
        MembershipService.remove_member(
            membership_id=membership.id,
            actor=self.owner
        )
        membership.refresh_from_db()
        self.assertEqual(membership.status, MembershipStatus.REMOVED)

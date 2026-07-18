from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone

from apps.authorization.models import Role
from apps.authorization.constants import RoleSlugs
from apps.organizations.models import (
    Organization,
    OrganizationMembership,
    OrganizationInvitation,
    OrganizationSettings,
)
from apps.organizations.constants import (
    OrganizationStatus,
    MembershipStatus,
    InvitationStatus,
)
from apps.organizations.selectors import (
    OrganizationSelector,
    MembershipSelector,
    InvitationSelector,
    SettingsSelector,
)
from apps.organizations.exceptions import (
    OrganizationNotFoundException,
    MembershipNotFoundException,
    InvitationNotFoundException,
)

User = get_user_model()


class OrganizationSelectorTests(TestCase):
    """
    Unit tests for OrganizationSelector methods.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="password123"
        )
        self.org_active = Organization.objects.create(
            name="Active Corp",
            slug="active-corp",
            owner=self.user,
            status=OrganizationStatus.ACTIVE
        )
        self.org_inactive = Organization.objects.create(
            name="Inactive Corp",
            slug="inactive-corp",
            owner=self.user,
            status=OrganizationStatus.INACTIVE
        )
        self.org_deleted = Organization.objects.create(
            name="Deleted Corp",
            slug="deleted-corp",
            owner=self.user,
            status=OrganizationStatus.DELETED
        )

    def test_get_organization_by_id_success(self):
        resolved = OrganizationSelector.get_organization_by_id(self.org_active.id)
        self.assertEqual(resolved, self.org_active)

    def test_get_organization_by_id_deleted_raises_not_found(self):
        with self.assertRaises(OrganizationNotFoundException):
            OrganizationSelector.get_organization_by_id(self.org_deleted.id)

    def test_get_organization_by_id_deleted_include_deleted(self):
        resolved = OrganizationSelector.get_organization_by_id(self.org_deleted.id, include_deleted=True)
        self.assertEqual(resolved, self.org_deleted)

    def test_get_organization_by_id_missing_raises_not_found(self):
        with self.assertRaises(OrganizationNotFoundException):
            OrganizationSelector.get_organization_by_id("11111111-1111-1111-1111-111111111111")

    def test_get_organization_by_slug_success(self):
        resolved = OrganizationSelector.get_organization_by_slug("active-corp")
        self.assertEqual(resolved, self.org_active)

    def test_get_organization_by_slug_deleted_raises_not_found(self):
        with self.assertRaises(OrganizationNotFoundException):
            OrganizationSelector.get_organization_by_slug("deleted-corp")

    def test_get_organization_by_slug_deleted_include_deleted(self):
        resolved = OrganizationSelector.get_organization_by_slug("deleted-corp", include_deleted=True)
        self.assertEqual(resolved, self.org_deleted)

    def test_get_organization_by_slug_missing_raises_not_found(self):
        with self.assertRaises(OrganizationNotFoundException):
            OrganizationSelector.get_organization_by_slug("non-existent-slug")

    def test_list_active_organizations(self):
        active_list = list(OrganizationSelector.list_active_organizations())
        self.assertIn(self.org_active, active_list)
        self.assertNotIn(self.org_inactive, active_list)
        self.assertNotIn(self.org_deleted, active_list)

    def test_list_all_organizations(self):
        all_list = list(OrganizationSelector.list_all_organizations())
        self.assertIn(self.org_active, all_list)
        self.assertIn(self.org_inactive, all_list)
        self.assertNotIn(self.org_deleted, all_list)

    def test_list_all_organizations_include_deleted(self):
        all_list = list(OrganizationSelector.list_all_organizations(include_deleted=True))
        self.assertIn(self.org_active, all_list)
        self.assertIn(self.org_inactive, all_list)
        self.assertIn(self.org_deleted, all_list)


class MembershipSelectorTests(TestCase):
    """
    Unit tests for MembershipSelector methods.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="owner",
            email="owner@example.com",
            password="password123"
        )
        self.org = Organization.objects.create(
            name="Test Org",
            slug="test-org",
            owner=self.user,
            status=OrganizationStatus.ACTIVE
        )
        self.role = Role.objects.create(
            name="Admin",
            slug=RoleSlugs.ADMIN,
            priority=100
        )
        self.membership = OrganizationMembership.objects.create(
            organization=self.org,
            user=self.user,
            role=self.role,
            status=MembershipStatus.ACTIVE
        )
        self.removed_user = User.objects.create_user(
            username="removed_user",
            email="removed@example.com",
            password="password123"
        )
        self.removed_membership = OrganizationMembership.objects.create(
            organization=self.org,
            user=self.removed_user,
            role=self.role,
            status=MembershipStatus.REMOVED
        )

    def test_get_membership_by_id_success(self):
        resolved = MembershipSelector.get_membership_by_id(self.membership.id)
        self.assertEqual(resolved, self.membership)

    def test_get_membership_by_id_removed_raises_not_found(self):
        with self.assertRaises(MembershipNotFoundException):
            MembershipSelector.get_membership_by_id(self.removed_membership.id)

    def test_get_membership_by_id_removed_include_removed(self):
        resolved = MembershipSelector.get_membership_by_id(self.removed_membership.id, include_removed=True)
        self.assertEqual(resolved, self.removed_membership)

    def test_get_membership_by_id_missing_raises_not_found(self):
        with self.assertRaises(MembershipNotFoundException):
            MembershipSelector.get_membership_by_id("22222222-2222-2222-2222-222222222222")

    def test_get_user_membership_success(self):
        resolved = MembershipSelector.get_user_membership(
            organization_id=self.org.id,
            user_id=self.user.id
        )
        self.assertEqual(resolved, self.membership)

    def test_get_user_membership_removed_returns_none_when_excluded(self):
        resolved = MembershipSelector.get_user_membership(
            organization_id=self.org.id,
            user_id=self.removed_user.id,
            include_removed=False
        )
        self.assertIsNone(resolved)

    def test_get_user_membership_removed_success_by_default(self):
        resolved = MembershipSelector.get_user_membership(
            organization_id=self.org.id,
            user_id=self.removed_user.id
        )
        self.assertEqual(resolved, self.removed_membership)

    def test_get_user_membership_missing_returns_none(self):
        other_user = User.objects.create_user(
            username="other",
            email="other@example.com",
            password="password123"
        )
        resolved = MembershipSelector.get_user_membership(
            organization_id=self.org.id,
            user_id=other_user.id
        )
        self.assertIsNone(resolved)

    def test_list_organization_memberships_no_filter(self):
        memberships = list(MembershipSelector.list_organization_memberships(self.org.id))
        self.assertIn(self.membership, memberships)
        self.assertNotIn(self.removed_membership, memberships)

    def test_list_organization_memberships_include_removed(self):
        memberships = list(MembershipSelector.list_organization_memberships(self.org.id, include_removed=True))
        self.assertIn(self.membership, memberships)
        self.assertIn(self.removed_membership, memberships)

    def test_list_organization_memberships_with_status_match(self):
        memberships = list(MembershipSelector.list_organization_memberships(self.org.id, status=MembershipStatus.ACTIVE))
        self.assertIn(self.membership, memberships)
        self.assertNotIn(self.removed_membership, memberships)

    def test_list_organization_memberships_with_status_mismatch(self):
        memberships = list(MembershipSelector.list_organization_memberships(self.org.id, status=MembershipStatus.SUSPENDED))
        self.assertNotIn(self.membership, memberships)
        self.assertNotIn(self.removed_membership, memberships)


class InvitationSelectorTests(TestCase):
    """
    Unit tests for InvitationSelector methods.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="inviter",
            email="inviter@example.com",
            password="password123"
        )
        self.org = Organization.objects.create(
            name="Inv Org",
            slug="inv-org",
            owner=self.user,
            status=OrganizationStatus.ACTIVE
        )
        self.invitation = OrganizationInvitation.objects.create(
            organization=self.org,
            email="invited@example.com",
            invited_by=self.user,
            status=InvitationStatus.PENDING,
            expires_at=timezone.now() + timezone.timedelta(days=7)
        )

    def test_get_invitation_by_id_success(self):
        resolved = InvitationSelector.get_invitation_by_id(self.invitation.id)
        self.assertEqual(resolved, self.invitation)

    def test_get_invitation_by_id_missing_raises_not_found(self):
        with self.assertRaises(InvitationNotFoundException):
            InvitationSelector.get_invitation_by_id("33333333-3333-3333-3333-333333333333")

    def test_get_invitation_by_token_success(self):
        resolved = InvitationSelector.get_invitation_by_token(self.invitation.token)
        self.assertEqual(resolved, self.invitation)

    def test_get_invitation_by_token_missing_raises_not_found(self):
        with self.assertRaises(InvitationNotFoundException):
            InvitationSelector.get_invitation_by_token("44444444-4444-4444-4444-444444444444")

    def test_list_pending_invitations(self):
        pending = list(InvitationSelector.list_pending_invitations(self.org.id))
        self.assertIn(self.invitation, pending)


class SettingsSelectorTests(TestCase):
    """
    Unit tests for SettingsSelector methods.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="owner_settings",
            email="owner_settings@example.com",
            password="password123"
        )
        self.org = Organization.objects.create(
            name="Settings Org",
            slug="settings-org",
            owner=self.user,
            status=OrganizationStatus.ACTIVE
        )
        self.settings = OrganizationSettings.objects.create(
            organization=self.org,
            timezone="UTC",
            country="US"
        )

    def test_get_settings_by_organization_id_success(self):
        resolved = SettingsSelector.get_settings_by_organization_id(self.org.id)
        self.assertEqual(resolved, self.settings)

    def test_get_settings_by_organization_id_missing_raises_not_found(self):
        with self.assertRaises(OrganizationNotFoundException):
            SettingsSelector.get_settings_by_organization_id("55555555-5555-5555-5555-555555555555")

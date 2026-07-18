from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.exceptions import ValidationError

from apps.authorization.models import Role
from apps.authorization.constants import RoleSlugs
from apps.organizations.models import Organization, OrganizationMembership, OrganizationInvitation
from apps.organizations.constants import OrganizationStatus, MembershipStatus, InvitationStatus
from apps.organizations.services.invitation_service import InvitationService
from apps.organizations.exceptions import (
    InvitationNotFoundException,
    InvitationExpiredException,
    InvitationAlreadyAcceptedException,
    InvalidInvitationStateException,
    MembershipAlreadyExistsException,
)

User = get_user_model()


class InvitationServiceTests(TestCase):
    """
    Unit tests for InvitationService.
    """

    def setUp(self):
        self.owner = User.objects.create_user(
            username="inviter_owner",
            email="inviter@example.com",
            password="password123"
        )
        self.user = User.objects.create_user(
            username="existing_member",
            email="existing@example.com",
            password="password123"
        )
        self.org = Organization.objects.create(
            name="Alpha Org",
            slug="alpha-org",
            owner=self.owner,
            status=OrganizationStatus.ACTIVE
        )
        self.employee_role = Role.objects.create(
            name="Employee",
            slug=RoleSlugs.EMPLOYEE,
            priority=100
        )

    def test_invite_member_new_email_success(self):
        invitation = InvitationService.invite_member(
            organization_id=self.org.id,
            email="new_user@example.com",
            invited_by=self.owner,
            role_slug=RoleSlugs.EMPLOYEE
        )
        self.assertEqual(invitation.email, "new_user@example.com")
        self.assertEqual(invitation.status, InvitationStatus.PENDING)
        self.assertEqual(invitation.organization, self.org)

        # No membership should be created yet since user doesn't exist in system
        self.assertFalse(OrganizationMembership.objects.filter(organization=self.org, user__email="new_user@example.com").exists())

    def test_invite_member_existing_email_pre_registers_membership(self):
        invitation = InvitationService.invite_member(
            organization_id=self.org.id,
            email="existing@example.com",
            invited_by=self.owner,
            role_slug=RoleSlugs.EMPLOYEE
        )
        self.assertEqual(invitation.email, "existing@example.com")

        # Verify a PENDING membership was pre-registered
        membership = OrganizationMembership.objects.get(organization=self.org, user=self.user)
        self.assertEqual(membership.status, MembershipStatus.PENDING)

    def test_invite_member_invalidates_previous_pending_invitation(self):
        inv1 = InvitationService.invite_member(
            organization_id=self.org.id,
            email="repeat@example.com",
            invited_by=self.owner,
            role_slug=RoleSlugs.EMPLOYEE
        )
        inv2 = InvitationService.invite_member(
            organization_id=self.org.id,
            email="repeat@example.com",
            invited_by=self.owner,
            role_slug=RoleSlugs.EMPLOYEE
        )
        
        inv1.refresh_from_db()
        inv2.refresh_from_db()

        self.assertEqual(inv1.status, InvitationStatus.CANCELLED)
        self.assertEqual(inv2.status, InvitationStatus.PENDING)

    def test_accept_invitation_success(self):
        invitation = InvitationService.invite_member(
            organization_id=self.org.id,
            email="existing@example.com",
            invited_by=self.owner,
            role_slug=RoleSlugs.EMPLOYEE
        )
        membership = InvitationService.accept_invitation(
            token=invitation.token,
            user=self.user
        )
        self.assertEqual(membership.status, MembershipStatus.ACTIVE)
        self.assertEqual(membership.user, self.user)

        invitation.refresh_from_db()
        self.assertEqual(invitation.status, InvitationStatus.ACCEPTED)

    def test_accept_invitation_expired_raises_exception(self):
        invitation = OrganizationInvitation.objects.create(
            organization=self.org,
            email="existing@example.com",
            invited_by=self.owner,
            status=InvitationStatus.PENDING,
            expires_at=timezone.now() - timezone.timedelta(hours=1)
        )
        with self.assertRaises(InvitationExpiredException):
            InvitationService.accept_invitation(
                token=invitation.token,
                user=self.user
            )

    def test_accept_invitation_wrong_email_identity_raises_validation_error(self):
        invitation = InvitationService.invite_member(
            organization_id=self.org.id,
            email="existing@example.com",
            invited_by=self.owner,
            role_slug=RoleSlugs.EMPLOYEE
        )
        wrong_user = User.objects.create_user(
            username="wrong_user",
            email="wrong@example.com",
            password="password123"
        )
        with self.assertRaises(ValidationError):
            InvitationService.accept_invitation(
                token=invitation.token,
                user=wrong_user
            )

    def test_reject_invitation_success(self):
        invitation = InvitationService.invite_member(
            organization_id=self.org.id,
            email="new@example.com",
            invited_by=self.owner
        )
        rejected = InvitationService.reject_invitation(token=invitation.token)
        self.assertEqual(rejected.status, InvitationStatus.REJECTED)

    def test_cancel_invitation_success(self):
        invitation = InvitationService.invite_member(
            organization_id=self.org.id,
            email="new@example.com",
            invited_by=self.owner
        )
        cancelled = InvitationService.cancel_invitation(invitation_id=invitation.id, actor=self.owner)
        self.assertEqual(cancelled.status, InvitationStatus.CANCELLED)

    def test_invite_member_allowed_if_previous_invitation_cancelled(self):
        # 1. Create first invitation
        inv1 = InvitationService.invite_member(
            organization_id=self.org.id,
            email="existing@example.com",
            invited_by=self.owner,
            role_slug=RoleSlugs.EMPLOYEE
        )
        # 2. Cancel invitation
        InvitationService.cancel_invitation(invitation_id=inv1.id, actor=self.owner)
        # 3. Create second invitation - should succeed now
        inv2 = InvitationService.invite_member(
            organization_id=self.org.id,
            email="existing@example.com",
            invited_by=self.owner,
            role_slug=RoleSlugs.EMPLOYEE
        )
        self.assertEqual(inv2.email, "existing@example.com")
        self.assertEqual(inv2.status, InvitationStatus.PENDING)

    def test_invite_member_allowed_if_previous_invitation_rejected(self):
        inv1 = InvitationService.invite_member(
            organization_id=self.org.id,
            email="existing@example.com",
            invited_by=self.owner,
            role_slug=RoleSlugs.EMPLOYEE
        )
        InvitationService.reject_invitation(token=inv1.token)
        inv2 = InvitationService.invite_member(
            organization_id=self.org.id,
            email="existing@example.com",
            invited_by=self.owner,
            role_slug=RoleSlugs.EMPLOYEE
        )
        self.assertEqual(inv2.status, InvitationStatus.PENDING)

    def test_invite_member_allowed_if_previous_invitation_expired(self):
        inv1 = InvitationService.invite_member(
            organization_id=self.org.id,
            email="existing@example.com",
            invited_by=self.owner,
            role_slug=RoleSlugs.EMPLOYEE
        )
        # Force expiration
        inv1.expires_at = timezone.now() - timezone.timedelta(hours=1)
        inv1.save()

        inv2 = InvitationService.invite_member(
            organization_id=self.org.id,
            email="existing@example.com",
            invited_by=self.owner,
            role_slug=RoleSlugs.EMPLOYEE
        )
        self.assertEqual(inv2.status, InvitationStatus.PENDING)

    def test_invite_member_blocked_if_previous_invitation_pending(self):
        inv1 = InvitationService.invite_member(
            organization_id=self.org.id,
            email="existing@example.com",
            invited_by=self.owner,
            role_slug=RoleSlugs.EMPLOYEE
        )
        with self.assertRaises(MembershipAlreadyExistsException):
            InvitationService.invite_member(
                organization_id=self.org.id,
                email="existing@example.com",
                invited_by=self.owner,
                role_slug=RoleSlugs.EMPLOYEE
            )

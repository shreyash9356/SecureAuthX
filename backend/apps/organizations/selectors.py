import logging
import uuid
from typing import Optional
from django.db.models import QuerySet
from django.utils import timezone

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
from apps.organizations.exceptions import (
    OrganizationNotFoundException,
    MembershipNotFoundException,
    InvitationNotFoundException,
)

logger = logging.getLogger(__name__)


class OrganizationSelector:
    """
    Read-only database search and retrieval operations for the Organization model.
    """

    @classmethod
    def get_organization_by_id(cls, organization_id: uuid.UUID | str, include_deleted: bool = False) -> Organization:
        """
        Retrieves an Organization by its unique UUID.
        
        Args:
            organization_id: Unique UUID or string representing the organization.
            include_deleted: If True, returns the organization even if status is DELETED.
            
        Returns:
            The Organization model instance.
            
        Raises:
            OrganizationNotFoundException: If the organization does not exist or is soft-deleted.
        """
        try:
            org = Organization.objects.get(id=organization_id)
            if not include_deleted and org.status == OrganizationStatus.DELETED:
                raise OrganizationNotFoundException(f"Organization with ID '{organization_id}' not found.")
            return org
        except Organization.DoesNotExist:
            raise OrganizationNotFoundException(f"Organization with ID '{organization_id}' not found.")

    @classmethod
    def get_organization_by_slug(cls, slug: str, include_deleted: bool = False) -> Organization:
        """
        Retrieves an Organization by its unique slug.
        
        Args:
            slug: Unique URL-friendly slug representing the organization.
            include_deleted: If True, returns the organization even if status is DELETED.
            
        Returns:
            The Organization model instance.
            
        Raises:
            OrganizationNotFoundException: If the organization does not exist or is soft-deleted.
        """
        try:
            org = Organization.objects.get(slug=slug)
            if not include_deleted and org.status == OrganizationStatus.DELETED:
                raise OrganizationNotFoundException(f"Organization with slug '{slug}' not found.")
            return org
        except Organization.DoesNotExist:
            raise OrganizationNotFoundException(f"Organization with slug '{slug}' not found.")

    @classmethod
    def list_active_organizations(cls) -> QuerySet[Organization]:
        """
        Lists all organizations in the system that are currently ACTIVE.
        """
        return Organization.objects.filter(status=OrganizationStatus.ACTIVE)

    @classmethod
    def list_all_organizations(cls, include_deleted: bool = False) -> QuerySet[Organization]:
        """
        Lists all organizations in the system, regardless of status (excluding deleted by default).
        """
        queryset = Organization.objects.all()
        if not include_deleted:
            queryset = queryset.exclude(status=OrganizationStatus.DELETED)
        return queryset


class MembershipSelector:
    """
    Read-only query operations for OrganizationMembership mappings.
    """

    @classmethod
    def get_membership_by_id(
        cls,
        membership_id: uuid.UUID | str,
        include_removed: bool = False
    ) -> OrganizationMembership:
        """
        Retrieves an OrganizationMembership record by its UUID.
        
        Args:
            membership_id: Unique UUID of the membership.
            include_removed: If True, returns the membership even if status is REMOVED.
            
        Returns:
            The OrganizationMembership instance.
            
        Raises:
            MembershipNotFoundException: If the membership does not exist, organization is soft-deleted,
                                         or membership is soft-removed (when include_removed is False).
        """
        try:
            membership = OrganizationMembership.objects.select_related("organization", "user", "role").get(id=membership_id)
            if membership.organization.status == OrganizationStatus.DELETED:
                raise MembershipNotFoundException(f"Membership with ID '{membership_id}' not found.")
            if not include_removed and membership.status == MembershipStatus.REMOVED:
                raise MembershipNotFoundException(f"Membership with ID '{membership_id}' not found.")
            return membership
        except OrganizationMembership.DoesNotExist:
            raise MembershipNotFoundException(f"Membership with ID '{membership_id}' not found.")

    @classmethod
    def get_user_membership(
        cls,
        *,
        organization_id: uuid.UUID | str,
        user_id: uuid.UUID | str,
        include_removed: bool = True
    ) -> Optional[OrganizationMembership]:
        """
        Retrieves a user's membership within a specific organization, returning None if missing.
        
        Optimized with select_related for related mapping resolution.
        """
        queryset = OrganizationMembership.objects.select_related("organization", "user", "role").filter(
            organization_id=organization_id,
            user_id=user_id
        )
        if not include_removed:
            queryset = queryset.exclude(status=MembershipStatus.REMOVED)
        return queryset.first()

    @classmethod
    def list_organization_memberships(
        cls,
        organization_id: uuid.UUID | str,
        *,
        status: Optional[str] = None,
        include_removed: bool = False
    ) -> QuerySet[OrganizationMembership]:
        """
        Lists all memberships in an organization, with optional status filtering.
        """
        queryset = OrganizationMembership.objects.select_related("user", "role").filter(
            organization_id=organization_id
        )
        if not include_removed:
            queryset = queryset.exclude(status=MembershipStatus.REMOVED)
        if status is not None:
            queryset = queryset.filter(status=status)
        return queryset


class InvitationSelector:
    """
    Read-only query operations for OrganizationInvitation tracking.
    """

    @classmethod
    def get_invitation_by_id(cls, invitation_id: uuid.UUID | str) -> OrganizationInvitation:
        """
        Retrieves an OrganizationInvitation record by its UUID.
        
        Args:
            invitation_id: Unique UUID of the invitation.
            
        Returns:
            The OrganizationInvitation instance.
            
        Raises:
            InvitationNotFoundException: If the invitation does not exist or organization is soft-deleted.
        """
        try:
            invitation = OrganizationInvitation.objects.select_related("organization", "invited_by").get(id=invitation_id)
            if invitation.organization.status == OrganizationStatus.DELETED:
                raise InvitationNotFoundException(f"Invitation with ID '{invitation_id}' was not found.")
            return invitation
        except OrganizationInvitation.DoesNotExist:
            raise InvitationNotFoundException(f"Invitation with ID '{invitation_id}' was not found.")

    @classmethod
    def get_invitation_by_token(cls, token: uuid.UUID | str) -> OrganizationInvitation:
        """
        Retrieves an OrganizationInvitation record by its unique secure token.
        
        Args:
            token: Secure UUID token.
            
        Returns:
            The OrganizationInvitation instance.
            
        Raises:
            InvitationNotFoundException: If the token is invalid or organization is soft-deleted.
        """
        try:
            invitation = OrganizationInvitation.objects.select_related("organization", "invited_by").get(token=token)
            if invitation.organization.status == OrganizationStatus.DELETED:
                raise InvitationNotFoundException("Invitation with this token was not found.")
            return invitation
        except OrganizationInvitation.DoesNotExist:
            raise InvitationNotFoundException("Invitation with this token was not found.")

    @classmethod
    def list_pending_invitations(cls, organization_id: uuid.UUID | str) -> QuerySet[OrganizationInvitation]:
        """
        Lists all PENDING status invitations issued for a specific organization.
        """
        return OrganizationInvitation.objects.filter(
            organization_id=organization_id,
            status=InvitationStatus.PENDING
        )

    @classmethod
    def has_active_pending_invitation(
        cls,
        *,
        organization_id: uuid.UUID | str,
        email: str
    ) -> bool:
        """
        Checks if there is an active pending invitation for a given email in the organization.
        
        An invitation is active pending if its status is PENDING and it has not expired yet.
        """
        return cls.list_pending_invitations(organization_id).filter(
            email__iexact=email,
            expires_at__gt=timezone.now()
        ).exists()


class SettingsSelector:
    """
    Read-only query operations for OrganizationSettings mappings.
    """

    @classmethod
    def get_settings_by_organization_id(cls, organization_id: uuid.UUID | str) -> OrganizationSettings:
        """
        Retrieves OrganizationSettings mapping for a specific organization.
        
        Args:
            organization_id: Unique UUID or string representing the organization.
            
        Returns:
            The associated OrganizationSettings model instance.
            
        Raises:
            OrganizationNotFoundException: If the settings record is missing or organization is soft-deleted.
        """
        try:
            settings = OrganizationSettings.objects.select_related("organization").get(organization_id=organization_id)
            if settings.organization.status == OrganizationStatus.DELETED:
                raise OrganizationNotFoundException(f"Settings for organization '{organization_id}' not found.")
            return settings
        except OrganizationSettings.DoesNotExist:
            raise OrganizationNotFoundException(f"Settings for organization '{organization_id}' not found.")

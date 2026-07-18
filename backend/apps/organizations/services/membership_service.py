import logging
import uuid
from typing import Any
from django.db import transaction
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db.models import QuerySet

from apps.authorization.models import Role
from apps.authorization.constants import RoleSlugs
from apps.authorization.exceptions import RoleNotFoundException
from apps.organizations.models import Organization, OrganizationMembership
from apps.organizations.constants import MembershipStatus
from apps.organizations.exceptions import (
    OrganizationNotFoundException,
    MembershipNotFoundException,
    MembershipAlreadyExistsException,
    InvalidMembershipException,
)
from apps.organizations.selectors import OrganizationSelector, MembershipSelector

logger = logging.getLogger(__name__)


class MembershipService:
    """
    Enterprise Tenant Membership Lifecycle Service.
    
    Manages active memberships, assigns and validates workspace roles, coordinates
    suspension or reactivation flows, and prevents multiple simultaneous memberships
    for a single identity.
    """

    @classmethod
    def get_members(cls, organization_id: uuid.UUID | str) -> QuerySet[OrganizationMembership]:
        """
        Retrieves all membership records associated with the organization, including inactive ones.
        
        Args:
            organization_id: Unique UUID or string identifier of the target organization.
            
        Returns:
            A Django QuerySet of OrganizationMembership records.
        """
        # Retrieve roster via Selector layer to maintain read boundaries
        return MembershipSelector.list_organization_memberships(organization_id)

    @classmethod
    def add_member(
        cls,
        *,
        organization_id: uuid.UUID | str,
        user_id: uuid.UUID | str,
        role_slug: str,
        status: str = MembershipStatus.ACTIVE
    ) -> OrganizationMembership:
        """
        Explicitly inserts/updates a user membership, bypassing the invitation flow.
        
        Can reactivate previously removed/suspended memberships or map a new user identity.
        
        Args:
            organization_id: UUID of the target organization.
            user_id: UUID of the User identity to add.
            role_slug: Slug of the role to assign.
            status: Initial status of the membership (default ACTIVE).
            
        Returns:
            The created or updated OrganizationMembership instance.
            
        Raises:
            OrganizationNotFoundException: If the organization does not exist.
            MembershipAlreadyExistsException: If the user is already an active member.
            RoleNotFoundException: If the requested role slug is invalid.
            ValidationError: If database or model-level validations fail.
        """
        # Lookup organization via Selector layer
        org = OrganizationSelector.get_organization_by_id(organization_id)

        user_model = get_user_model()
        try:
            user = user_model.objects.get(id=user_id)
        except user_model.DoesNotExist:
            raise ValidationError({"user_id": f"User with ID '{user_id}' not found."})

        try:
            role_obj = Role.objects.get(slug=role_slug)
        except Role.DoesNotExist:
            raise RoleNotFoundException(f"Role with slug '{role_slug}' not found.")

        # Guard: Check for duplicate membership using selector lookup
        existing = MembershipSelector.get_user_membership(organization_id=org.id, user_id=user.id)
        if existing:
            if existing.status in [MembershipStatus.ACTIVE, MembershipStatus.PENDING]:
                raise MembershipAlreadyExistsException(
                    f"User '{user.id}' is already a member with status '{existing.status}'."
                )

            # Reactivate previously removed or suspended memberships cleanly
            try:
                with transaction.atomic():
                    existing.status = status
                    existing.role = role_obj
                    if status == MembershipStatus.ACTIVE and not existing.joined_at:
                        existing.joined_at = timezone.now()
                    existing.full_clean()
                    existing.save()
                    
                    # Sanitize Logs: Use UUIDs and Slugs instead of user email
                    logger.info("Reactivated membership for user_id: %s in organization: %s with role: %s", user.id, org.slug, role_slug)
                    return existing
            except ValidationError as e:
                raise ValidationError(e.message_dict)

        try:
            with transaction.atomic():
                membership = OrganizationMembership(
                    organization=org,
                    user=user,
                    role=role_obj,
                    status=status,
                    joined_at=timezone.now() if status == MembershipStatus.ACTIVE else None
                )
                membership.full_clean()
                membership.save()
                
                # Sanitize Logs: Use UUIDs and Slugs instead of user email
                logger.info("Successfully added user_id: %s directly to organization: %s with role: %s", user.id, org.slug, role_slug)
                return membership
                
        except ValidationError as e:
            logger.error("Validation failed adding member directly to organization %s: %s", organization_id, e.message_dict)
            raise ValidationError(e.message_dict)

    @classmethod
    def update_membership_role(
        cls,
        *,
        membership_id: uuid.UUID | str,
        role_slug: str,
        actor: Any
    ) -> OrganizationMembership:
        """
        Updates the role mapped to a specific membership.
        
        Prevents demoting the primary tenant owner below the Administrator role.
        
        Args:
            membership_id: UUID of the membership record.
            role_slug: The target role slug to map.
            actor: The User executing the update (used for logging).
            
        Returns:
            The updated OrganizationMembership instance.
            
        Raises:
            MembershipNotFoundException: If the membership does not exist.
            RoleNotFoundException: If the target role slug is invalid.
            InvalidMembershipException: If the update attempts to demote the owner.
            ValidationError: If model validations fail.
        """
        # Retrieve membership record via Selector layer
        membership = MembershipSelector.get_membership_by_id(membership_id)

        try:
            role_obj = Role.objects.get(slug=role_slug)
        except Role.DoesNotExist:
            raise RoleNotFoundException(f"Role with slug '{role_slug}' not found.")

        org = membership.organization

        # Guard: The primary owner of the organization must always retain the Administrator role.
        if org.owner == membership.user and role_slug != RoleSlugs.ADMIN:
            raise InvalidMembershipException("The organization owner must retain the Administrator role. Transfer ownership first.")

        try:
            with transaction.atomic():
                membership.role = role_obj
                membership.full_clean()
                membership.save()
                
                # Sanitize Logs: Use UUIDs and Slugs instead of user email
                logger.info("Updated role of member_id: %s to role: %s in organization: %s by actor_id: %s", membership.user_id, role_slug, org.slug, actor.id)
                return membership
        except ValidationError as e:
            logger.error("Validation failed updating role of membership %s: %s", membership_id, e.message_dict)
            raise ValidationError(e.message_dict)

    @classmethod
    def update_membership_status(
        cls,
        *,
        membership_id: uuid.UUID | str,
        status: str,
        actor: Any
    ) -> OrganizationMembership:
        """
        Suspends, activates, or modifies the status of a user membership.
        
        Prevents deactivation or suspension of the organization's current owner.
        
        Args:
            membership_id: UUID of the membership record.
            status: Target MembershipStatus value.
            actor: The User executing the update (used for logging).
            
        Returns:
            The updated OrganizationMembership instance.
            
        Raises:
            MembershipNotFoundException: If the membership does not exist.
            InvalidMembershipException: If the update attempts to suspend/remove the owner.
            ValidationError: If status is invalid or model validations fail.
        """
        if status not in MembershipStatus.values:
            raise ValidationError({"status": f"Invalid membership status choice: {status}"})

        # Retrieve membership record via Selector layer
        membership = MembershipSelector.get_membership_by_id(membership_id)

        org = membership.organization

        # Guard: Deactivating the primary owner would leave the organization orphan / unmanageable.
        if org.owner == membership.user and status in [MembershipStatus.SUSPENDED, MembershipStatus.REMOVED]:
            raise InvalidMembershipException("The organization owner's membership cannot be suspended or removed. Transfer ownership first.")

        try:
            with transaction.atomic():
                membership.status = status
                membership.full_clean()
                membership.save()
                
                # Sanitize Logs: Use UUIDs instead of user email
                logger.info("Updated status of membership_id: %s to status: %s by actor_id: %s", membership_id, status, actor.id)
                return membership
        except ValidationError as e:
            logger.error("Validation failed updating status of membership %s: %s", membership_id, e.message_dict)
            raise ValidationError(e.message_dict)

    @classmethod
    def remove_member(cls, *, membership_id: uuid.UUID | str, actor: Any) -> None:
        """
        Revokes a user's membership in an organization (soft-delete).
        
        Args:
            membership_id: UUID of the membership record.
            actor: The User executing the removal.
        """
        cls.update_membership_status(
            membership_id=membership_id,
            status=MembershipStatus.REMOVED,
            actor=actor
        )

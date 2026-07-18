import logging
import uuid
from typing import Any
from django.db import transaction
from django.core.exceptions import ValidationError

from apps.authorization.models import Role
from apps.authorization.constants import RoleSlugs
from apps.authorization.exceptions import RoleNotFoundException
from apps.organizations.models import Organization
from apps.organizations.constants import MembershipStatus
from apps.organizations.exceptions import (
    OrganizationNotFoundException,
    OwnershipTransferException,
)
from apps.organizations.selectors import OrganizationSelector, MembershipSelector

logger = logging.getLogger(__name__)


class OwnershipService:
    """
    Enterprise Tenant Ownership Management Service.
    
    Coordinates the secure transfer of primary tenant ownership between administrators and
    members. Validates role-precedence constraints, enforces membership state checks, and
    performs atomic transactions to protect organizations from becoming ownerless.
    """

    @classmethod
    def transfer_ownership(
        cls,
        *,
        organization_id: uuid.UUID | str,
        current_owner: Any,
        new_owner: Any
    ) -> Organization:
        """
        Transfers organization ownership from the current owner to a new owner.
        
        This method operates within an atomic transaction. It transitions the Organization
        owner attribute, elevates the new owner to the Administrator role within the
        organization's membership list, and preserves the old owner's membership as an
        Administrator.
        
        Args:
            organization_id: Unique UUID or string identifier of the organization.
            current_owner: The User model instance who currently owns the organization.
            new_owner: The prospective User model instance taking ownership.
            
        Returns:
            The updated Organization model instance.
            
        Raises:
            OrganizationNotFoundException: If the organization does not exist.
            OwnershipTransferException: If current_owner is invalid, current/new match,
                                        or new_owner is not an active member.
            RoleNotFoundException: If the core Administrator role is missing.
            ValidationError: If model constraints fail during clean processes.
        """
        # Resolving via selector to centralize ORM read logic
        org = OrganizationSelector.get_organization_by_id(organization_id)

        # Guard: Enforce owner identity matches requesting current owner
        if org.owner != current_owner:
            raise OwnershipTransferException("The requesting user is not the current owner of this organization.")

        # Guard: Prevent redundant transfer calls to the same user
        if current_owner == new_owner:
            raise OwnershipTransferException("Cannot transfer ownership to the same user.")

        # Guard: Validate that the incoming owner is a verified, active tenant member
        new_owner_membership = MembershipSelector.get_user_membership(
            organization_id=org.id,
            user_id=new_owner.id
        )

        if not new_owner_membership or new_owner_membership.status != MembershipStatus.ACTIVE:
            raise OwnershipTransferException("The prospective owner must be an active member of the organization.")

        try:
            admin_role = Role.objects.get(slug=RoleSlugs.ADMIN)
        except Role.DoesNotExist:
            raise RoleNotFoundException(f"Core Admin role '{RoleSlugs.ADMIN}' must be seeded first.")

        try:
            with transaction.atomic():
                # Reassign tenant owner ForeignKey
                org.owner = new_owner
                org.full_clean()
                org.save()

                # Elevate new owner to Administrator status within the membership roster
                new_owner_membership.role = admin_role
                new_owner_membership.full_clean()
                new_owner_membership.save()

                # Guarantee outgoing owner retains an active Administrator membership role to prevent Lockout.
                old_owner_membership = MembershipSelector.get_user_membership(
                    organization_id=org.id,
                    user_id=current_owner.id
                )
                
                if old_owner_membership:
                    old_owner_membership.role = admin_role
                    old_owner_membership.status = MembershipStatus.ACTIVE
                    old_owner_membership.full_clean()
                    old_owner_membership.save()

                # Masked PII: Log only UUIDs instead of plaintext emails to comply with privacy frameworks
                logger.info(
                    "Successfully transferred ownership of organization %s (ID: %s) from owner_id: %s to owner_id: %s.",
                    org.slug,
                    org.id,
                    current_owner.id,
                    new_owner.id,
                )
                return org

        except ValidationError as e:
            logger.error("Validation failed during ownership transfer for organization %s: %s", organization_id, e.message_dict)
            raise ValidationError(e.message_dict)

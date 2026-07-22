import logging
import uuid
from typing import Any
from django.db import transaction
from django.core.exceptions import ValidationError

from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService
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
        """
        org = OrganizationSelector.get_organization_by_id(organization_id)

        if org.owner != current_owner:
            raise OwnershipTransferException("The requesting user is not the current owner of this organization.")

        if current_owner == new_owner:
            raise OwnershipTransferException("Cannot transfer ownership to the same user.")

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
                org.owner = new_owner
                org.full_clean()
                org.save()

                new_owner_membership.role = admin_role
                new_owner_membership.full_clean()
                new_owner_membership.save()

                old_owner_membership = MembershipSelector.get_user_membership(
                    organization_id=org.id,
                    user_id=current_owner.id
                )
                
                if old_owner_membership:
                    old_owner_membership.role = admin_role
                    old_owner_membership.status = MembershipStatus.ACTIVE
                    old_owner_membership.full_clean()
                    old_owner_membership.save()

                AuditLogService.log(
                    event_type=AuditLog.EventType.ORGANIZATION_OWNERSHIP_TRANSFERRED,
                    status=AuditLog.Status.SUCCESS,
                    description=f"Ownership of organization {org.slug} transferred to {new_owner.email}.",
                    user=current_owner,
                    resource="Organization",
                    resource_id=str(org.id),
                    metadata={"previous_owner_id": str(current_owner.id), "new_owner_id": str(new_owner.id)},
                )

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

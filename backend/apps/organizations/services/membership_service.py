import logging
import uuid
from typing import Any
from django.db import transaction
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db.models import QuerySet

from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService
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
        """
        return MembershipSelector.list_organization_memberships(organization_id)

    @classmethod
    def add_member(
        cls,
        *,
        organization_id: uuid.UUID | str,
        user_id: uuid.UUID | str,
        role_slug: str,
        status: str = MembershipStatus.ACTIVE,
        actor: Any = None,
    ) -> OrganizationMembership:
        """
        Explicitly inserts/updates a user membership, bypassing the invitation flow.
        """
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

        existing = MembershipSelector.get_user_membership(organization_id=org.id, user_id=user.id)
        if existing:
            if existing.status in [MembershipStatus.ACTIVE, MembershipStatus.PENDING]:
                raise MembershipAlreadyExistsException(
                    f"User '{user.id}' is already a member with status '{existing.status}'."
                )

            try:
                with transaction.atomic():
                    existing.status = status
                    existing.role = role_obj
                    if status == MembershipStatus.ACTIVE and not existing.joined_at:
                        existing.joined_at = timezone.now()
                    existing.full_clean()
                    existing.save()

                    AuditLogService.log(
                        event_type=AuditLog.EventType.ORGANIZATION_MEMBER_ADDED,
                        status=AuditLog.Status.SUCCESS,
                        description=f"Member {user.email} reactivated in organization {org.slug}.",
                        user=actor or user,
                        resource="OrganizationMembership",
                        resource_id=str(existing.id),
                        metadata={"organization_id": str(org.id), "user_id": str(user.id), "role": role_slug},
                    )

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

                AuditLogService.log(
                    event_type=AuditLog.EventType.ORGANIZATION_MEMBER_ADDED,
                    status=AuditLog.Status.SUCCESS,
                    description=f"Member {user.email} added to organization {org.slug}.",
                    user=actor or user,
                    resource="OrganizationMembership",
                    resource_id=str(membership.id),
                    metadata={"organization_id": str(org.id), "user_id": str(user.id), "role": role_slug},
                )

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
        """
        membership = MembershipSelector.get_membership_by_id(membership_id)

        try:
            role_obj = Role.objects.get(slug=role_slug)
        except Role.DoesNotExist:
            raise RoleNotFoundException(f"Role with slug '{role_slug}' not found.")

        org = membership.organization

        if org.owner == membership.user and role_slug != RoleSlugs.ADMIN:
            raise InvalidMembershipException("The organization owner must retain the Administrator role. Transfer ownership first.")

        try:
            with transaction.atomic():
                membership.role = role_obj
                membership.full_clean()
                membership.save()

                AuditLogService.log(
                    event_type=AuditLog.EventType.ORGANIZATION_MEMBER_UPDATED,
                    status=AuditLog.Status.SUCCESS,
                    description=f"Membership role updated to {role_slug} for user {membership.user.email}.",
                    user=actor,
                    resource="OrganizationMembership",
                    resource_id=str(membership.id),
                    metadata={"organization_id": str(org.id), "user_id": str(membership.user_id), "new_role": role_slug},
                )

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
        """
        if status not in MembershipStatus.values:
            raise ValidationError({"status": f"Invalid membership status choice: {status}"})

        membership = MembershipSelector.get_membership_by_id(membership_id)

        org = membership.organization

        if org.owner == membership.user and status in [MembershipStatus.SUSPENDED, MembershipStatus.REMOVED]:
            raise InvalidMembershipException("The organization owner's membership cannot be suspended or removed. Transfer ownership first.")

        try:
            with transaction.atomic():
                membership.status = status
                membership.full_clean()
                membership.save()

                event_type = (
                    AuditLog.EventType.ORGANIZATION_MEMBER_REMOVED
                    if status == MembershipStatus.REMOVED
                    else AuditLog.EventType.ORGANIZATION_MEMBER_UPDATED
                )

                AuditLogService.log(
                    event_type=event_type,
                    status=AuditLog.Status.SUCCESS,
                    description=f"Membership status updated to {status} for user {membership.user.email}.",
                    user=actor,
                    resource="OrganizationMembership",
                    resource_id=str(membership.id),
                    metadata={"organization_id": str(org.id), "user_id": str(membership.user_id), "new_status": status},
                )

                logger.info("Updated status of membership_id: %s to status: %s by actor_id: %s", membership_id, status, actor.id)
                return membership
        except ValidationError as e:
            logger.error("Validation failed updating status of membership %s: %s", membership_id, e.message_dict)
            raise ValidationError(e.message_dict)

    @classmethod
    def remove_member(cls, *, membership_id: uuid.UUID | str, actor: Any) -> None:
        """
        Revokes a user's membership in an organization (soft-delete).
        """
        cls.update_membership_status(
            membership_id=membership_id,
            status=MembershipStatus.REMOVED,
            actor=actor
        )

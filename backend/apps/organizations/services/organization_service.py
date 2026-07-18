import logging
import uuid
from typing import Any, Dict, Optional
from django.db import transaction, IntegrityError
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.text import slugify

from apps.authorization.models import Role
from apps.authorization.constants import RoleSlugs
from apps.authorization.exceptions import RoleNotFoundException
from apps.organizations.models import (
    Organization,
    OrganizationMembership,
    OrganizationSettings,
)
from apps.organizations.constants import (
    OrganizationStatus,
    MembershipStatus,
    DEFAULT_TIMEZONE,
    DEFAULT_SESSION_TIMEOUT_MINUTES,
)
from apps.organizations.exceptions import (
    OrganizationNotFoundException,
    OrganizationAlreadyExistsException,
)
from apps.organizations.selectors import OrganizationSelector

logger = logging.getLogger(__name__)


class OrganizationService:
    """
    Enterprise Organization Tenant Lifecycle Service.
    
    Orchestrates tenant registration, metadata adjustments, and soft deletion.
    Enforces name uniqueness and manages default configuration bootstrapping alongside owner mappings.
    """

    @classmethod
    def get_organization(cls, organization_id: uuid.UUID | str) -> Organization:
        """
        Retrieves a specific organization record by its UUID.
        
        Args:
            organization_id: Unique UUID or string identifier of the organization.
            
        Returns:
            The retrieved Organization instance.
            
        Raises:
            OrganizationNotFoundException: If the organization does not exist.
        """
        # Delegated lookup to selector layer
        return OrganizationSelector.get_organization_by_id(organization_id)

    @classmethod
    def create_organization(
        cls,
        *,
        name: str,
        owner: Any,
        slug: Optional[str] = None,
        description: str = "",
        settings_data: Optional[Dict[str, Any]] = None
    ) -> Organization:
        """
        Registers a new organization tenant, bootstraps settings, and maps the owner membership.
        
        Performs case-insensitive validation against duplicate organization names, resolves/creates
        a unique slug identifier, and runs all operations inside a transactional block.
        
        Args:
            name: Human-readable organization name.
            owner: User model instance establishing the tenant.
            slug: Optional predefined slug. If omitted, one is generated from the name.
            description: Optional details summary.
            settings_data: Settings parameters (e.g. timezone) to override defaults.
            
        Returns:
            The created Organization model instance.
            
        Raises:
            OrganizationAlreadyExistsException: If the name or slug is in use.
            RoleNotFoundException: If the Administrator role does not exist in the database.
            ValidationError: If model constraints fail.
        """
        # Guard: Validate duplicate names case-insensitively
        if Organization.objects.filter(name__iexact=name).exists():
            raise OrganizationAlreadyExistsException(f"Organization with name '{name}' already exists.")

        # Slug Resolution: Use provided slug or automatically generate a unique variant
        if slug:
            slug = slugify(slug)
            if Organization.objects.filter(slug=slug).exists():
                raise OrganizationAlreadyExistsException(f"Organization with slug '{slug}' already exists.")
        else:
            base_slug = slugify(name)
            slug = base_slug
            counter = 1
            while Organization.objects.filter(slug=slug).exists():
                slug = f"{base_slug}-{counter}"
                counter += 1

        try:
            admin_role = Role.objects.get(slug=RoleSlugs.ADMIN)
        except Role.DoesNotExist:
            logger.error("Seeded role '%s' not found in database.", RoleSlugs.ADMIN)
            raise RoleNotFoundException(f"Core Admin role '{RoleSlugs.ADMIN}' must be seeded first.")

        try:
            with transaction.atomic():
                org = Organization(
                    name=name,
                    slug=slug,
                    description=description,
                    owner=owner,
                    status=OrganizationStatus.ACTIVE
                )
                org.full_clean()
                org.save()

                settings_payload = settings_data or {}
                # Bootstrapping settings using centralized defaults
                org_settings = OrganizationSettings(
                    organization=org,
                    timezone=settings_payload.get("timezone", DEFAULT_TIMEZONE),
                    country=settings_payload.get("country", ""),
                    branding_name=settings_payload.get("branding_name", name),
                    logo=settings_payload.get("logo", ""),
                    session_timeout_minutes=settings_payload.get("session_timeout_minutes", DEFAULT_SESSION_TIMEOUT_MINUTES)
                )
                org_settings.full_clean()
                org_settings.save()

                # Register the owner as an active member with the administrator role
                membership = OrganizationMembership(
                    organization=org,
                    user=owner,
                    role=admin_role,
                    status=MembershipStatus.ACTIVE,
                    invited_by=None,
                    joined_at=timezone.now()
                )
                membership.full_clean()
                membership.save()

                # Sanitize Logs: Use UUID instead of user email
                logger.info("Successfully created Organization: %s (Slug: %s, Owner_id: %s)", org.name, org.slug, owner.id)
                return org

        except ValidationError as e:
            logger.error("Validation failed during organization creation: %s", e.message_dict)
            raise ValidationError(e.message_dict)
        except IntegrityError as e:
            logger.error("Integrity conflict during organization creation: %s", str(e))
            raise OrganizationAlreadyExistsException(f"Database conflict occurred: {e}")

    @classmethod
    def update_organization(
        cls,
        organization_id: uuid.UUID | str,
        *,
        name: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None
    ) -> Organization:
        """
        Updates organization parameters and status.
        
        Args:
            organization_id: UUID of the organization.
            name: New display name.
            description: New description summary.
            status: New lifecycle status choice.
            
        Returns:
            The updated Organization model instance.
            
        Raises:
            OrganizationNotFoundException: If the organization does not exist.
            ValidationError: If model validations or choices fail.
        """
        # Lookup organization via Selector layer
        org = OrganizationSelector.get_organization_by_id(organization_id)

        try:
            with transaction.atomic():
                if name is not None:
                    # Enforce case-insensitive validation for names during rename
                    name_stripped = name.strip()
                    if Organization.objects.exclude(id=org.id).filter(name__iexact=name_stripped).exists():
                        raise OrganizationAlreadyExistsException(f"Organization with name '{name_stripped}' already exists.")
                    org.name = name_stripped
                if description is not None:
                    org.description = description.strip()
                if status is not None:
                    if status not in OrganizationStatus.values:
                        raise ValidationError({"status": f"Invalid status choice: {status}"})
                    org.status = status

                org.full_clean()
                org.save()
                logger.info("Successfully updated Organization: %s (ID: %s)", org.name, org.id)
                return org
        except ValidationError as e:
            logger.error("Validation failed during organization update: %s", e.message_dict)
            raise ValidationError(e.message_dict)

    @classmethod
    def delete_organization(cls, organization_id: uuid.UUID | str) -> None:
        """
        Soft-deletes the organization tenant and its member roster.
        
        Args:
            organization_id: UUID of the organization to delete.
            
        Raises:
            OrganizationNotFoundException: If the organization does not exist.
        """
        # Lookup organization via Selector layer
        org = OrganizationSelector.get_organization_by_id(organization_id)

        try:
            with transaction.atomic():
                org.status = OrganizationStatus.DELETED
                org.save()

                # Revoke membership access for all members
                org.memberships.filter(status=MembershipStatus.ACTIVE).update(
                    status=MembershipStatus.REMOVED,
                    updated_at=timezone.now()
                )
                logger.info("Successfully soft-deleted Organization: %s.", org.id)
        except Exception as e:
            logger.error("Failed to soft-delete organization %s: %s", organization_id, str(e))
            raise

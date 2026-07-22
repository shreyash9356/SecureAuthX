import logging
from django.db import transaction, IntegrityError
from django.core.exceptions import ValidationError
from django.db.models import QuerySet

from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService
from apps.authorization.models import Role, Permission, RolePermission
from apps.authorization.exceptions import (
    RoleNotFoundException,
    RoleAlreadyExistsException,
    SystemRoleModificationException,
    PermissionAssignmentException,
    PermissionNotFoundException,
    InvalidRoleException,
)

logger = logging.getLogger(__name__)


class RoleService:
    """
    Enterprise Role Lifecycle and Permission Assignment Service.
    
    Orchestrates job-role management, capability mapping, soft-deletion,
    and access governance checks. Enforces role immutability and data constraints.
    """

    # --------------------------------------------------------------------------
    # Role Lifecycle Methods
    # --------------------------------------------------------------------------

    @classmethod
    def create_role(
        cls,
        *,
        name: str,
        slug: str,
        description: str = "",
        priority: int = 0,
        is_system: bool = False,
        actor=None
    ) -> Role:
        """
        Creates and registers a new Role in the authorization system.
        """
        if Role.objects.filter(name=name).exists():
            raise RoleAlreadyExistsException(f"Role with name '{name}' already exists.")
            
        if Role.objects.filter(slug=slug).exists():
            raise RoleAlreadyExistsException(f"Role with slug '{slug}' already exists.")

        try:
            with transaction.atomic():
                role = Role(
                    name=name,
                    slug=slug,
                    description=description,
                    priority=priority,
                    is_system=is_system,
                    is_active=True
                )
                role.full_clean()
                role.save()

                logger.info("Successfully created Role: %s (Slug: %s)", name, slug)

                AuditLogService.log(
                    event_type=AuditLog.EventType.ROLE_CREATED,
                    status=AuditLog.Status.SUCCESS,
                    description=f"Role {name} ({slug}) created.",
                    user=actor,
                    resource="Role",
                    resource_id=str(role.id),
                    metadata={"slug": role.slug, "is_system": is_system, "priority": priority},
                )

                return role
                
        except ValidationError as e:
            logger.error("Validation failed during role creation for %s: %s", slug, e.message_dict)
            raise InvalidRoleException(f"Invalid role attributes: {e.message_dict}")
        except IntegrityError as e:
            logger.error("Database conflict during role creation for %s: %s", slug, str(e))
            raise RoleAlreadyExistsException(f"Database conflict occurred: {e}")

    @classmethod
    def update_role(
        cls,
        role_id: str,
        *,
        name: str = None,
        description: str = None,
        priority: int = None,
        actor=None,
        **kwargs
    ) -> Role:
        """
        Updates fields of an existing Role.
        """
        try:
            role = Role.objects.get(id=role_id)
        except Role.DoesNotExist:
            raise RoleNotFoundException(f"Role with ID '{role_id}' not found.")

        if role.is_system:
            if name is not None and name.strip() != role.name:
                raise SystemRoleModificationException(
                    f"System role '{role.slug}' cannot be renamed."
                )

        immutable_fields = ["slug", "is_system"]
        for field in immutable_fields:
            if field in kwargs:
                raise SystemRoleModificationException(
                    f"Field '{field}' is immutable and cannot be modified."
                )

        try:
            with transaction.atomic():
                if name is not None:
                    role.name = name.strip()
                if description is not None:
                    role.description = description.strip()
                if priority is not None:
                    role.priority = priority

                role.full_clean()
                role.save()

                logger.info("Successfully updated Role: %s", role.slug)

                AuditLogService.log(
                    event_type=AuditLog.EventType.ROLE_UPDATED,
                    status=AuditLog.Status.SUCCESS,
                    description=f"Role {role.slug} updated.",
                    user=actor,
                    resource="Role",
                    resource_id=str(role.id),
                    metadata={"slug": role.slug},
                )

                return role
                
        except ValidationError as e:
            logger.error("Validation failed during role update for ID %s: %s", role_id, e.message_dict)
            raise InvalidRoleException(f"Invalid role updates: {e.message_dict}")

    @classmethod
    def activate_role(cls, role_id: str, actor=None) -> Role:
        """
        Activates a deactivated Role.
        """
        try:
            role = Role.objects.get(id=role_id)
        except Role.DoesNotExist:
            raise RoleNotFoundException(f"Role with ID '{role_id}' not found.")

        try:
            with transaction.atomic():
                role.is_active = True
                role.save()

                logger.info("Activated Role: %s", role.slug)

                AuditLogService.log(
                    event_type=AuditLog.EventType.ROLE_UPDATED,
                    status=AuditLog.Status.SUCCESS,
                    description=f"Role {role.slug} activated.",
                    user=actor,
                    resource="Role",
                    resource_id=str(role.id),
                    metadata={"slug": role.slug},
                )

                return role
        except ValidationError as e:
            raise InvalidRoleException(f"Validation failed: {e.message_dict}")

    @classmethod
    def deactivate_role(cls, role_id: str, actor=None) -> Role:
        """
        Deactivates a Role definition.
        """
        try:
            role = Role.objects.get(id=role_id)
        except Role.DoesNotExist:
            raise RoleNotFoundException(f"Role with ID '{role_id}' not found.")

        if role.is_system:
            raise SystemRoleModificationException(
                f"System role '{role.slug}' is immutable and cannot be deactivated."
            )

        try:
            with transaction.atomic():
                role.is_active = False
                role.save()

                logger.warning("Deactivated Role: %s", role.slug)

                AuditLogService.log(
                    event_type=AuditLog.EventType.ROLE_DELETED,
                    status=AuditLog.Status.SUCCESS,
                    description=f"Role {role.slug} deactivated.",
                    user=actor,
                    resource="Role",
                    resource_id=str(role.id),
                    metadata={"slug": role.slug},
                )

                return role
        except ValidationError as e:
            raise InvalidRoleException(f"Validation failed: {e.message_dict}")

    @classmethod
    def soft_delete_role(cls, role_id: str, actor=None) -> Role:
        """
        Deletes a role from the catalog (soft-delete only).
        """
        return cls.deactivate_role(role_id, actor=actor)

    @classmethod
    def get_role(cls, role_id: str) -> Role:
        """
        Retrieves a single Role by its UUID identifier.
        """
        try:
            return Role.objects.get(id=role_id)
        except Role.DoesNotExist:
            raise RoleNotFoundException(f"Role with ID '{role_id}' not found.")

    @classmethod
    def get_role_by_slug(cls, slug: str) -> Role:
        """
        Retrieves a single Role by its unique slug key.
        """
        try:
            return Role.objects.get(slug=slug)
        except Role.DoesNotExist:
            raise RoleNotFoundException(f"Role with slug '{slug}' not found.")

    @classmethod
    def list_roles(cls, *, is_active: bool = None) -> QuerySet[Role]:
        """
        Lists all roles, with optional active status filtering.
        """
        queryset = Role.objects.all()
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active)
        return queryset

    @classmethod
    def role_exists(cls, slug: str) -> bool:
        """
        Checks if a role with the given slug exists in the system.
        """
        return Role.objects.filter(slug=slug).exists()

    # --------------------------------------------------------------------------
    # Role Permission Management Methods
    # --------------------------------------------------------------------------

    @classmethod
    def assign_permission(
        cls,
        role_id: str,
        permission_id: str,
        assigned_by_user,
        assignment_reason: str = None
    ) -> RolePermission:
        """
        Maps a permission catalog capability to a specific job Role.
        """
        try:
            role = Role.objects.get(id=role_id)
        except Role.DoesNotExist:
            raise RoleNotFoundException(f"Role with ID '{role_id}' not found.")

        try:
            permission = Permission.objects.get(id=permission_id)
        except Permission.DoesNotExist:
            raise PermissionNotFoundException(f"Permission with ID '{permission_id}' not found in catalog.")

        if not role.is_active:
            raise PermissionAssignmentException(
                f"Cannot map permission to Role '{role.slug}' because the role is inactive."
            )

        if not permission.is_active:
            raise PermissionAssignmentException(
                f"Cannot assign permission '{permission.code}' because the permission catalog item is inactive."
            )

        try:
            with transaction.atomic():
                mapping, created = RolePermission.objects.get_or_create(
                    role=role,
                    permission=permission,
                    defaults={
                        "assigned_by": assigned_by_user,
                        "assignment_reason": assignment_reason,
                        "is_active": True
                    }
                )

                if not created:
                    if mapping.is_active:
                        raise PermissionAssignmentException(
                            f"Permission '{permission.code}' is already actively assigned to role '{role.slug}'."
                        )
                    mapping.is_active = True
                    mapping.assigned_by = assigned_by_user
                    mapping.assignment_reason = assignment_reason
                    mapping.save()

                logger.info("Mapped capability %s to Role %s", permission.code, role.slug)

                AuditLogService.log(
                    event_type=AuditLog.EventType.PERMISSION_ASSIGNED,
                    status=AuditLog.Status.SUCCESS,
                    description=f"Permission {permission.code} assigned to role {role.slug}.",
                    user=assigned_by_user,
                    resource="RolePermission",
                    resource_id=str(mapping.id),
                    metadata={"role_slug": role.slug, "permission_code": permission.code},
                )

                return mapping

        except ValidationError as e:
            raise PermissionAssignmentException(f"Validation failed during assignment: {e.message_dict}")

    @classmethod
    def remove_permission(cls, role_id: str, permission_id: str, actor=None) -> RolePermission:
        """
        Revokes a permission mapping from a Role (soft-deactivation).
        """
        try:
            mapping = RolePermission.objects.select_related("role", "permission").get(
                role_id=role_id,
                permission_id=permission_id
            )
        except RolePermission.DoesNotExist:
            raise PermissionAssignmentException(
                f"No active relationship mapping exists for Role ID '{role_id}' and Permission ID '{permission_id}'."
            )

        try:
            with transaction.atomic():
                mapping.is_active = False
                mapping.save()

                logger.warning("Revoked capability %s from Role %s", mapping.permission.code, mapping.role.slug)

                AuditLogService.log(
                    event_type=AuditLog.EventType.PERMISSION_REMOVED,
                    status=AuditLog.Status.SUCCESS,
                    description=f"Permission {mapping.permission.code} removed from role {mapping.role.slug}.",
                    user=actor,
                    resource="RolePermission",
                    resource_id=str(mapping.id),
                    metadata={"role_slug": mapping.role.slug, "permission_code": mapping.permission.code},
                )

                return mapping
        except ValidationError as e:
            raise PermissionAssignmentException(f"Validation failed during revocation: {e.message_dict}")

    @classmethod
    def get_role_permissions(cls, role_id: str, *, is_active: bool = None) -> QuerySet[Permission]:
        """
        Retrieves all Permission catalog items linked to a Role.
        
        Optimized using select_related to load all permission details in a single query.
        """
        # Verification guard
        if not Role.objects.filter(id=role_id).exists():
            raise RoleNotFoundException(f"Role with ID '{role_id}' not found.")

        # Optimize Query: Select 'permission' in the same SQL statement to avoid lazy load N+1 queries.
        mappings = RolePermission.objects.filter(role_id=role_id).select_related("permission")
        
        if is_active is not None:
            mappings = mappings.filter(is_active=is_active)
            
        # We return a QuerySet of Permission objects directly
        permission_ids = mappings.values_list("permission_id", flat=True)
        return Permission.objects.filter(id__in=permission_ids)

    @classmethod
    def clear_permissions(cls, role_id: str) -> int:
        """
        Soft-deactivates all permission capability mappings linked to a specific Role.
        
        Returns the count of deactivated mappings.
        """
        if not Role.objects.filter(id=role_id).exists():
            raise RoleNotFoundException(f"Role with ID '{role_id}' not found.")

        try:
            with transaction.atomic():
                # We soft deactivate active mappings only
                updated_count = RolePermission.objects.filter(
                    role_id=role_id,
                    is_active=True
                ).update(is_active=False)

                logger.warning("Cleared %d mapped permissions from Role ID %s", updated_count, role_id)

                # TODO: Trigger AuditLogService call in a later phase.
                # AuditLogService.log_permissions_cleared(role_id=role_id)

                return updated_count
        except Exception as e:
            raise PermissionAssignmentException(f"Failed to clear mappings: {str(e)}")

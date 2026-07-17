import logging
from django.db import transaction, IntegrityError
from django.core.exceptions import ValidationError
from django.db.models import QuerySet

from apps.authorization.models import Permission
from apps.authorization.exceptions import (
    PermissionAlreadyExistsException,
    PermissionNotFoundException,
)

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------------------
# Custom Exceptions
# ------------------------------------------------------------------------------

class PermissionServiceException(Exception):
    """Base exception for all PermissionService errors."""
    pass


class SystemPermissionModificationException(PermissionServiceException):
    """Raised when attempting to modify, delete, or deactivate immutable system permissions."""
    pass


class InvalidPermissionException(PermissionServiceException):
    """Raised when a permission's attributes are semantically invalid."""
    pass


# ------------------------------------------------------------------------------
# Permission Service Implementation
# ------------------------------------------------------------------------------

class PermissionService:
    """
    Enterprise Permission Catalog Service.
    
    Provides standard capabilities to register, list, search, update, and soft-deactivate
    catalog permissions. Enforces system-level immutability rules, data consistency,
    and transactional integrity.
    """

    @classmethod
    def create_permission(
        cls,
        *,
        name: str,
        resource: str,
        action: str,
        description: str = "",
        is_system: bool = False
    ) -> Permission:
        """
        Registers a new permission capability in the system catalog.
        
        Enforces unique code naming conventions and resource-action consistency.
        """
        code = f"{resource}:{action}"
        
        if cls.permission_exists(code):
            raise PermissionAlreadyExistsException(
                f"Permission capability with code '{code}' is already registered in the catalog."
            )

        try:
            with transaction.atomic():
                permission = Permission(
                    name=name,
                    code=code,
                    resource=resource,
                    action=action,
                    description=description,
                    is_system=is_system,
                    is_active=True
                )
                permission.full_clean()
                permission.save()

                logger.info("Successfully registered permission catalog item: %s", code)

                # TODO: Trigger AuditLogService here in a later phase.
                # AuditLogService.log_event(
                #     event_type="authorization.permission.create",
                #     resource=code,
                #     status="success",
                #     details=f"Created permission: {name} (System: {is_system})"
                # )

                return permission
                
        except ValidationError as e:
            logger.error("Validation failed during permission registration for code %s: %s", code, e.message_dict)
            raise InvalidPermissionException(f"Invalid permission structure: {e.message_dict}")
        except IntegrityError as e:
            logger.error("Database integrity conflict during permission registration for code %s: %s", code, str(e))
            raise PermissionAlreadyExistsException(f"Database conflict occurred: {e}")

    @classmethod
    def update_permission(
        cls,
        permission_id: str,
        *,
        name: str = None,
        description: str = None,
        **kwargs
    ) -> Permission:
        """
        Updates name and description attributes of an existing permission.
        
        System-defined permissions are protected from renaming or modification of their core properties.
        """
        try:
            permission = Permission.objects.get(id=permission_id)
        except Permission.DoesNotExist:
            raise PermissionNotFoundException(f"Permission catalog item with ID '{permission_id}' not found.")

        # Immutability Check for system roles
        if permission.is_system:
            if name is not None and name.strip() != permission.name:
                raise SystemPermissionModificationException(
                    f"System permission '{permission.code}' is immutable and cannot be renamed."
                )

        # Core fields (code, resource, action, is_system) are read-only
        immutable_fields = ["code", "resource", "action", "is_system"]
        for field in immutable_fields:
            if field in kwargs:
                raise SystemPermissionModificationException(
                    f"Field '{field}' represents a core catalog configuration and cannot be modified."
                )

        try:
            with transaction.atomic():
                if name is not None:
                    permission.name = name.strip()
                if description is not None:
                    permission.description = description.strip()

                permission.full_clean()
                permission.save()

                logger.info("Successfully updated permission catalog item: %s", permission.code)

                # TODO: Trigger AuditLogService here in a later phase.
                # AuditLogService.log_event(
                #     event_type="authorization.permission.update",
                #     resource=permission.code,
                #     status="success",
                #     details=f"Updated permission details"
                # )

                return permission
                
        except ValidationError as e:
            logger.error("Validation failed during permission update for ID %s: %s", permission_id, e.message_dict)
            raise InvalidPermissionException(f"Invalid updates: {e.message_dict}")

    @classmethod
    def deactivate_permission(cls, permission_id: str) -> Permission:
        """
        Deactivates (soft-deletes) a permission catalog capability.
        
        Immutable system capabilities cannot be deactivated.
        """
        try:
            permission = Permission.objects.get(id=permission_id)
        except Permission.DoesNotExist:
            raise PermissionNotFoundException(f"Permission catalog item with ID '{permission_id}' not found.")

        if permission.is_system:
            raise SystemPermissionModificationException(
                f"System permission '{permission.code}' is required for IAM operations and cannot be deactivated."
            )

        try:
            with transaction.atomic():
                permission.is_active = False
                permission.save()

                logger.warning("Soft-deactivated permission catalog item: %s", permission.code)

                # TODO: Trigger AuditLogService here in a later phase.
                # AuditLogService.log_event(
                #     event_type="authorization.permission.deactivate",
                #     resource=permission.code,
                #     status="success",
                #     details="Soft-deactivated permission capability"
                # )

                return permission
                
        except ValidationError as e:
            raise InvalidPermissionException(f"Validation failed: {e.message_dict}")

    @classmethod
    def activate_permission(cls, permission_id: str) -> Permission:
        """
        Re-activates a soft-disabled permission catalog capability.
        """
        try:
            permission = Permission.objects.get(id=permission_id)
        except Permission.DoesNotExist:
            raise PermissionNotFoundException(f"Permission catalog item with ID '{permission_id}' not found.")

        try:
            with transaction.atomic():
                permission.is_active = True
                permission.save()

                logger.info("Re-activated permission catalog item: %s", permission.code)

                # TODO: Trigger AuditLogService here in a later phase.
                # AuditLogService.log_event(
                #     event_type="authorization.permission.activate",
                #     resource=permission.code,
                #     status="success",
                #     details="Re-activated permission capability"
                # )

                return permission
                
        except ValidationError as e:
            raise InvalidPermissionException(f"Validation failed: {e.message_dict}")

    @classmethod
    def get_permission_by_code(cls, code: str) -> Permission:
        """
        Fetches a permission model instance from the database by its unique code.
        """
        try:
            return Permission.objects.get(code=code)
        except Permission.DoesNotExist:
            raise PermissionNotFoundException(f"Permission catalog capability '{code}' not found.")

    @classmethod
    def list_permissions(cls, *, is_active: bool = None) -> QuerySet[Permission]:
        """
        Lists all permissions registered in the system catalog, with optional active filtering.
        """
        queryset = Permission.objects.all()
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active)
        return queryset

    @classmethod
    def permission_exists(cls, code: str) -> bool:
        """
        Helper method to check the registration status of a permission code.
        """
        return Permission.objects.filter(code=code).exists()

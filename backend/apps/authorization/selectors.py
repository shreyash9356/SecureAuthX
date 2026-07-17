import logging
from django.db import models
from django.db.models import QuerySet
from django.utils import timezone

from apps.authorization.models import Permission, Role, RolePermission, UserRole
from apps.authorization.exceptions import PermissionNotFoundException, RoleNotFoundException

logger = logging.getLogger(__name__)


class PermissionSelector:
    """
    Selector layer for read-only Permission catalog queries.
    
    Provides highly optimized and reusable database search methods,
    preventing direct ORM leakage into service or view layers.
    """

    @classmethod
    def get_permission_by_id(cls, permission_id: str) -> Permission:
        """
        Retrieves a single Permission by its UUID string.
        """
        try:
            return Permission.objects.get(id=permission_id)
        except Permission.DoesNotExist:
            raise PermissionNotFoundException(f"Permission with ID '{permission_id}' not found in the catalog.")

    @classmethod
    def get_permission_by_code(cls, code: str) -> Permission:
        """
        Retrieves a single Permission by its unique code (e.g. 'identity:user:create').
        """
        try:
            return Permission.objects.get(code=code)
        except Permission.DoesNotExist:
            raise PermissionNotFoundException(f"Permission with code '{code}' not found in the catalog.")

    @classmethod
    def list_permissions(cls, *, is_active: bool = None) -> QuerySet[Permission]:
        """
        Lists all permissions, with optional active status filtering.
        """
        queryset = Permission.objects.all()
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active)
        return queryset

    @classmethod
    def list_system_permissions(cls) -> QuerySet[Permission]:
        """
        Lists only system-defined (immutable) permissions.
        """
        return Permission.objects.filter(is_system=True)


class RoleSelector:
    """
    Selector layer for read-only Role query operations.
    """

    @classmethod
    def get_role_by_id(cls, role_id: str) -> Role:
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
        Retrieves a single Role by its unique slug identifier.
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
    def list_system_roles(cls) -> QuerySet[Role]:
        """
        Lists only system-defined default roles.
        """
        return Role.objects.filter(is_system=True)


class AuthorizationSelector:
    """
    High-performance selector layer for runtime policy access resolution checks.
    
    Provides clean read queries to determine active roles, mappings, 
    and capabilities.
    """

    @classmethod
    def get_active_user_roles(cls, user) -> QuerySet[Role]:
        """
        Resolves the user's active, unexpired roles.
        
        Ignores inactive roles, expired memberships, and disabled assignments.
        """
        if not user or not user.is_authenticated:
            return Role.objects.none()

        now = timezone.now()
        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True,
            role__is_active=True
        ).filter(
            models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now)
        )

        role_ids = user_roles.values_list("role_id", flat=True)
        return Role.objects.filter(id__in=role_ids, is_active=True)

    @classmethod
    def get_active_role_permissions(cls, role: Role) -> QuerySet[Permission]:
        """
        Retrieves all active Permission catalog items currently mapped to a Role.
        """
        # Optimize Query: Select permission in the same SQL statement to avoid lazy loading N+1 queries.
        mappings = RolePermission.objects.filter(
            role=role,
            is_active=True,
            permission__is_active=True
        ).select_related("permission")

        permission_ids = mappings.values_list("permission_id", flat=True)
        return Permission.objects.filter(id__in=permission_ids, is_active=True)

    @classmethod
    def get_effective_user_permissions(cls, user) -> set[str]:
        """
        Resolves the user's active, unexpired capability codes.
        
        Filters out:
        - Inactive user role mappings or expired time-windows.
        - Deactivated roles.
        - Deactivated role-permission mappings.
        - Disabled permission catalog definitions.
        
        Optimized to fetch unique code strings in a single JOIN statement.
        """
        if not user or not user.is_authenticated:
            return set()

        now = timezone.now()

        # Perform a single JOIN query to resolve effective codes
        active_codes = Permission.objects.filter(
            is_active=True,
            permission_roles__is_active=True,
            permission_roles__role__is_active=True,
            permission_roles__role__role_users__user=user,
            permission_roles__role__role_users__is_active=True
        ).filter(
            models.Q(permission_roles__role__role_users__expires_at__isnull=True) |
            models.Q(permission_roles__role__role_users__expires_at__gt=now)
        ).values_list("code", flat=True).distinct()

        return set(active_codes)

import logging
from django.db import models
from django.utils import timezone

from apps.authorization.models import Role, Permission, RolePermission, UserRole

logger = logging.getLogger(__name__)


class AuthorizationService:
    """
    Core Authorization Engine for SecureAuthX.
    
    Evaluates runtime permission checks, active job role mappings, 
    and resolves effective capability scopes for users. Decoupled from HTTP context.
    """

    # --------------------------------------------------------------------------
    # Check-time Methods
    # --------------------------------------------------------------------------

    @classmethod
    def has_permission(cls, user, permission_code: str) -> bool:
        """
        Evaluates whether a user is currently authorized to perform an action.
        
        Checks if the permission code exists within the user's active,
        unexpired privilege catalog set.
        """
        if not user or not user.is_authenticated:
            return False

        effective_perms = cls.get_effective_permissions(user)
        is_allowed = permission_code in effective_perms

        if is_allowed:
            logger.debug("Access GRANTED to user %s for permission '%s'", user.email, permission_code)
        else:
            logger.warning("Access DENIED to user %s for permission '%s'", user.email, permission_code)

        return is_allowed

    @classmethod
    def has_role(cls, user, role_slug: str) -> bool:
        """
        Determines if a user currently holds an active, unexpired job role.
        """
        if not user or not user.is_authenticated:
            return False

        now = timezone.now()
        return UserRole.objects.filter(
            user=user,
            role__slug=role_slug,
            is_active=True,
            role__is_active=True
        ).filter(
            models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now)
        ).exists()

    @classmethod
    def has_any_role(cls, user, roles: list[str]) -> bool:
        """
        Checks if a user holds at least one active role in the provided list.
        """
        if not user or not user.is_authenticated or not roles:
            return False

        now = timezone.now()
        return UserRole.objects.filter(
            user=user,
            role__slug__in=roles,
            is_active=True,
            role__is_active=True
        ).filter(
            models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now)
        ).exists()

    @classmethod
    def has_all_roles(cls, user, roles: list[str]) -> bool:
        """
        Checks if a user holds all active roles specified in the provided list.
        """
        if not user or not user.is_authenticated or not roles:
            return False

        now = timezone.now()
        user_role_slugs = set(
            UserRole.objects.filter(
                user=user,
                is_active=True,
                role__is_active=True
            ).filter(
                models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now)
            ).values_list("role__slug", flat=True)
        )

        return all(role in user_role_slugs for role in roles)

    # --------------------------------------------------------------------------
    # Scope Resolution Methods
    # --------------------------------------------------------------------------

    @classmethod
    def get_user_roles(cls, user) -> models.QuerySet[Role]:
        """
        Retrieves all roles historically or currently assigned to a user.
        
        Includes both active/inactive and expired mappings.
        """
        if not user or not user.is_authenticated:
            return Role.objects.none()

        assignments = UserRole.objects.filter(user=user).select_related("role")
        role_ids = assignments.values_list("role_id", flat=True)
        return Role.objects.filter(id__in=role_ids)

    @classmethod
    def get_user_permissions(cls, user) -> models.QuerySet[Permission]:
        """
        Retrieves all permission definitions associated with any role mapped to the user.
        
        Includes inactive/expired assignments and disabled permissions.
        """
        if not user or not user.is_authenticated:
            return Permission.objects.none()

        user_roles = UserRole.objects.filter(user=user).values_list("role_id", flat=True)
        role_perms = RolePermission.objects.filter(role_id__in=user_roles).values_list("permission_id", flat=True)
        return Permission.objects.filter(id__in=role_perms)

    @classmethod
    def get_effective_roles(cls, user) -> models.QuerySet[Role]:
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
    def get_effective_permissions(cls, user) -> set[str]:
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

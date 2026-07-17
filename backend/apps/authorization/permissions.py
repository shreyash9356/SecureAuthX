import logging
from rest_framework.permissions import BasePermission

from apps.authorization.constants import PermissionCodes, RoleSlugs
from apps.authorization.services.authorization_service import AuthorizationService

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# DRF Permission Classes
# --------------------------------------------------------------------------

class HasPermission(BasePermission):
    """
    Enforces catalog RBAC via AuthorizationService.has_permission.

    Resolution order for required codes (first match wins):
      1. view.get_required_permissions() / view.get_required_permission()
      2. view.required_permission_map[request.method]
      3. view.required_permissions  (ALL must be held — AND)
      4. view.required_permission   (single code)

    Fail-secure: missing configuration or missing capability → deny.
    Pair with IsAuthenticated so unauthenticated callers receive 401 first.
    """

    message = "You do not have permission to perform this action."

    def has_permission(self, request, view) -> bool:
        if not request.user or not request.user.is_authenticated:
            return False

        required_codes = self._resolve_required_codes(request, view)
        if not required_codes:
            logger.warning(
                "HasPermission applied to '%s' but no required permission is configured.",
                view.__class__.__name__,
            )
            return False

        return all(
            AuthorizationService.has_permission(request.user, code)
            for code in required_codes
        )

    def _resolve_required_codes(self, request, view) -> list[str]:
        if hasattr(view, "get_required_permissions"):
            codes = view.get_required_permissions()
            if codes:
                return self._normalize_codes(codes)

        if hasattr(view, "get_required_permission"):
            code = view.get_required_permission()
            if code:
                return [code]

        method_map = getattr(view, "required_permission_map", None)
        if method_map:
            mapped = method_map.get(request.method)
            if mapped:
                return self._normalize_codes(mapped)

        permissions = getattr(view, "required_permissions", None)
        if permissions:
            return self._normalize_codes(permissions)

        permission = getattr(view, "required_permission", None)
        if permission:
            return [permission]

        return []

    @staticmethod
    def _normalize_codes(value) -> list[str]:
        if isinstance(value, str):
            return [value]
        return list(value)


class HasRole(BasePermission):
    """
    Enforces that the authenticated user holds the specific role slug.

    Reads ``required_role`` from the view class.
    """

    message = "You do not have the required role to perform this action."

    def has_permission(self, request, view) -> bool:
        if not request.user or not request.user.is_authenticated:
            return False

        role_slug = getattr(view, "required_role", None)
        if not role_slug:
            logger.warning(
                "HasRole gate applied to view '%s' but no 'required_role' is configured.",
                view.__class__.__name__,
            )
            return False

        return AuthorizationService.has_role(request.user, role_slug)


class HasAnyRole(BasePermission):
    """
    Enforces that the authenticated user holds at least one role slug
    from ``required_roles`` on the view.
    """

    message = "You do not have any of the required roles to perform this action."

    def has_permission(self, request, view) -> bool:
        if not request.user or not request.user.is_authenticated:
            return False

        role_slugs = getattr(view, "required_roles", None)
        if not role_slugs:
            logger.warning(
                "HasAnyRole gate applied to view '%s' but no 'required_roles' is configured.",
                view.__class__.__name__,
            )
            return False

        return AuthorizationService.has_any_role(request.user, list(role_slugs))


class HasAllRoles(BasePermission):
    """
    Enforces that the authenticated user holds every role slug
    in ``required_roles`` on the view.
    """

    message = "You do not have all of the required roles to perform this action."

    def has_permission(self, request, view) -> bool:
        if not request.user or not request.user.is_authenticated:
            return False

        role_slugs = getattr(view, "required_roles", None)
        if not role_slugs:
            logger.warning(
                "HasAllRoles gate applied to view '%s' but no 'required_roles' is configured.",
                view.__class__.__name__,
            )
            return False

        return AuthorizationService.has_all_roles(request.user, list(role_slugs))


class IsSuperAdmin(BasePermission):
    """Restricts access to Super Administrators only."""

    message = "Super Administrator role is required."

    def has_permission(self, request, view) -> bool:
        if not request.user or not request.user.is_authenticated:
            return False

        return AuthorizationService.has_role(request.user, RoleSlugs.SUPER_ADMIN)


class IsAdmin(BasePermission):
    """Restricts access to Administrators and Super Administrators."""

    message = "Administrator role is required."

    def has_permission(self, request, view) -> bool:
        if not request.user or not request.user.is_authenticated:
            return False

        return AuthorizationService.has_any_role(
            request.user,
            [RoleSlugs.SUPER_ADMIN, RoleSlugs.ADMIN],
        )


class IsManager(BasePermission):
    """Restricts access to Managers, Administrators, and Super Administrators."""

    message = "Manager role (or higher) is required."

    def has_permission(self, request, view) -> bool:
        if not request.user or not request.user.is_authenticated:
            return False

        return AuthorizationService.has_any_role(
            request.user,
            [RoleSlugs.SUPER_ADMIN, RoleSlugs.ADMIN, RoleSlugs.MANAGER],
        )


# --------------------------------------------------------------------------
# Object-Level Authorization Helpers (BOLA/IDOR protection)
# --------------------------------------------------------------------------

def can_edit_user(request_user, target_user) -> bool:
    """
    Determines if a user can edit another user's profile details.

    Rules:
    - Users can edit their own profiles.
    - Admins with identity:user:update can edit other profiles.
    """
    if not request_user or not request_user.is_authenticated:
        return False

    if target_user and request_user.id == target_user.id:
        return True

    return AuthorizationService.has_permission(
        request_user, PermissionCodes.USER_UPDATE
    )


def can_delete_user(request_user, target_user) -> bool:
    """
    Determines if a user can soft-delete or remove a user account.

    Rules:
    - Users cannot delete themselves (prevents self-lockout).
    - Requires identity:user:delete.
    """
    if not request_user or not request_user.is_authenticated:
        return False

    if target_user and request_user.id == target_user.id:
        return False

    return AuthorizationService.has_permission(
        request_user, PermissionCodes.USER_DELETE
    )


def can_assign_role(request_user, target_user, role) -> bool:
    """
    Determines if a user can assign a role to a target user account.

    Rules:
    - Requires identity:user:update.
    - Cannot assign a role with higher rank (lower priority number)
      than the caller's own highest rank.
    """
    if not request_user or not request_user.is_authenticated:
        return False

    if not AuthorizationService.has_permission(
        request_user, PermissionCodes.USER_UPDATE
    ):
        return False

    assigned_roles = AuthorizationService.get_effective_roles(request_user)
    if not assigned_roles.exists():
        return False

    # Higher priority number = higher privilege (see seed_roles).
    highest_user_priority = max(r.priority for r in assigned_roles)
    if role.priority > highest_user_priority:
        return False

    return True


def can_manage_role(request_user, role) -> bool:
    """
    Determines if a user can create, update, or deactivate a Role.

    Rules:
    - Requires identity:role:update.
    - Cannot modify roles with higher rank than the caller's own.
    """
    if not request_user or not request_user.is_authenticated:
        return False

    if not AuthorizationService.has_permission(
        request_user, PermissionCodes.ROLE_UPDATE
    ):
        return False

    assigned_roles = AuthorizationService.get_effective_roles(request_user)
    if not assigned_roles.exists():
        return False

    # Higher priority number = higher privilege (see seed_roles).
    highest_user_priority = max(r.priority for r in assigned_roles)
    if role.priority > highest_user_priority:
        return False

    return True


def can_view_organization(request_user, organization) -> bool:
    """
    Determines if a user can view organization details.

    Requires identity:organization read capability.
    """
    if not request_user or not request_user.is_authenticated:
        return False

    return AuthorizationService.has_permission(
        request_user, PermissionCodes.ORGANIZATION_READ
    )


def can_manage_organization(request_user, organization) -> bool:
    """
    Determines if a user can manage organization settings.

    Requires identity:organization update capability.
    """
    if not request_user or not request_user.is_authenticated:
        return False

    return AuthorizationService.has_permission(
        request_user, PermissionCodes.ORGANIZATION_UPDATE
    )


def can_view_audit_log(request_user) -> bool:
    """
    Determines if a user can search or read security audit logs.

    Requires audit:log:read.
    """
    if not request_user or not request_user.is_authenticated:
        return False

    return AuthorizationService.has_permission(
        request_user, PermissionCodes.AUDIT_LOG_READ
    )

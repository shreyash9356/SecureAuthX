class AuthorizationException(Exception):
    """Base exception for all authorization module errors."""
    pass


class PermissionNotFoundException(AuthorizationException):
    """Raised when a requested permission is not found in the catalog."""
    pass


class RoleNotFoundException(AuthorizationException):
    """Raised when a requested role is not found."""
    pass


class RoleAlreadyExistsException(AuthorizationException):
    """Raised when trying to register a role with a duplicate name or slug."""
    pass


class SystemRoleModificationException(AuthorizationException):
    """Raised when trying to modify, rename, deactivate, or delete a system-defined role."""
    pass


class PermissionAssignmentException(AuthorizationException):
    """Raised when permission assignment check-time conditions or invariants fail."""
    pass


class InvalidRoleException(AuthorizationException):
    """Raised when a role's attributes are semantically invalid."""
    pass


class RoleAssignmentException(AuthorizationException):
    """Raised when user-role allocation rules, uniqueness, or expiration validations fail."""
    pass

class PermissionAlreadyExistsException(AuthorizationException):
    """Raised when attempting to create a permission that already exists."""
    pass
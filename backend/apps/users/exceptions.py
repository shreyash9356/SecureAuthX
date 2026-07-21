class UserManagementException(Exception):
    """Base exception for all user-management related business rule violations."""
    pass


class SelfOperationException(UserManagementException):
    """Raised when an actor attempts to perform a self-destructive action (e.g., self-deactivate, self-lock)."""
    pass


class OwnerDeactivationException(UserManagementException):
    """Raised when attempting to deactivate or lock the owner of an active organization."""
    pass

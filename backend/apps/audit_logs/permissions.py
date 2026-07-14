"""
DRF permission classes for the audit_logs module.

Audit logs are sensitive security records.  Only active Django staff
users (is_staff=True) are permitted to read them via the API.
"""

from rest_framework.permissions import BasePermission


class IsAdminUser(BasePermission):
    """
    Grants access exclusively to authenticated staff users.

    Uses Django's built-in ``is_staff`` flag rather than a custom
    role so the permission works without the RBAC module being present.
    """

    message = "You do not have permission to access audit logs."

    def has_permission(self, request, view) -> bool:
        return bool(
            request.user and request.user.is_authenticated and request.user.is_staff
        )

"""
Permissions for the Multi-Factor Authentication (MFA) module.
"""

from rest_framework.permissions import BasePermission


class IsMFADeviceOwner(BasePermission):
    """
    Ensure the request user is the owner of the target MFA device.
    """

    def has_object_permission(self, request, view, obj) -> bool:
        if not request.user or not request.user.is_authenticated:
            return False
        return obj.user_id == request.user.id

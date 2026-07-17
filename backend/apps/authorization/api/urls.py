from django.urls import path

from apps.authorization.api.views import (
    PermissionListCreateAPIView,
    PermissionDetailAPIView,
    PermissionActivateAPIView,
    PermissionDeactivateAPIView,
    RoleListCreateAPIView,
    RoleDetailAPIView,
    RoleActivateAPIView,
    RoleDeactivateAPIView,
    RolePermissionAssignAPIView,
    RolePermissionRemoveAPIView,
    RolePermissionListAPIView,
    UserRoleAssignAPIView,
    UserRoleRevokeAPIView,
    UserRoleExtendAPIView,
    UserRoleListAPIView,
)

app_name = "authorization"

urlpatterns = [
    # --------------------------------------------------------------------------
    # Permissions Endpoints
    # --------------------------------------------------------------------------
    path(
        "permissions/", 
        PermissionListCreateAPIView.as_view(), 
        name="permission-list-create"
    ),
    path(
        "permissions/<uuid:permission_id>/", 
        PermissionDetailAPIView.as_view(), 
        name="permission-detail"
    ),
    path(
        "permissions/<uuid:permission_id>/activate/", 
        PermissionActivateAPIView.as_view(), 
        name="permission-activate"
    ),
    path(
        "permissions/<uuid:permission_id>/deactivate/", 
        PermissionDeactivateAPIView.as_view(), 
        name="permission-deactivate"
    ),

    # --------------------------------------------------------------------------
    # Roles Endpoints
    # --------------------------------------------------------------------------
    path(
        "roles/", 
        RoleListCreateAPIView.as_view(), 
        name="role-list-create"
    ),
    path(
        "roles/<uuid:role_id>/", 
        RoleDetailAPIView.as_view(), 
        name="role-detail"
    ),
    path(
        "roles/<uuid:role_id>/activate/", 
        RoleActivateAPIView.as_view(), 
        name="role-activate"
    ),
    path(
        "roles/<uuid:role_id>/deactivate/", 
        RoleDeactivateAPIView.as_view(), 
        name="role-deactivate"
    ),

    # --------------------------------------------------------------------------
    # Role Permissions Mapping Endpoints
    # --------------------------------------------------------------------------
    path(
        "roles/permissions/assign/", 
        RolePermissionAssignAPIView.as_view(), 
        name="role-permission-assign"
    ),
    path(
        "roles/permissions/remove/", 
        RolePermissionRemoveAPIView.as_view(), 
        name="role-permission-remove"
    ),
    path(
        "roles/<uuid:role_id>/permissions/", 
        RolePermissionListAPIView.as_view(), 
        name="role-permission-list"
    ),

    # --------------------------------------------------------------------------
    # User Roles Assignments Endpoints
    # --------------------------------------------------------------------------
    path(
        "users/roles/assign/", 
        UserRoleAssignAPIView.as_view(), 
        name="user-role-assign"
    ),
    path(
        "users/roles/revoke/", 
        UserRoleRevokeAPIView.as_view(), 
        name="user-role-revoke"
    ),
    path(
        "users/roles/extend/", 
        UserRoleExtendAPIView.as_view(), 
        name="user-role-extend"
    ),
    path(
        "users/<uuid:user_id>/roles/", 
        UserRoleListAPIView.as_view(), 
        name="user-role-list"
    ),
]

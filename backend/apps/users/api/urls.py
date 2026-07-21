from django.urls import path
from apps.users.api.views import (
    UserListAPIView,
    UserDetailAPIView,
    UserActivateAPIView,
    UserDeactivateAPIView,
    UserLockAPIView,
    UserUnlockAPIView,
    UserRoleAssignAPIView,
    UserRoleRevokeAPIView,
)

app_name = "users"

urlpatterns = [
    path("", UserListAPIView.as_view(), name="user-list"),
    path("<uuid:pk>/", UserDetailAPIView.as_view(), name="user-detail"),
    path("<uuid:pk>/activate/", UserActivateAPIView.as_view(), name="user-activate"),
    path("<uuid:pk>/deactivate/", UserDeactivateAPIView.as_view(), name="user-deactivate"),
    path("<uuid:pk>/lock/", UserLockAPIView.as_view(), name="user-lock"),
    path("<uuid:pk>/unlock/", UserUnlockAPIView.as_view(), name="user-unlock"),
    path("<uuid:pk>/assign-role/", UserRoleAssignAPIView.as_view(), name="user-assign-role"),
    path("<uuid:pk>/revoke-role/", UserRoleRevokeAPIView.as_view(), name="user-revoke-role"),
]

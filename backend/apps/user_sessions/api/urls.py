"""
URL configuration for the user_sessions API.
"""

from django.urls import path

from apps.user_sessions.api.views import (
    SessionListAPIView,
    SessionDetailAPIView,
    LogoutCurrentSessionAPIView,
    LogoutAllSessionsAPIView,
    RevokeSessionAPIView,
)

app_name = "user_sessions"

urlpatterns = [
    path("", SessionListAPIView.as_view(), name="session-list"),
    path(
        "logout-current/",
        LogoutCurrentSessionAPIView.as_view(),
        name="logout-current",
    ),
    path("logout-all/", LogoutAllSessionsAPIView.as_view(), name="logout-all"),
    path("<uuid:session_id>/", SessionDetailAPIView.as_view(), name="session-detail"),
    path(
        "<uuid:session_id>/revoke/",
        RevokeSessionAPIView.as_view(),
        name="session-revoke",
    ),
]

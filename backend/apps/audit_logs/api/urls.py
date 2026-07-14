"""
URL configuration for the audit_logs API module.
"""

from django.urls import path

from apps.audit_logs.api.views import (
    AuditLogDetailAPIView,
    AuditLogListAPIView,
)

app_name = "audit_logs"

urlpatterns = [
    path(
        "",
        AuditLogListAPIView.as_view(),
        name="list",
    ),
    path(
        "<uuid:pk>/",
        AuditLogDetailAPIView.as_view(),
        name="detail",
    ),
]

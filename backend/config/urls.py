"""
URL configuration for SecureAuthX.
"""

from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

urlpatterns = [
    # Django Admin
    path("admin/", admin.site.urls),
    # Authentication API
    path(
        "api/v1/auth/",
        include("apps.authentication.api.urls"),
    ),
    # Authorization API
    path(
        "api/v1/authorization/",
        include("apps.authorization.api.urls"),
    ),
    # Organizations API
    path(
        "api/v1/organizations/",
        include("apps.organizations.api.urls"),
    ),
    # Audit Logs API
    path(
        "api/v1/audit-logs/",
        include("apps.audit_logs.api.urls"),
    ),
    # OpenAPI schema (machine-readable)
    path(
        "api/schema/",
        SpectacularAPIView.as_view(),
        name="schema",
    ),
    # Swagger UI (human-readable)
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
    # ReDoc (alternative documentation UI)
    path(
        "api/redoc/",
        SpectacularRedocView.as_view(url_name="schema"),
        name="redoc",
    ),
]

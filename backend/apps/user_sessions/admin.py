from django.contrib import admin

from .models import UserSession


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    """Admin configuration for UserSession."""

    list_display = (
        "id",
        "user",
        "organization",
        "status",
        "device_type",
        "browser",
        "operating_system",
        "ip_address",
        "login_time",
        "last_activity",
        "expires_at",
    )

    list_filter = (
        "status",
        "device_type",
        "organization",
        "login_time",
        "expires_at",
    )

    search_fields = (
        "user__email",
        "user__username",
        "browser",
        "operating_system",
        "ip_address",
    )

    readonly_fields = (
        "id",
        "login_time",
        "created_at",
        "updated_at",
        "last_activity",
        "logout_time",
        "revoked_at",
    )

    ordering = ("-login_time",)

    autocomplete_fields = (
        "user",
        "organization",
        "revoked_by",
    )

    list_per_page = 25

    fieldsets = (
        (
            "Session Information",
            {
                "fields": (
                    "id",
                    "user",
                    "organization",
                    "status",
                )
            },
        ),
        (
            "Device Information",
            {
                "fields": (
                    "device_type",
                    "browser",
                    "operating_system",
                    "user_agent",
                    "ip_address",
                )
            },
        ),
        (
            "Session Lifecycle",
            {
                "fields": (
                    "login_time",
                    "last_activity",
                    "logout_time",
                    "expires_at",
                )
            },
        ),
        (
            "Revocation",
            {
                "fields": (
                    "revoked_by",
                    "revoked_at",
                    "revocation_reason",
                )
            },
        ),
        (
            "Audit",
            {
                "classes": ("collapse",),
                "fields": (
                    "created_at",
                    "updated_at",
                ),
            },
        ),
    )
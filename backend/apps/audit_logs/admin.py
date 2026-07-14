"""
Django Admin configuration for the audit_logs module.

Audit logs are read-only in the admin panel.
No add, change, or delete actions are permitted.
"""

from django.contrib import admin

from apps.audit_logs.models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """
    Read-only admin interface for AuditLog records.

    Deliberately disables all write operations to preserve
    the immutability guarantee of the audit trail.
    """

    # ── Display ────────────────────────────────────────────────────────────────
    list_display = (
        "created_at",
        "event_type",
        "status",
        "get_user_email",
        "ip_address",
        "resource",
        "resource_id",
    )

    list_display_links = ("created_at", "event_type")

    # ── Filtering & search ────────────────────────────────────────────────────
    list_filter = (
        "status",
        "event_type",
        "created_at",
    )

    search_fields = (
        "user__email",
        "event_type",
        "description",
    )

    # ── Ordering ──────────────────────────────────────────────────────────────
    ordering = ("-created_at",)

    # ── Detail view ───────────────────────────────────────────────────────────
    readonly_fields = (
        "id",
        "user",
        "event_type",
        "status",
        "ip_address",
        "user_agent",
        "description",
        "metadata",
        "resource",
        "resource_id",
        "created_at",
    )

    fieldsets = (
        (
            "Event",
            {
                "fields": (
                    "id",
                    "event_type",
                    "status",
                    "description",
                ),
            },
        ),
        (
            "Actor",
            {
                "fields": (
                    "user",
                    "ip_address",
                    "user_agent",
                ),
            },
        ),
        (
            "Resource",
            {
                "fields": (
                    "resource",
                    "resource_id",
                ),
            },
        ),
        (
            "Metadata",
            {
                "fields": ("metadata",),
                "classes": ("collapse",),
            },
        ),
        (
            "Timestamps",
            {
                "fields": ("created_at",),
            },
        ),
    )

    # ── Immutability enforcement ───────────────────────────────────────────────

    def has_add_permission(self, request) -> bool:
        """Disable manual creation of audit logs via admin."""
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        """Disable editing of audit logs via admin."""
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        """Disable deletion of audit logs via admin."""
        return False

    # ── Custom columns ─────────────────────────────────────────────────────────

    @admin.display(description="User Email", ordering="user__email")
    def get_user_email(self, obj: AuditLog) -> str:
        """Display user email or '—' for anonymous events."""
        return obj.user.email if obj.user_id else "—"

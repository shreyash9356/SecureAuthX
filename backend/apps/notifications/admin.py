from django.contrib import admin
from apps.notifications.models import (
    Notification,
    NotificationPreference,
    NotificationTemplate,
)


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "category",
        "priority",
        "channel",
        "title",
        "is_read",
        "is_deleted",
        "created_at",
    )
    list_filter = (
        "category",
        "priority",
        "channel",
        "is_read",
        "is_deleted",
        "created_at",
    )
    search_fields = (
        "id",
        "user__email",
        "title",
        "message",
    )
    raw_id_fields = ("user", "organization")
    readonly_fields = ("id", "created_at", "read_at", "deleted_at")
    ordering = ("-created_at",)


@admin.register(NotificationPreference)
class NotificationPreferenceAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "email_notifications",
        "in_app_notifications",
        "security_notifications",
        "organization_notifications",
        "marketing_notifications",
        "updated_at",
    )
    list_filter = (
        "email_notifications",
        "in_app_notifications",
        "security_notifications",
        "organization_notifications",
    )
    search_fields = ("user__email",)
    raw_id_fields = ("user",)
    readonly_fields = ("created_at", "updated_at")


@admin.register(NotificationTemplate)
class NotificationTemplateAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "category",
        "channel",
        "subject",
        "title",
        "is_active",
        "updated_at",
    )
    list_filter = (
        "category",
        "channel",
        "is_active",
    )
    search_fields = (
        "name",
        "subject",
        "title",
        "body",
    )
    readonly_fields = ("id", "created_at", "updated_at")
    ordering = ("name", "channel")

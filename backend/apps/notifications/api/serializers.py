from rest_framework import serializers
from apps.notifications.models import (
    Notification,
    NotificationPreference,
    NotificationTemplate,
)


class NotificationSerializer(serializers.ModelSerializer):
    """
    Serializer for listing notifications.
    """
    organization_name = serializers.CharField(source="organization.name", read_only=True, default=None)

    class Meta:
        model = Notification
        fields = [
            "id",
            "category",
            "priority",
            "channel",
            "title",
            "message",
            "is_read",
            "read_at",
            "organization",
            "organization_name",
            "metadata",
            "created_at",
        ]
        read_only_fields = fields


class NotificationDetailSerializer(serializers.ModelSerializer):
    """
    Serializer for detailed view of a single notification.
    """
    organization_slug = serializers.CharField(source="organization.slug", read_only=True, default=None)
    organization_name = serializers.CharField(source="organization.name", read_only=True, default=None)

    class Meta:
        model = Notification
        fields = [
            "id",
            "category",
            "priority",
            "channel",
            "title",
            "message",
            "is_read",
            "read_at",
            "is_deleted",
            "deleted_at",
            "organization",
            "organization_slug",
            "organization_name",
            "metadata",
            "created_at",
        ]
        read_only_fields = fields


class NotificationPreferenceSerializer(serializers.ModelSerializer):
    """
    Serializer for retrieving user notification preferences.
    """
    class Meta:
        model = NotificationPreference
        fields = [
            "email_notifications",
            "in_app_notifications",
            "security_notifications",
            "organization_notifications",
            "marketing_notifications",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["created_at", "updated_at"]


class UpdateNotificationPreferenceSerializer(serializers.ModelSerializer):
    """
    Serializer for updating user notification preferences.
    """
    class Meta:
        model = NotificationPreference
        fields = [
            "email_notifications",
            "in_app_notifications",
            "security_notifications",
            "organization_notifications",
            "marketing_notifications",
        ]


class MarkAsReadSerializer(serializers.Serializer):
    """
    Empty serializer for mark as read endpoint validation.
    """
    pass


class NotificationTemplateSerializer(serializers.ModelSerializer):
    """
    Serializer for managing notification templates in admin.
    """
    class Meta:
        model = NotificationTemplate
        fields = [
            "id",
            "name",
            "category",
            "channel",
            "subject",
            "title",
            "body",
            "is_active",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

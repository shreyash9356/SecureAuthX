"""
Serializers for the audit_logs API module.

These serializers are read-only.  No write operations are exposed.
"""

from rest_framework import serializers

from apps.audit_logs.models import AuditLog


class AuditLogUserSerializer(serializers.Serializer):
    """
    Minimal user representation embedded in an audit log record.
    """

    id = serializers.UUIDField(
        help_text="User's unique identifier.",
    )
    email = serializers.EmailField(
        help_text="User's email address.",
    )


class AuditLogSerializer(serializers.ModelSerializer):
    """
    Full read-only serializer for ``AuditLog`` records.

    The nested ``user`` field uses a slim representation to avoid
    exposing sensitive profile data.
    """

    user = AuditLogUserSerializer(
        read_only=True,
        allow_null=True,
        help_text="User who performed the action. Null for anonymous events.",
    )

    event_type_display = serializers.CharField(
        source="get_event_type_display",
        read_only=True,
        help_text="Human-readable event type label.",
    )

    status_display = serializers.CharField(
        source="get_status_display",
        read_only=True,
        help_text="Human-readable status label.",
    )

    class Meta:
        model = AuditLog
        fields = (
            "id",
            "user",
            "event_type",
            "event_type_display",
            "status",
            "status_display",
            "ip_address",
            "user_agent",
            "description",
            "metadata",
            "resource",
            "resource_id",
            "created_at",
        )
        read_only_fields = fields

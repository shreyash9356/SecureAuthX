"""
Serializers for the user_sessions API.
"""

from rest_framework import serializers

from apps.user_sessions.models import UserSession


class UserSessionSerializer(serializers.ModelSerializer):
    """
    Serializer for exposing UserSession details to clients.
    """

    class Meta:
        model = UserSession
        fields = [
            "id",
            "organization",
            "status",
            "ip_address",
            "device_type",
            "browser",
            "operating_system",
            "login_time",
            "last_activity",
            "logout_time",
            "expires_at",
            "revoked_at",
            "revocation_reason",
        ]
        read_only_fields = fields


class SessionRevokeSerializer(serializers.Serializer):
    """
    Serializer for administrative session revocation.
    """

    revocation_reason = serializers.CharField(
        required=True,
        allow_blank=False,
        max_length=500,
        help_text="Reason for administrative revocation of the session.",
    )

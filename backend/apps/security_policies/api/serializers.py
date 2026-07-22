from rest_framework import serializers
from apps.security_policies.models import SecurityPolicy


class SecurityPolicySerializer(serializers.ModelSerializer):
    """
    Serializer for viewing detailed SecurityPolicy attributes.
    """
    organization_slug = serializers.CharField(source="organization.slug", read_only=True, default=None)

    class Meta:
        model = SecurityPolicy
        fields = [
            "id",
            "name",
            "organization",
            "organization_slug",
            "is_active",
            # Password Policy
            "min_password_length",
            "max_password_length",
            "require_uppercase",
            "require_lowercase",
            "require_numeric",
            "require_special_char",
            "password_history_count",
            "password_expiration_days",
            # Account Lockout
            "max_failed_login_attempts",
            "lockout_duration_minutes",
            "auto_unlock_enabled",
            # Session Policy
            "max_concurrent_sessions",
            "session_absolute_timeout_minutes",
            "session_idle_timeout_minutes",
            "force_logout_on_password_change",
            # MFA Policy
            "require_mfa_for_admins",
            "require_mfa_for_all_org_members",
            "mfa_grace_period_days",
            # Login & Network
            "allowed_login_start_hour",
            "allowed_login_end_hour",
            "ip_allowlist",
            "ip_denylist",
            "country_denylist",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class SecurityPolicyUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating SecurityPolicy settings.
    """
    class Meta:
        model = SecurityPolicy
        fields = [
            "name",
            "is_active",
            "min_password_length",
            "max_password_length",
            "require_uppercase",
            "require_lowercase",
            "require_numeric",
            "require_special_char",
            "password_history_count",
            "password_expiration_days",
            "max_failed_login_attempts",
            "lockout_duration_minutes",
            "auto_unlock_enabled",
            "max_concurrent_sessions",
            "session_absolute_timeout_minutes",
            "session_idle_timeout_minutes",
            "force_logout_on_password_change",
            "require_mfa_for_admins",
            "require_mfa_for_all_org_members",
            "mfa_grace_period_days",
            "allowed_login_start_hour",
            "allowed_login_end_hour",
            "ip_allowlist",
            "ip_denylist",
            "country_denylist",
        ]


class PasswordPolicyCheckSerializer(serializers.Serializer):
    """
    Serializer for testing a raw password against the active security policy.
    """
    password = serializers.CharField(write_only=True)

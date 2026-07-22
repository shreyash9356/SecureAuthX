from django.contrib import admin
from apps.security_policies.models import SecurityPolicy, PasswordHistory


@admin.register(SecurityPolicy)
class SecurityPolicyAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "organization",
        "is_active",
        "min_password_length",
        "max_failed_login_attempts",
        "lockout_duration_minutes",
        "max_concurrent_sessions",
        "require_mfa_for_admins",
        "updated_at",
    )
    list_filter = (
        "is_active",
        "require_uppercase",
        "require_lowercase",
        "require_numeric",
        "require_special_char",
        "require_mfa_for_admins",
        "require_mfa_for_all_org_members",
        "auto_unlock_enabled",
    )
    search_fields = (
        "name",
        "organization__name",
        "organization__slug",
    )
    raw_id_fields = ("organization",)
    readonly_fields = ("id", "created_at", "updated_at")
    fieldsets = (
        ("Policy Overview", {
            "fields": ("id", "name", "organization", "is_active")
        }),
        ("Password Controls", {
            "fields": (
                "min_password_length",
                "max_password_length",
                "require_uppercase",
                "require_lowercase",
                "require_numeric",
                "require_special_char",
                "password_history_count",
                "password_expiration_days",
            )
        }),
        ("Lockout Controls", {
            "fields": (
                "max_failed_login_attempts",
                "lockout_duration_minutes",
                "auto_unlock_enabled",
            )
        }),
        ("Session Controls", {
            "fields": (
                "max_concurrent_sessions",
                "session_absolute_timeout_minutes",
                "session_idle_timeout_minutes",
                "force_logout_on_password_change",
            )
        }),
        ("MFA Controls", {
            "fields": (
                "require_mfa_for_admins",
                "require_mfa_for_all_org_members",
                "mfa_grace_period_days",
            )
        }),
        ("Network & Risk Controls", {
            "fields": (
                "allowed_login_start_hour",
                "allowed_login_end_hour",
                "ip_allowlist",
                "ip_denylist",
                "country_denylist",
            )
        }),
        ("Timestamps", {
            "fields": ("created_at", "updated_at")
        }),
    )


@admin.register(PasswordHistory)
class PasswordHistoryAdmin(admin.ModelAdmin):
    list_display = ("user", "created_at")
    search_fields = ("user__email",)
    raw_id_fields = ("user",)
    readonly_fields = ("id", "user", "password_hash", "created_at")

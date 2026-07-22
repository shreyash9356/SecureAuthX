import uuid
from django.conf import settings
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator

from apps.organizations.models import Organization


class SecurityPolicy(models.Model):
    """
    Enterprise Security Policy Model.
    
    Defines configurable password controls, lockout parameters, session limits,
    MFA mandates, and network access restrictions.
    Supports organization-level multi-tenant policies with global default fallback.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    name = models.CharField(
        max_length=100,
        help_text="Descriptive policy identifier, e.g. 'Global Security Policy' or 'Acme Corp Policy'.",
    )

    organization = models.OneToOneField(
        Organization,
        on_delete=models.CASCADE,
        related_name="security_policy",
        null=True,
        blank=True,
        help_text="Associated organization for tenant-scoped policies. Null designates global default policy.",
    )

    is_active = models.BooleanField(
        default=True,
        help_text="Designates whether this policy is actively enforced.",
    )

    # --------------------------------------------------------------------------
    # 1. Password Policy Controls
    # --------------------------------------------------------------------------

    min_password_length = models.PositiveIntegerField(
        default=12,
        validators=[MinValueValidator(8), MaxValueValidator(128)],
        help_text="Minimum character count for user passwords.",
    )

    max_password_length = models.PositiveIntegerField(
        default=128,
        validators=[MinValueValidator(16), MaxValueValidator(256)],
        help_text="Maximum character length for user passwords.",
    )

    require_uppercase = models.BooleanField(
        default=True,
        help_text="Requires at least one uppercase letter (A-Z).",
    )

    require_lowercase = models.BooleanField(
        default=True,
        help_text="Requires at least one lowercase letter (a-z).",
    )

    require_numeric = models.BooleanField(
        default=True,
        help_text="Requires at least one numeric digit (0-9).",
    )

    require_special_char = models.BooleanField(
        default=True,
        help_text="Requires at least one special character (!@#$%^&*...).",
    )

    password_history_count = models.PositiveIntegerField(
        default=5,
        validators=[MaxValueValidator(24)],
        help_text="Number of previous password hashes to retain and prevent reuse.",
    )

    password_expiration_days = models.PositiveIntegerField(
        default=90,
        help_text="Days before user password expires and requires change. 0 disables expiration.",
    )

    # --------------------------------------------------------------------------
    # 2. Account Lockout Policies
    # --------------------------------------------------------------------------

    max_failed_login_attempts = models.PositiveIntegerField(
        default=5,
        validators=[MinValueValidator(1), MaxValueValidator(20)],
        help_text="Maximum consecutive failed login attempts before locking account.",
    )

    lockout_duration_minutes = models.PositiveIntegerField(
        default=15,
        help_text="Duration in minutes an account remains locked.",
    )

    auto_unlock_enabled = models.BooleanField(
        default=True,
        help_text="If enabled, accounts auto-unlock after lockout_duration_minutes expires.",
    )

    # --------------------------------------------------------------------------
    # 3. Session Policies
    # --------------------------------------------------------------------------

    max_concurrent_sessions = models.PositiveIntegerField(
        default=5,
        help_text="Maximum active user sessions allowed simultaneously. 0 = unlimited.",
    )

    session_absolute_timeout_minutes = models.PositiveIntegerField(
        default=1440,
        help_text="Maximum absolute session duration in minutes (e.g. 1440 = 24 hours).",
    )

    session_idle_timeout_minutes = models.PositiveIntegerField(
        default=60,
        help_text="Maximum inactivity idle time in minutes before session invalidation.",
    )

    force_logout_on_password_change = models.BooleanField(
        default=True,
        help_text="Revokes all active sessions upon password reset or modification.",
    )

    # --------------------------------------------------------------------------
    # 4. MFA Policies
    # --------------------------------------------------------------------------

    require_mfa_for_admins = models.BooleanField(
        default=True,
        help_text="Mandates TOTP MFA for all administrator users.",
    )

    require_mfa_for_all_org_members = models.BooleanField(
        default=False,
        help_text="Mandates TOTP MFA for all members in the organization.",
    )

    mfa_grace_period_days = models.PositiveIntegerField(
        default=7,
        help_text="Days allowed for new users to configure MFA before access is blocked.",
    )

    # --------------------------------------------------------------------------
    # 5. Network & Login Policies
    # --------------------------------------------------------------------------

    allowed_login_start_hour = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(23)],
        help_text="UTC start hour (0-23) for permitted logins. Null = unrestricted.",
    )

    allowed_login_end_hour = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(23)],
        help_text="UTC end hour (0-23) for permitted logins. Null = unrestricted.",
    )

    ip_allowlist = models.JSONField(
        default=list,
        blank=True,
        help_text="List of allowed IP addresses or CIDR blocks, e.g. ['192.168.1.0/24'].",
    )

    ip_denylist = models.JSONField(
        default=list,
        blank=True,
        help_text="List of explicitly blocked IP addresses or CIDR blocks.",
    )

    country_denylist = models.JSONField(
        default=list,
        blank=True,
        help_text="List of blocked ISO 2-letter country codes, e.g. ['CN', 'RU'].",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Security Policy"
        verbose_name_plural = "Security Policies"
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["organization"]),
            models.Index(fields=["is_active"]),
        ]

    def __str__(self):
        scope = self.organization.slug if self.organization else "Global Default"
        return f"{self.name} [{scope}]"


class PasswordHistory(models.Model):
    """
    Tracks previous Argon2/PBKDF2 password hashes for users to prevent password reuse.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="password_history",
    )

    password_hash = models.CharField(
        max_length=255,
        help_text="Hashed password string.",
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Password History"
        verbose_name_plural = "Password Histories"
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["user", "-created_at"]),
        ]

    def __str__(self):
        return f"PasswordHistory - User: {self.user.email} ({self.created_at})"

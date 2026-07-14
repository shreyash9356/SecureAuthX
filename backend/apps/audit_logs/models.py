"""
Audit Log model for SecureAuthX.

Every security-relevant event across the platform is persisted here.
Records are intentionally immutable — no update/delete endpoints exist.
"""

import uuid

from django.conf import settings
from django.db import models


class AuditLog(models.Model):
    """
    Immutable record of a security or domain event.

    Design decisions
    ----------------
    - UUID primary key prevents sequential ID enumeration attacks.
    - ``user`` is nullable so unauthenticated events (e.g. failed
      login for unknown email) can still be recorded.
    - ``SET_NULL`` on user deletion preserves the audit trail even
      after a user account is removed.
    - ``metadata`` (JSONField) accepts arbitrary structured context
      without requiring schema migrations for every new event type.
    - No ``updated_at`` field — records must never be modified.
    """

    # ===========================================================================
    # Choices
    # ===========================================================================

    class EventType(models.TextChoices):
        """All supported audit event types grouped by domain."""

        # ── Authentication ─────────────────────────────────────────────────────
        REGISTER = "REGISTER", "Register"
        LOGIN_SUCCESS = "LOGIN_SUCCESS", "Login Success"
        LOGIN_FAILED = "LOGIN_FAILED", "Login Failed"
        LOGOUT = "LOGOUT", "Logout"
        EMAIL_VERIFIED = "EMAIL_VERIFIED", "Email Verified"
        EMAIL_VERIFICATION_SENT = "EMAIL_VERIFICATION_SENT", "Email Verification Sent"
        PASSWORD_CHANGED = "PASSWORD_CHANGED", "Password Changed"
        PASSWORD_RESET_REQUESTED = (
            "PASSWORD_RESET_REQUESTED",
            "Password Reset Requested",
        )
        PASSWORD_RESET = "PASSWORD_RESET", "Password Reset"
        TOKEN_REFRESHED = "TOKEN_REFRESHED", "Token Refreshed"
        ACCOUNT_LOCKED = "ACCOUNT_LOCKED", "Account Locked"
        ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED", "Account Unlocked"

        # ── Organizations ──────────────────────────────────────────────────────
        ORGANIZATION_CREATED = "ORGANIZATION_CREATED", "Organization Created"
        ORGANIZATION_UPDATED = "ORGANIZATION_UPDATED", "Organization Updated"
        ORGANIZATION_DELETED = "ORGANIZATION_DELETED", "Organization Deleted"

        # ── Roles ──────────────────────────────────────────────────────────────
        ROLE_CREATED = "ROLE_CREATED", "Role Created"
        ROLE_UPDATED = "ROLE_UPDATED", "Role Updated"
        ROLE_DELETED = "ROLE_DELETED", "Role Deleted"
        ROLE_ASSIGNED = "ROLE_ASSIGNED", "Role Assigned"
        ROLE_REMOVED = "ROLE_REMOVED", "Role Removed"

        # ── Permissions ────────────────────────────────────────────────────────
        PERMISSION_CREATED = "PERMISSION_CREATED", "Permission Created"
        PERMISSION_UPDATED = "PERMISSION_UPDATED", "Permission Updated"
        PERMISSION_DELETED = "PERMISSION_DELETED", "Permission Deleted"
        PERMISSION_ASSIGNED = "PERMISSION_ASSIGNED", "Permission Assigned"
        PERMISSION_REMOVED = "PERMISSION_REMOVED", "Permission Removed"

        # ── MFA ────────────────────────────────────────────────────────────────
        MFA_ENABLED = "MFA_ENABLED", "MFA Enabled"
        MFA_DISABLED = "MFA_DISABLED", "MFA Disabled"

        # ── User Sessions ──────────────────────────────────────────────────────
        SESSION_CREATED = "SESSION_CREATED", "Session Created"
        SESSION_REVOKED = "SESSION_REVOKED", "Session Revoked"

    class Status(models.TextChoices):
        """Outcome of the event."""

        SUCCESS = "SUCCESS", "Success"
        FAILURE = "FAILURE", "Failure"
        WARNING = "WARNING", "Warning"
        INFO = "INFO", "Info"

    # ===========================================================================
    # Fields
    # ===========================================================================

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
        help_text="User who performed the action. Null for unauthenticated events.",
    )

    event_type = models.CharField(
        max_length=64,
        choices=EventType.choices,
        db_index=True,
    )

    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.INFO,
        db_index=True,
    )

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="Client IP address extracted from the HTTP request.",
    )

    user_agent = models.TextField(
        blank=True,
        default="",
        help_text="Client User-Agent string from the HTTP request.",
    )

    description = models.TextField(
        blank=True,
        default="",
        help_text="Human-readable summary of what occurred.",
    )

    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text="Arbitrary structured context for the event.",
    )

    resource = models.CharField(
        max_length=128,
        blank=True,
        default="",
        help_text="Resource type affected by the event (e.g. 'User', 'Role').",
    )

    resource_id = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Identifier of the affected resource.",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    # ===========================================================================
    # Meta
    # ===========================================================================

    class Meta:
        db_table = "audit_logs"
        ordering = ["-created_at"]
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"

    # ===========================================================================
    # Dunder
    # ===========================================================================

    def __str__(self) -> str:
        user_label = self.user.email if self.user_id else "anonymous"
        return f"[{self.status}] {self.event_type} — {user_label} @ {self.created_at:%Y-%m-%d %H:%M:%S}"

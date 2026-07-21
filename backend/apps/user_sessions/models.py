"""
UserSession model for SecureAuthX.

Tracks every authenticated session across the platform.
Records are never deleted — status transitions handle the full lifecycle.

Design decisions
----------------
- UUID primary key is the public session identifier (no separate session_key).
- No JWT, refresh token, or credentials are stored here.
- ``revoked_by`` / ``revoked_at`` / ``revocation_reason`` support forced
  administrative termination with a full audit trail.
- ``organization`` is optional — supports future concurrent-session limits
  per tenant without breaking the single-user use case.
- ``last_activity`` enables sliding expiry, suspicious session detection,
  and impossible-travel analysis.
- Device / browser / operating_system fields are parsed from the User-Agent
  at session creation and stored as plain strings; never re-parsed at read time.

CheckConstraints
----------------
Three DB-level constraints enforce lifecycle consistency:

1. ``chk_usess_logout_time_requires_logged_out``
   ``logout_time`` may only be non-null when status is LOGGED_OUT.
   Prevents accidental population of logout_time on active/revoked/expired rows.

2. ``chk_usess_revoked_fields_require_revoked``
   ``revoked_at`` may only be non-null when status is REVOKED.
   Mirrors the same constraint for the revocation timestamp.

3. ``chk_usess_last_activity_not_before_login``
   ``last_activity`` must be >= ``login_time``.
   Guards against clock-skew or service bugs that would produce impossible
   activity timestamps earlier than the login timestamp.
"""

import uuid

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone


class UserSession(models.Model):
    """
    Represents a single authenticated session for a user.

    Lifecycle
    ---------
    ACTIVE → LOGGED_OUT  (voluntary logout)
    ACTIVE → REVOKED     (administrative revocation)
    ACTIVE → EXPIRED     (passive TTL expiry, no explicit logout)
    """

    # ===========================================================================
    # Choices
    # ===========================================================================

    class Status(models.TextChoices):
        """Session lifecycle state."""

        ACTIVE      = "ACTIVE",      "Active"
        LOGGED_OUT  = "LOGGED_OUT",  "Logged Out"
        REVOKED     = "REVOKED",     "Revoked"
        EXPIRED     = "EXPIRED",     "Expired"

    class DeviceType(models.TextChoices):
        """Broad device category derived from the User-Agent at login time."""

        DESKTOP = "DESKTOP", "Desktop"
        MOBILE  = "MOBILE",  "Mobile"
        TABLET  = "TABLET",  "Tablet"
        UNKNOWN = "UNKNOWN", "Unknown"

    # ===========================================================================
    # Identity
    # ===========================================================================

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text=(
            "Opaque public session identifier. "
            "Exposed to clients instead of internal DB surrogate keys."
        ),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="sessions",
        db_index=True,
        help_text="The authenticated user this session belongs to.",
    )

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="user_sessions",
        db_index=True,
        help_text=(
            "Organization context for the session. "
            "Null for platform-level (non-tenant) sessions. "
            "Supports future concurrent-session limits per tenant."
        ),
    )

    # ===========================================================================
    # Lifecycle
    # ===========================================================================

    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.ACTIVE,
        db_index=True,
        help_text="Current lifecycle state of the session.",
    )

    # ===========================================================================
    # Network context (set once at creation, never updated)
    # ===========================================================================

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text=(
            "Client IP address at login time. "
            "Extracted from X-Forwarded-For or REMOTE_ADDR. "
            "Used for impossible-travel and suspicious login detection."
        ),
    )

    user_agent = models.TextField(
        blank=True,
        default="",
        help_text="Raw User-Agent header string captured at login time.",
    )

    # ===========================================================================
    # Device information (parsed from user_agent at creation)
    # ===========================================================================

    device_type = models.CharField(
        max_length=16,
        choices=DeviceType.choices,
        default=DeviceType.UNKNOWN,
        help_text=(
            "Broad device category derived from User-Agent "
            "(Desktop / Mobile / Tablet / Unknown)."
        ),
    )

    browser = models.CharField(
        max_length=128,
        blank=True,
        default="",
        help_text=(
            "Browser name and major version parsed from User-Agent "
            "(e.g. 'Chrome 124')."
        ),
    )

    operating_system = models.CharField(
        max_length=128,
        blank=True,
        default="",
        help_text=(
            "Operating system name parsed from User-Agent "
            "(e.g. 'Windows 11', 'iOS 17')."
        ),
    )

    # ===========================================================================
    # Temporal tracking
    # ===========================================================================

    login_time = models.DateTimeField(
        default=timezone.now,
        help_text=(
            "Timestamp when this session was established "
            "(user authenticated successfully)."
        ),
    )

    last_activity = models.DateTimeField(
        default=timezone.now,
        db_index=True,
        help_text=(
            "Timestamp of the most recent authenticated request in this session. "
            "Updated by the session middleware on every valid API call. "
            "Used for sliding expiry and suspicious activity detection."
        ),
    )

    logout_time = models.DateTimeField(
        null=True,
        blank=True,
        help_text=(
            "Timestamp when the user explicitly logged out. "
            "Null until a voluntary logout occurs. "
            "Must be non-null when status is LOGGED_OUT."
        ),
    )

    expires_at = models.DateTimeField(
        db_index=True,
        help_text=(
            "Hard expiry timestamp for this session, aligned with the "
            "JWT refresh token lifetime. Sessions are considered EXPIRED "
            "after this point regardless of activity."
        ),
    )

    # ===========================================================================
    # Revocation (administrative forced termination)
    # ===========================================================================

    revoked_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=(
            "Timestamp when an administrator forcibly revoked this session. "
            "Must be non-null when status is REVOKED."
        ),
    )

    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="revoked_sessions",
        help_text=(
            "The staff user who revoked this session. "
            "Null for self-revocation (logout) or TTL expiry."
        ),
    )

    revocation_reason = models.TextField(
        blank=True,
        default="",
        help_text=(
            "Human-readable explanation for why the session was forcibly terminated. "
            "Required for compliance audit trails when revoked by an administrator."
        ),
    )

    # ===========================================================================
    # Audit timestamps
    # ===========================================================================

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    # ===========================================================================
    # Meta
    # ===========================================================================

    class Meta:
        db_table = "user_sessions"
        verbose_name = "User Session"
        verbose_name_plural = "User Sessions"
        ordering = ["-login_time"]

        indexes = [
            # ── Single-column ──────────────────────────────────────────────────
            models.Index(fields=["user"],          name="idx_usess_user"),
            models.Index(fields=["organization"],  name="idx_usess_org"),
            models.Index(fields=["status"],        name="idx_usess_status"),
            models.Index(fields=["expires_at"],    name="idx_usess_expires_at"),
            models.Index(fields=["last_activity"], name="idx_usess_last_activity"),

            # ── Composite ─────────────────────────────────────────────────────
            # "All active sessions for a user" — list-sessions + concurrent-limit
            models.Index(
                fields=["user", "status"],
                name="idx_usess_user_status",
            ),
            # "All sessions for a tenant" — organization-scoped management
            models.Index(
                fields=["organization", "status"],
                name="idx_usess_org_status",
            ),
            # "Sessions eligible for passive expiry sweep"
            models.Index(
                fields=["status", "expires_at"],
                name="idx_usess_status_expires",
            ),
        ]

        constraints = [
            # ── Lifecycle consistency ─────────────────────────────────────────

            # logout_time must only be set when the session is LOGGED_OUT.
            # Prevents service bugs from populating logout_time on rows that
            # were revoked or expired rather than explicitly logged out.
            models.CheckConstraint(
                condition=(
                    Q(logout_time__isnull=True)
                    | Q(status="LOGGED_OUT")
                ),
                name="chk_usess_logout_time_requires_logged_out",
            ),

            # revoked_at must only be set when the session is REVOKED.
            # Mirrors the same integrity rule for the revocation timestamp.
            models.CheckConstraint(
                condition=(
                    Q(revoked_at__isnull=True)
                    | Q(status="REVOKED")
                ),
                name="chk_usess_revoked_at_requires_revoked",
            ),

            # last_activity must be >= login_time.
            # Guards against clock-skew or bugs producing impossible timestamps.
            models.CheckConstraint(
                condition=Q(last_activity__gte=models.F("login_time")),
                name="chk_usess_last_activity_not_before_login",
            ),
        ]

    # ===========================================================================
    # Dunder
    # ===========================================================================

    def __str__(self) -> str:
        # Prefer email; fall back to username; last resort is the raw UUID.
        user_label = (
            getattr(self, "_user_cache", None)
            and (
                getattr(self._user_cache, "email", None)
                or getattr(self._user_cache, "username", None)
            )
        ) or str(self.user_id)

        # Use the cached user FK attribute when available (avoids extra query).
        if self.user_id:
            try:
                user_obj = self.user  # hits FK cache; no extra query if prefetched
                user_label = (
                    getattr(user_obj, "email", None)
                    or getattr(user_obj, "username", None)
                    or str(self.user_id)
                )
            except Exception:  # noqa: BLE001
                user_label = str(self.user_id)

        return (
            f"[{self.status}] {user_label} | "
            f"{self.device_type} | "
            f"{self.ip_address or 'unknown IP'} | "
            f"login={self.login_time:%Y-%m-%d %H:%M:%S}"
        )

    # ===========================================================================
    # Helper properties
    # ===========================================================================

    @property
    def is_active(self) -> bool:
        """
        Return True only when the session is in the ACTIVE state.

        Does NOT perform a real-time TTL check — that belongs in a service.
        Use this only for quick in-memory status reads.
        """
        return self.status == self.Status.ACTIVE

    @property
    def is_expired(self) -> bool:
        """
        Return True when the hard expiry timestamp has passed.

        Read-only — for display and serialization only.
        Transitioning the DB status to EXPIRED is the service's responsibility.
        """
        return timezone.now() >= self.expires_at

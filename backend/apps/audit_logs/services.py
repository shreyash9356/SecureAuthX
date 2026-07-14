"""
Audit Log service for SecureAuthX.

Single public entry point: ``AuditLogService.log()``.

Design decisions
----------------
- **Never crashes the caller.**  All internal exceptions are caught,
  logged via Python's standard ``logging`` module, and swallowed.
  An audit-logging failure must never interrupt a user-facing request.
- **Fire-and-forget semantics** from the caller's perspective.  The
  return value is the created ``AuditLog`` instance (or ``None`` on
  failure), but callers are not required to use it.
- IP address and User-Agent are extracted automatically from the
  request object when provided, so callers don't have to.
- ``metadata`` accepts any JSON-serialisable dict, making the service
  forward-compatible with new event types without schema changes.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from apps.audit_logs.models import AuditLog
from apps.audit_logs.utils import get_client_ip, get_user_agent

if TYPE_CHECKING:
    from rest_framework.request import Request

logger = logging.getLogger(__name__)


class AuditLogService:
    """
    Central service for creating audit log entries.

    All authentication services, API views, and background tasks
    should call ``AuditLogService.log()`` — never instantiate
    ``AuditLog`` directly outside of this service.
    """

    @staticmethod
    def log(
        *,
        event_type: str,
        status: str,
        description: str,
        user=None,
        request: "Request | None" = None,
        metadata: dict[str, Any] | None = None,
        resource: str = "",
        resource_id: str = "",
    ) -> AuditLog | None:
        """
        Create and persist an ``AuditLog`` record.

        This method is intentionally non-atomic — audit log writes
        are independent of the business transaction that triggered them.
        If the caller's transaction rolls back, the audit log entry
        is still committed (assuming it was called after the save).

        Args:
            event_type:   One of ``AuditLog.EventType`` values.
            status:       One of ``AuditLog.Status`` values.
            description:  Human-readable summary of the event.
            user:         The ``User`` instance responsible for the event.
                          Pass ``None`` for unauthenticated events.
            request:      The current HTTP request.  Used to extract
                          IP address and User-Agent automatically.
                          Pass ``None`` when logging outside a request.
            metadata:     Arbitrary JSON-serialisable dict for extra context.
            resource:     Resource type name (e.g. ``"User"``, ``"Role"``).
            resource_id:  String identifier of the affected resource.

        Returns:
            The created ``AuditLog`` instance, or ``None`` if an internal
            error prevented the record from being saved.
        """
        try:
            audit_log = AuditLog.objects.create(
                user=user,
                event_type=event_type,
                status=status,
                description=description,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request),
                metadata=metadata or {},
                resource=resource,
                resource_id=str(resource_id) if resource_id else "",
            )
            return audit_log

        except Exception:  # noqa: BLE001
            logger.exception(
                "AuditLogService.log() failed silently. "
                "event_type=%s status=%s user=%s",
                event_type,
                status,
                getattr(user, "email", None),
            )
            return None

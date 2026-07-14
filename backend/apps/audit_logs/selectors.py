"""
Read-only data access layer for the audit_logs module.

Selectors encapsulate all query logic so that views and serializers
stay thin and testable without touching ORM syntax directly.
"""

from __future__ import annotations

from django.db.models import QuerySet

from apps.audit_logs.models import AuditLog


class AuditLogSelector:
    """
    Read-only query helpers for ``AuditLog`` records.

    All methods return un-evaluated ``QuerySet`` objects so callers
    can chain additional filters, apply pagination, or pass them
    directly to serializers.
    """

    @staticmethod
    def get_all() -> QuerySet[AuditLog]:
        """
        Return all audit log records ordered newest-first.

        Returns:
            QuerySet of all ``AuditLog`` instances.
        """
        return AuditLog.objects.select_related("user").order_by("-created_at")

    @staticmethod
    def get_by_id(audit_log_id: str) -> AuditLog:
        """
        Return a single ``AuditLog`` by its UUID primary key.

        Args:
            audit_log_id: UUID string of the audit log record.

        Returns:
            The matching ``AuditLog`` instance.

        Raises:
            AuditLog.DoesNotExist: If no record with that ID exists.
        """
        return AuditLog.objects.select_related("user").get(id=audit_log_id)

    @staticmethod
    def get_by_user(user) -> QuerySet[AuditLog]:
        """
        Return all audit log records for a specific user.

        Args:
            user: A ``User`` instance.

        Returns:
            Filtered QuerySet of ``AuditLog`` instances.
        """
        return (
            AuditLog.objects.select_related("user")
            .filter(user=user)
            .order_by("-created_at")
        )

    @staticmethod
    def get_by_event_type(event_type: str) -> QuerySet[AuditLog]:
        """
        Return all audit log records for a specific event type.

        Args:
            event_type: One of ``AuditLog.EventType`` values.

        Returns:
            Filtered QuerySet of ``AuditLog`` instances.
        """
        return (
            AuditLog.objects.select_related("user")
            .filter(event_type=event_type)
            .order_by("-created_at")
        )

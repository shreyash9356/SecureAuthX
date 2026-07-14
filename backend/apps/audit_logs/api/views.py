"""
API views for the audit_logs module.

Read-only. Admin staff access only.
Supports filtering, search, and ordering via django-filter + DRF.
"""

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.audit_logs.api.serializers import AuditLogSerializer
from apps.audit_logs.exceptions import AuditLogNotFoundException
from apps.audit_logs.models import AuditLog
from apps.audit_logs.permissions import IsAdminUser
from apps.audit_logs.selectors import AuditLogSelector
from apps.authentication.utils import success_response


class AuditLogListAPIView(APIView):
    """
    GET /api/v1/audit-logs/

    Returns a paginated, filterable, searchable list of all audit logs.
    Access restricted to authenticated staff users.
    """

    permission_classes = [IsAdminUser]

    # ── Filter / search / order backends ──────────────────────────────────────
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ["status", "event_type"]
    search_fields = ["user__email", "description", "event_type"]
    ordering_fields = ["created_at", "event_type", "status"]
    ordering = ["-created_at"]

    def get(self, request) -> Response:
        """
        List all audit log records.

        Supports:
        - ``?search=<term>``   — search across user email, description, event type
        - ``?status=SUCCESS``  — filter by status
        - ``?event_type=LOGIN_SUCCESS`` — filter by event type
        - ``?ordering=-created_at``    — custom ordering
        """
        queryset = AuditLogSelector.get_all()

        # Apply DRF filter/search/ordering backends manually on APIView.
        for backend in self.filter_backends:
            queryset = backend().filter_queryset(request, queryset, self)

        # Paginate
        from rest_framework.pagination import PageNumberPagination

        paginator = PageNumberPagination()
        paginator.page_size = 20
        page = paginator.paginate_queryset(queryset, request)

        serializer = AuditLogSerializer(page, many=True)

        # Build the standard response envelope and embed the pagination
        # meta (count, next, previous) at the top level alongside it.
        data = success_response(
            message="Audit logs retrieved successfully.",
            data=serializer.data,
        )
        response = paginator.get_paginated_response(data)
        return response


class AuditLogDetailAPIView(APIView):
    """
    GET /api/v1/audit-logs/{id}/

    Returns a single audit log record by its UUID.
    Access restricted to authenticated staff users.
    """

    permission_classes = [IsAdminUser]

    def get(self, request, pk: str) -> Response:
        """
        Retrieve a single audit log entry.

        Args:
            pk: UUID string of the audit log record.
        """
        try:
            audit_log = AuditLogSelector.get_by_id(pk)
        except AuditLog.DoesNotExist as exc:
            raise AuditLogNotFoundException() from exc

        serializer = AuditLogSerializer(audit_log)

        return Response(
            success_response(
                message="Audit log retrieved successfully.",
                data=serializer.data,
            ),
            status=status.HTTP_200_OK,
        )

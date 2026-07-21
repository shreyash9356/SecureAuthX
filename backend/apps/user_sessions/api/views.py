"""
API Views for the user_sessions module.
"""

from drf_spectacular.utils import extend_schema, OpenApiParameter
from rest_framework import status
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response

from apps.authorization.permissions import IsAdmin
from apps.common.pagination import StandardPageNumberPagination
from apps.common.responses import success_response, error_response
from apps.user_sessions.api.serializers import (
    UserSessionSerializer,
    SessionRevokeSerializer,
)
from apps.user_sessions.selectors.session_selector import SessionSelector
from apps.user_sessions.services.session_service import SessionService
from apps.user_sessions.models import UserSession


class SessionListAPIView(APIView):
    """
    API endpoint to list active, non-expired sessions.

    - Authenticated users can list their own active sessions.
    - Administrators can list active sessions for an organization by passing `organization_id`.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="List Active Sessions",
        description="Retrieve a list of active, non-expired sessions for the authenticated user, or for an organization if requestor is an admin.",
        tags=["User Sessions"],
        parameters=[
            OpenApiParameter(
                "organization_id",
                description="Filter sessions by organization context (Administrators only).",
                required=False,
                type=str,
            ),
        ],
        responses={200: UserSessionSerializer(many=True)},
    )
    def get(self, request):
        organization_id = request.query_params.get("organization_id")

        if organization_id:
            # Check permissions for viewing organization sessions
            is_admin = IsAdmin().has_permission(request, self)
            if not is_admin:
                raise PermissionDenied(
                    "You do not have permission to view organization sessions."
                )
            queryset = SessionSelector.list_active_sessions_for_organization(
                organization_id
            )
        else:
            queryset = SessionSelector.list_active_sessions_for_user(request.user)

        paginator = StandardPageNumberPagination()
        page = paginator.paginate_queryset(queryset, request, view=self)
        if page is not None:
            serializer = UserSessionSerializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)

        serializer = UserSessionSerializer(queryset, many=True)
        return success_response(
            data=serializer.data,
            message="Active sessions retrieved successfully.",
        )


class SessionDetailAPIView(APIView):
    """
    API endpoint to retrieve details of a specific session.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Get Session Details",
        description="Retrieve session metadata for a specific session ID. Users can only view their own sessions unless they are administrators.",
        tags=["User Sessions"],
        responses={200: UserSessionSerializer, 404: dict},
    )
    def get(self, request, session_id):
        try:
            # Admin role bypass check
            is_admin = IsAdmin().has_permission(request, self)
            if is_admin:
                session = SessionSelector.get_session_by_id(session_id)
            else:
                session = SessionSelector.get_active_session_by_id_and_user(
                    session_id, request.user
                )
        except UserSession.DoesNotExist:
            raise NotFound("Session not found or is inactive.")

        serializer = UserSessionSerializer(session)
        return success_response(
            data=serializer.data,
            message="Session details retrieved successfully.",
        )


class LogoutCurrentSessionAPIView(APIView):
    """
    API endpoint to log out the current session.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Logout Current Session",
        description="Terminate the current active session associated with the bearer token.",
        tags=["User Sessions"],
        responses={200: dict, 400: dict},
    )
    def post(self, request):
        session = getattr(request, "user_session", None)
        if not session:
            return error_response(
                errors={"detail": "No active session associated with this request."},
                message="Logout failed.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        SessionService.logout_session(session)
        return success_response(
            data={},
            message="Current session logged out successfully.",
        )


class LogoutAllSessionsAPIView(APIView):
    """
    API endpoint to log out all sessions for the authenticated user.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Logout All Other Sessions",
        description="Terminate all active sessions for the authenticated user, optionally preserving the current request's session.",
        tags=["User Sessions"],
        responses={200: dict},
    )
    def post(self, request):
        current_session = getattr(request, "user_session", None)
        terminated_count = SessionService.logout_all_sessions(
            request.user, exclude_session=current_session
        )

        return success_response(
            data={"terminated_count": terminated_count},
            message="All other sessions logged out successfully.",
        )


class RevokeSessionAPIView(APIView):
    """
    API endpoint for administrators to revoke a specific session.
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    @extend_schema(
        summary="Revoke User Session",
        description="Forcibly terminate a session. Restricted to administrators and super administrators.",
        tags=["User Sessions"],
        request=SessionRevokeSerializer,
        responses={200: UserSessionSerializer, 400: dict, 404: dict},
    )
    def post(self, request, session_id):
        serializer = SessionRevokeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        reason = serializer.validated_data["revocation_reason"]

        try:
            session = SessionSelector.get_session_by_id(session_id)
        except UserSession.DoesNotExist:
            raise NotFound("Session not found.")

        updated_session = SessionService.revoke_session(
            session, revoked_by=request.user, revocation_reason=reason
        )

        return success_response(
            data=UserSessionSerializer(updated_session).data,
            message="Session revoked successfully.",
        )

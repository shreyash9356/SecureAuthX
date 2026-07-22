from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination

from apps.notifications.selectors import (
    get_notification_by_id,
    get_user_notifications,
    get_notification_preferences,
)
from apps.notifications.services.notification_service import NotificationService
from apps.notifications.api.serializers import (
    NotificationSerializer,
    NotificationDetailSerializer,
    NotificationPreferenceSerializer,
    UpdateNotificationPreferenceSerializer,
)
from apps.notifications.api.schema import (
    notification_list_schema,
    notification_detail_schema,
    notification_delete_schema,
    notification_read_schema,
    notification_read_all_schema,
    notification_preference_get_schema,
    notification_preference_patch_schema,
)


class StandardNotificationPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100


class NotificationListAPIView(APIView):
    """
    GET /api/v1/notifications/
    List active notifications for the authenticated user with optional filters.
    """
    permission_classes = [IsAuthenticated]
    pagination_class = StandardNotificationPagination

    @notification_list_schema
    def get(self, request):
        category = request.query_params.get("category")
        priority = request.query_params.get("priority")
        is_read_param = request.query_params.get("is_read")

        is_read = None
        if is_read_param is not None:
            is_read = is_read_param.lower() in ["true", "1"]

        notifications_qs = get_user_notifications(
            request.user,
            category=category,
            priority=priority,
            is_read=is_read,
        )

        paginator = self.pagination_class()
        paginated_qs = paginator.paginate_queryset(notifications_qs, request)
        serializer = NotificationSerializer(paginated_qs, many=True)

        return paginator.get_paginated_response(serializer.data)


class NotificationDetailAPIView(APIView):
    """
    GET /api/v1/notifications/{id}/
    DELETE /api/v1/notifications/{id}/
    """
    permission_classes = [IsAuthenticated]

    @notification_detail_schema
    def get(self, request, pk):
        notification = get_notification_by_id(notification_id=pk, user=request.user)
        serializer = NotificationDetailSerializer(notification)
        return Response(
            {
                "success": True,
                "message": "Notification details retrieved.",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )

    @notification_delete_schema
    def delete(self, request, pk):
        NotificationService.soft_delete_notification(notification_id=pk, user=request.user)
        return Response(
            {
                "success": True,
                "message": "Notification deleted successfully.",
            },
            status=status.HTTP_200_OK,
        )


class NotificationMarkAsReadAPIView(APIView):
    """
    PATCH /api/v1/notifications/{id}/read/
    Mark a notification as read.
    """
    permission_classes = [IsAuthenticated]

    @notification_read_schema
    def patch(self, request, pk):
        notification = NotificationService.mark_as_read(notification_id=pk, user=request.user)
        serializer = NotificationDetailSerializer(notification)
        return Response(
            {
                "success": True,
                "message": "Notification marked as read.",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )


class NotificationMarkAllAsReadAPIView(APIView):
    """
    PATCH /api/v1/notifications/read-all/
    Mark all unread notifications for authenticated user as read.
    """
    permission_classes = [IsAuthenticated]

    @notification_read_all_schema
    def patch(self, request):
        count = NotificationService.mark_all_as_read(user=request.user)
        return Response(
            {
                "success": True,
                "message": f"Successfully marked {count} notifications as read.",
                "count": count,
            },
            status=status.HTTP_200_OK,
        )


class NotificationPreferenceAPIView(APIView):
    """
    GET /api/v1/notifications/preferences/
    PATCH /api/v1/notifications/preferences/
    """
    permission_classes = [IsAuthenticated]

    @notification_preference_get_schema
    def get(self, request):
        preferences = get_notification_preferences(request.user)
        serializer = NotificationPreferenceSerializer(preferences)
        return Response(
            {
                "success": True,
                "message": "Notification preferences retrieved.",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )

    @notification_preference_patch_schema
    def patch(self, request):
        preferences = get_notification_preferences(request.user)
        serializer = UpdateNotificationPreferenceSerializer(
            preferences,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        response_serializer = NotificationPreferenceSerializer(preferences)
        return Response(
            {
                "success": True,
                "message": "Notification preferences updated successfully.",
                "data": response_serializer.data,
            },
            status=status.HTTP_200_OK,
        )


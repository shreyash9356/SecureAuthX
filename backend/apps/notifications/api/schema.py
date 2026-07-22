from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiTypes
from apps.notifications.api.serializers import (
    NotificationSerializer,
    NotificationDetailSerializer,
    NotificationPreferenceSerializer,
    UpdateNotificationPreferenceSerializer,
)

notification_list_schema = extend_schema(
    summary="List User Notifications",
    description="Retrieve paginated list of active notifications for the authenticated user.",
    parameters=[
        OpenApiParameter("category", OpenApiTypes.STR, description="Filter by category (SECURITY, AUTHENTICATION, MFA, ORGANIZATION, ACCOUNT, SYSTEM, GENERAL)"),
        OpenApiParameter("priority", OpenApiTypes.STR, description="Filter by priority (LOW, MEDIUM, HIGH, CRITICAL)"),
        OpenApiParameter("is_read", OpenApiTypes.BOOL, description="Filter by read status (true/false)"),
    ],
    responses={200: NotificationSerializer(many=True)},
    tags=["Notifications"],
)

notification_detail_schema = extend_schema(
    summary="Get Notification Detail",
    description="Retrieve details of a single notification by UUID.",
    responses={200: NotificationDetailSerializer},
    tags=["Notifications"],
)

notification_delete_schema = extend_schema(
    summary="Soft Delete Notification",
    description="Soft-delete a notification record.",
    responses={200: OpenApiTypes.OBJECT},
    tags=["Notifications"],
)

notification_read_schema = extend_schema(
    summary="Mark Notification As Read",
    description="Mark a specific notification as read.",
    responses={200: NotificationDetailSerializer},
    tags=["Notifications"],
)

notification_read_all_schema = extend_schema(
    summary="Mark All Notifications As Read",
    description="Mark all unread notifications for the authenticated user as read.",
    responses={200: OpenApiTypes.OBJECT},
    tags=["Notifications"],
)

notification_preference_get_schema = extend_schema(
    summary="Get Notification Preferences",
    description="Retrieve notification channel preferences for the authenticated user.",
    responses={200: NotificationPreferenceSerializer},
    tags=["Notifications"],
)

notification_preference_patch_schema = extend_schema(
    summary="Update Notification Preferences",
    description="Update notification channel preferences for the authenticated user.",
    request=UpdateNotificationPreferenceSerializer,
    responses={200: NotificationPreferenceSerializer},
    tags=["Notifications"],
)

from django.shortcuts import get_object_or_404
from django.db.models import QuerySet

from .models import (
    Notification,
    NotificationPreference,
    NotificationTemplate,
    NotificationChannel,
)


def get_notification_by_id(notification_id, user) -> Notification:
    """
    Retrieve a single active (non-deleted) notification belonging to the given user.
    """
    return get_object_or_404(
        Notification,
        id=notification_id,
        user=user,
        is_deleted=False,
    )


def get_user_notifications(
    user,
    *,
    category: str = None,
    priority: str = None,
    is_read: bool = None
) -> QuerySet[Notification]:
    """
    Return all active notifications for a user with optional category, priority, and read filters.
    """
    queryset = Notification.objects.filter(
        user=user,
        is_deleted=False,
    ).select_related("organization")

    if category:
        queryset = queryset.filter(category=category)
    if priority:
        queryset = queryset.filter(priority=priority)
    if is_read is not None:
        queryset = queryset.filter(is_read=is_read)

    return queryset.order_by("-created_at")


def get_unread_notifications(user) -> QuerySet[Notification]:
    """
    Return unread notifications for a user.
    """
    return (
        Notification.objects.filter(
            user=user,
            is_deleted=False,
            is_read=False,
        )
        .select_related("organization")
        .order_by("-created_at")
    )


def get_notification_preferences(user) -> NotificationPreference:
    """
    Retrieve or create default notification preferences for a user.
    """
    preference, _ = NotificationPreference.objects.get_or_create(user=user)
    return preference


def get_notification_template(
    name: str,
    channel: str = NotificationChannel.EMAIL,
) -> NotificationTemplate | None:
    """
    Retrieve an active notification template by name and channel.
    Returns None if not found in DB so service layer can use default fallbacks.
    """
    return NotificationTemplate.objects.filter(
        name=name,
        channel=channel,
        is_active=True,
    ).first()


def list_active_templates() -> QuerySet[NotificationTemplate]:
    """
    List all active notification templates.
    """
    return NotificationTemplate.objects.filter(is_active=True).order_by("name", "channel")
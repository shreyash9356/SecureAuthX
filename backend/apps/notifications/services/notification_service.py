import logging
import uuid
from typing import Any, Dict
from django.utils import timezone
from django.db import transaction

from apps.notifications.models import (
    Notification,
    NotificationCategory,
    NotificationPriority,
    NotificationChannel,
)
from apps.notifications.selectors import (
    get_notification_by_id,
    get_user_notifications,
    get_unread_notifications,
    get_notification_preferences,
)
from apps.notifications.services.email_service import EmailService

logger = logging.getLogger(__name__)


class NotificationService:
    """
    Enterprise Notification Orchestration Service.
    
    Manages in-app notifications, user delivery preferences, status transitions,
    and multi-channel security/organization alert dispatching.
    """

    @classmethod
    def create_notification(
        cls,
        *,
        user: Any,
        title: str,
        message: str,
        category: str = NotificationCategory.GENERAL,
        priority: str = NotificationPriority.MEDIUM,
        channel: str = NotificationChannel.IN_APP,
        organization: Any = None,
        metadata: Dict[str, Any] = None,
        send_email: bool = False,
    ) -> Notification | None:
        """
        Creates an in-app notification record and optionally dispatches an email,
        respecting user NotificationPreference settings.
        
        Args:
            user: Target User model instance.
            title: Header title of notification.
            message: Detailed notification message string.
            category: Notification category classification.
            priority: Priority severity level.
            channel: Notification delivery channel.
            organization: Optional linked Organization model instance.
            metadata: JSON metadata payload.
            send_email: Whether to also trigger email dispatch via EmailService.
            
        Returns:
            Created Notification instance or None if blocked by user preferences.
        """
        prefs = get_notification_preferences(user)

        # Check Category Preferences
        if category == NotificationCategory.SECURITY and not prefs.security_notifications:
            logger.info("Security notification suppressed for user %s per user preferences.", user.email)
            return None

        if category == NotificationCategory.ORGANIZATION and not prefs.organization_notifications:
            logger.info("Organization notification suppressed for user %s per user preferences.", user.email)
            return None

        notification = None

        # Process In-App Delivery
        if channel == NotificationChannel.IN_APP or prefs.in_app_notifications:
            with transaction.atomic():
                notification = Notification(
                    user=user,
                    organization=organization,
                    category=category,
                    priority=priority,
                    channel=channel,
                    title=title,
                    message=message,
                    metadata=metadata or {},
                )
                notification.full_clean()
                notification.save()

            logger.info("Created in-app notification ID %s for user %s", notification.id, user.email)

        # Process Email Delivery if requested and permitted
        if send_email and prefs.email_notifications:
            EmailService.send_email(
                recipient_email=user.email,
                subject=title,
                html_content=f"<p>{message}</p>",
            )

        return notification

    @classmethod
    def mark_as_read(cls, *, notification_id: uuid.UUID | str, user: Any) -> Notification:
        """
        Marks a specific notification as read by updating is_read and read_at timestamp.
        """
        notification = get_notification_by_id(notification_id=notification_id, user=user)

        if not notification.is_read:
            notification.is_read = True
            notification.read_at = timezone.now()
            notification.save(update_fields=["is_read", "read_at"])
            logger.info("Marked notification %s as read for user %s", notification_id, user.email)

        return notification

    @classmethod
    def mark_all_as_read(cls, *, user: Any) -> int:
        """
        Marks all unread non-deleted notifications for a user as read.
        
        Returns count of updated records.
        """
        unread_qs = get_unread_notifications(user)
        count = unread_qs.update(
            is_read=True,
            read_at=timezone.now()
        )
        logger.info("Marked %d notifications as read for user %s", count, user.email)
        return count

    @classmethod
    def soft_delete_notification(cls, *, notification_id: uuid.UUID | str, user: Any) -> Notification:
        """
        Soft-deletes a notification by setting is_deleted=True and setting deleted_at timestamp.
        """
        notification = get_notification_by_id(notification_id=notification_id, user=user)

        if not notification.is_deleted:
            notification.is_deleted = True
            notification.deleted_at = timezone.now()
            notification.save(update_fields=["is_deleted", "deleted_at"])
            logger.info("Soft-deleted notification %s for user %s", notification_id, user.email)

        return notification

    @classmethod
    def create_security_notification(
        cls,
        *,
        user: Any,
        title: str,
        message: str,
        priority: str = NotificationPriority.HIGH,
        metadata: Dict[str, Any] = None,
        send_email: bool = True,
    ) -> Notification | None:
        """
        Generates a Security-category notification and dispatches email alert if enabled.
        """
        if send_email:
            EmailService.send_security_alert_email(
                user=user,
                alert_title=title,
                details=message,
            )

        return cls.create_notification(
            user=user,
            title=title,
            message=message,
            category=NotificationCategory.SECURITY,
            priority=priority,
            channel=NotificationChannel.IN_APP,
            metadata=metadata,
        )

    @classmethod
    def create_login_alert(
        cls,
        *,
        user: Any,
        ip_address: str,
        user_agent: str,
        metadata: Dict[str, Any] = None,
        send_email: bool = True,
    ) -> Notification | None:
        """
        Generates an Authentication login alert notification.
        """
        title = "New Login Alert"
        message = f"Successful authentication session established from IP: {ip_address} using {user_agent}."

        if send_email:
            EmailService.send_login_alert_email(
                user=user,
                ip_address=ip_address,
                user_agent=user_agent,
            )

        meta = metadata or {}
        meta.update({"ip_address": ip_address, "user_agent": user_agent})

        return cls.create_notification(
            user=user,
            title=title,
            message=message,
            category=NotificationCategory.AUTHENTICATION,
            priority=NotificationPriority.MEDIUM,
            channel=NotificationChannel.IN_APP,
            metadata=meta,
        )

    @classmethod
    def create_new_device_notification(
        cls,
        *,
        user: Any,
        device: str,
        ip_address: str,
        metadata: Dict[str, Any] = None,
        send_email: bool = True,
    ) -> Notification | None:
        """
        Generates a Security notification for logins detected on new/unrecognized devices.
        """
        title = "New Device Detected"
        message = f"Your account was accessed from a new device: {device} (IP: {ip_address})."

        if send_email:
            EmailService.send_new_device_login_email(
                user=user,
                device=device,
                ip_address=ip_address,
            )

        meta = metadata or {}
        meta.update({"device": device, "ip_address": ip_address})

        return cls.create_notification(
            user=user,
            title=title,
            message=message,
            category=NotificationCategory.SECURITY,
            priority=NotificationPriority.HIGH,
            channel=NotificationChannel.IN_APP,
            metadata=meta,
        )

    @classmethod
    def create_organization_notification(
        cls,
        *,
        user: Any,
        organization: Any,
        title: str,
        message: str,
        metadata: Dict[str, Any] = None,
        send_email: bool = False,
    ) -> Notification | None:
        """
        Generates an Organization-scoped notification.
        """
        meta = metadata or {}
        if organization:
            meta.update({"organization_id": str(organization.id), "organization_name": organization.name})

        return cls.create_notification(
            user=user,
            organization=organization,
            title=title,
            message=message,
            category=NotificationCategory.ORGANIZATION,
            priority=NotificationPriority.MEDIUM,
            channel=NotificationChannel.IN_APP,
            metadata=meta,
            send_email=send_email,
        )

import uuid

from django.conf import settings
from django.db import models

from apps.organizations.models import Organization


class NotificationCategory(models.TextChoices):
    SECURITY = "SECURITY", "Security"
    AUTHENTICATION = "AUTHENTICATION", "Authentication"
    MFA = "MFA", "Multi-Factor Authentication"
    ORGANIZATION = "ORGANIZATION", "Organization"
    ACCOUNT = "ACCOUNT", "Account"
    SYSTEM = "SYSTEM", "System"
    GENERAL = "GENERAL", "General"


class NotificationPriority(models.TextChoices):
    LOW = "LOW", "Low"
    MEDIUM = "MEDIUM", "Medium"
    HIGH = "HIGH", "High"
    CRITICAL = "CRITICAL", "Critical"


class NotificationChannel(models.TextChoices):
    IN_APP = "IN_APP", "In-App"
    EMAIL = "EMAIL", "Email"
    SMS = "SMS", "SMS"
    PUSH = "PUSH", "Push"


class Notification(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notifications",
    )

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="notifications",
        null=True,
        blank=True,
    )

    category = models.CharField(
        max_length=30,
        choices=NotificationCategory.choices,
        default=NotificationCategory.GENERAL,
    )

    priority = models.CharField(
        max_length=20,
        choices=NotificationPriority.choices,
        default=NotificationPriority.MEDIUM,
    )

    channel = models.CharField(
        max_length=20,
        choices=NotificationChannel.choices,
        default=NotificationChannel.IN_APP,
    )

    title = models.CharField(max_length=255)

    message = models.TextField()

    is_read = models.BooleanField(default=False)

    read_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    is_deleted = models.BooleanField(default=False)

    deleted_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    metadata = models.JSONField(
        default=dict,
        blank=True,
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["user", "is_read"]),
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["organization"]),
            models.Index(fields=["category"]),
            models.Index(fields=["priority"]),
            models.Index(fields=["channel"]),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.title}"


class NotificationPreference(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notification_preferences",
    )

    email_notifications = models.BooleanField(default=True)

    in_app_notifications = models.BooleanField(default=True)

    security_notifications = models.BooleanField(default=True)

    organization_notifications = models.BooleanField(default=True)

    marketing_notifications = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Notification Preferences - {self.user.email}"


class NotificationTemplate(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    name = models.CharField(
        max_length=100,
        help_text="Unique template slug identifier, e.g. verification_email, login_alert.",
    )

    category = models.CharField(
        max_length=30,
        choices=NotificationCategory.choices,
        default=NotificationCategory.GENERAL,
    )

    channel = models.CharField(
        max_length=20,
        choices=NotificationChannel.choices,
        default=NotificationChannel.EMAIL,
    )

    subject = models.CharField(
        max_length=255,
        blank=True,
        help_text="Email subject line template.",
    )

    title = models.CharField(
        max_length=255,
        help_text="In-app or header title template.",
    )

    body = models.TextField(
        help_text="Body content template supporting Django template syntax placeholders.",
    )

    is_active = models.BooleanField(
        default=True,
        help_text="Designates whether this template is available for message rendering.",
    )

    created_at = models.DateTimeField(auto_now_add=True)

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name", "channel")
        unique_together = ("name", "channel")
        indexes = [
            models.Index(fields=["name", "channel"]),
            models.Index(fields=["is_active"]),
        ]

    def __str__(self):
        return f"Template: {self.name} ({self.channel})"
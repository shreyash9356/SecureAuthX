import uuid

from django.conf import settings
from django.db import models

from apps.authorization.models import Role
from .constants import (
    InvitationStatus,
    MembershipStatus,
    OrganizationStatus,
)


class Organization(models.Model):
    """
    Represents a tenant within the IAM platform.

    This model stores basic organization metadata such as name, slug,
    description, owner and lifecycle status. Timestamps track creation
    and last update.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    name = models.CharField(
        max_length=255,
    )

    # URL-friendly unique identifier used in routes and links

    slug = models.SlugField(
        max_length=255,
        unique=True,
    )

    description = models.TextField(
        blank=True,
    )

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="owned_organizations",
    )

    # Current lifecycle status of the organization (active, suspended, etc.)

    status = models.CharField(
        max_length=20,
        choices=OrganizationStatus.choices,
        default=OrganizationStatus.ACTIVE,
        db_index=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    class Meta:
        db_table = "organizations"
        ordering = ["name"]
        indexes = [
            models.Index(fields=["slug"]),
            models.Index(fields=["status"]),
            models.Index(fields=["owner"]),
        ]

    def __str__(self):
        return self.name


class OrganizationMembership(models.Model):
    """
    Connects users with organizations.
    """
    # Represents a user's membership within a given organization,
    # including role and invitation/joining state.

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="memberships",
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="organization_memberships",
    )

    # Role assigned to the user within the organization (FK to authorization.Role)

    role = models.ForeignKey(
        Role,
        on_delete=models.PROTECT,
        related_name="organization_memberships",
    )

    status = models.CharField(
        max_length=20,
        choices=MembershipStatus.choices,
        default=MembershipStatus.PENDING,
        db_index=True,
    )

    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="sent_membership_invitations",
    )

    # Timestamp when the user accepted/was recorded as joined

    joined_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    class Meta:
        db_table = "organization_memberships"
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "user"],
                name="unique_organization_membership",
            )
        ]
        indexes = [
            models.Index(fields=["organization", "status"]),
            models.Index(fields=["user"]),
        ]

    def __str__(self):
        return f"{self.user} - {self.organization}"


class OrganizationInvitation(models.Model):
    """
    Invitation sent to join an organization.
    """
    # Stores pending/used invitations sent to an email to join an organization.

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="invitations",
    )

    email = models.EmailField()

    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="organization_invitations_sent",
    )

    token = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        editable=False,
    )

    # Invitation lifecycle state (pending, accepted, expired, etc.)

    status = models.CharField(
        max_length=20,
        choices=InvitationStatus.choices,
        default=InvitationStatus.PENDING,
    )

    expires_at = models.DateTimeField()

    accepted_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    class Meta:
        db_table = "organization_invitations"
        indexes = [
            models.Index(fields=["email"]),
            models.Index(fields=["token"]),
            models.Index(fields=["status"]),
        ]

    def __str__(self):
        return f"{self.email} ({self.organization})"


class OrganizationSettings(models.Model):
    """
    Stores configurable settings for an organization.
    """
    # One-to-one settings model - stores preferences such as timezone,
    # branding and session timeout for the organization.

    organization = models.OneToOneField(
        Organization,
        on_delete=models.CASCADE,
        related_name="settings",
        primary_key=True,
    )

    timezone = models.CharField(
        max_length=100,
        default="UTC",
    )

    country = models.CharField(
        max_length=100,
        blank=True,
    )

    branding_name = models.CharField(
        max_length=255,
        blank=True,
    )

    logo = models.URLField(
        blank=True,
    )

    session_timeout_minutes = models.PositiveIntegerField(
        default=60,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    class Meta:
        db_table = "organization_settings"

    def __str__(self):
        return f"Settings - {self.organization.name}"
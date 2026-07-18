"""Admin registration for organization-related models."""

from django.contrib import admin

from .models import (
    Organization,
    OrganizationInvitation,
    OrganizationMembership,
    OrganizationSettings,
)


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    """Admin options for the Organization model."""

    list_display = (
        "name",
        "slug",
        "owner",
        "status",
        "created_at",
    )
    # Enable quick searching by key organization fields and related owner email.
    search_fields = (
        "name",
        "slug",
        "owner__email",
    )
    # Allow filtering organizations by status and creation date.
    list_filter = (
        "status",
        "created_at",
    )
    # Default ordering by organization name.
    ordering = (
        "name",
    )
    # Fields that should not be editable in the admin interface.
    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
    )
    # Use autocomplete for owner relationship selection.
    autocomplete_fields = (
        "owner",
    )


@admin.register(OrganizationMembership)
class OrganizationMembershipAdmin(admin.ModelAdmin):
    """Admin options for organization membership records."""

    list_display = (
        "user",
        "organization",
        "role",
        "status",
        "joined_at",
    )
    # Search by user email and organization name.
    search_fields = (
        "user__email",
        "organization__name",
    )
    # Filter membership list by status and assigned role.
    list_filter = (
        "status",
        "role",
    )
    # Order memberships by organization, then by user.
    ordering = (
        "organization",
        "user",
    )
    # Prevent editing of auto-generated metadata fields.
    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
    )
    # Autocomplete fields reduce the number of results when selecting related objects.
    autocomplete_fields = (
        "organization",
        "user",
        "role",
        "invited_by",
    )


@admin.register(OrganizationInvitation)
class OrganizationInvitationAdmin(admin.ModelAdmin):
    """Admin options for organization invitations."""

    list_display = (
        "email",
        "organization",
        "status",
        "expires_at",
        "created_at",
    )
    # Locate invitations by email or organization name.
    search_fields = (
        "email",
        "organization__name",
    )
    # Filter invitations by their current status.
    list_filter = (
        "status",
    )
    # Show newest invitations first by default.
    ordering = (
        "-created_at",
    )
    # Token and created timestamp are read-only in the admin.
    readonly_fields = (
        "id",
        "token",
        "created_at",
    )
    # Use autocomplete for organization and invited_by relationships.
    autocomplete_fields = (
        "organization",
        "invited_by",
    )


@admin.register(OrganizationSettings)
class OrganizationSettingsAdmin(admin.ModelAdmin):
    """Admin options for organization settings records."""

    list_display = (
        "organization",
        "timezone",
        "country",
        "session_timeout_minutes",
    )
    # Search settings by related organization name.
    search_fields = (
        "organization__name",
    )
    # Order settings by organization.
    ordering = (
        "organization",
    )
    # Autocomplete the organization relationship for the settings model.
    autocomplete_fields = (
        "organization",
    )
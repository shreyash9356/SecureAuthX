from django.contrib.auth import get_user_model
from django.core.validators import RegexValidator
from rest_framework import serializers

from apps.authorization.api.serializers import RoleDetailSerializer
from apps.authorization.constants import RoleSlugs
from apps.organizations.models import (
    Organization,
    OrganizationMembership,
    OrganizationInvitation,
    OrganizationSettings,
)
from apps.organizations.constants import (
    OrganizationStatus,
    MembershipStatus,
    InvitationStatus,
)

User = get_user_model()

# ==============================================================================
# Regex Validators matching model specifications
# ==============================================================================

slug_validator = RegexValidator(
    regex=r"^[a-z0-9_-]+$",
    message="Slug must contain only lowercase letters, numbers, underscores, or hyphens."
)


# ==============================================================================
# Minimal/Nested Helper Serializers
# ==============================================================================

class UserMinimalSerializer(serializers.ModelSerializer):
    """
    Compact read-only serializer for nested identity profile information.
    """
    class Meta:
        model = User
        fields = ["id", "email", "first_name", "last_name"]
        read_only_fields = fields


class OrganizationSettingsDetailSerializer(serializers.ModelSerializer):
    """
    Detailed read-only settings serializer.
    """
    class Meta:
        model = OrganizationSettings
        fields = [
            "timezone",
            "country",
            "branding_name",
            "logo",
            "session_timeout_minutes",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


# ==============================================================================
# Organization Serializers
# ==============================================================================

class OrganizationDetailSerializer(serializers.ModelSerializer):
    """
    Detailed read-only serializer for Organization tenant metadata.
    """
    owner = UserMinimalSerializer(read_only=True)
    settings = OrganizationSettingsDetailSerializer(read_only=True)

    class Meta:
        model = Organization
        fields = [
            "id",
            "name",
            "slug",
            "description",
            "owner",
            "status",
            "settings",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class OrganizationCreateSerializer(serializers.Serializer):
    """
    Input serializer for establishing a new organization tenant.
    """
    name = serializers.CharField(
        max_length=255,
        help_text="The human-readable name of the organization."
    )
    slug = serializers.CharField(
        max_length=255,
        required=False,
        validators=[slug_validator],
        help_text="Optional unique URL slug. Automatically generated if omitted."
    )
    description = serializers.CharField(
        required=False,
        allow_blank=True,
        default="",
        help_text="Optional summary details."
    )
    timezone = serializers.CharField(
        max_length=100,
        required=False,
        default="UTC",
        help_text="Regional timezone designation."
    )
    country = serializers.CharField(
        max_length=100,
        required=False,
        allow_blank=True,
        default="",
        help_text="Country name or ISO regional identifier."
    )
    branding_name = serializers.CharField(
        max_length=255,
        required=False,
        allow_blank=True,
        default="",
        help_text="Client-facing corporate name."
    )
    logo = serializers.URLField(
        required=False,
        allow_blank=True,
        default="",
        help_text="FQDN URL to corporate branding logo."
    )
    session_timeout_minutes = serializers.IntegerField(
        required=False,
        min_value=1,
        default=60,
        help_text="Maximum inactive session timeout before automatic logout."
    )


class OrganizationUpdateSerializer(serializers.Serializer):
    """
    Input serializer for updating organization metadata parameters.
    """
    name = serializers.CharField(
        max_length=255,
        required=False,
        help_text="New display name of the tenant."
    )
    description = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="New summary details."
    )
    status = serializers.ChoiceField(
        choices=OrganizationStatus.choices,
        required=False,
        help_text="Lifecycle state adjustment."
    )


# ==============================================================================
# Settings Serializers
# ==============================================================================

class OrganizationSettingsUpdateSerializer(serializers.Serializer):
    """
    Input serializer for updating organization settings configurations.
    """
    timezone = serializers.CharField(
        max_length=100,
        required=False,
        help_text="Regional timezone (e.g. UTC, America/New_York)."
    )
    country = serializers.CharField(
        max_length=100,
        required=False,
        allow_blank=True,
        help_text="Regional country name or code."
    )
    branding_name = serializers.CharField(
        max_length=255,
        required=False,
        allow_blank=True,
        help_text="Client-facing branding title."
    )
    logo = serializers.URLField(
        required=False,
        allow_blank=True,
        help_text="Fully qualified URL to logo image."
    )
    session_timeout_minutes = serializers.IntegerField(
        required=False,
        min_value=1,
        help_text="Maximum session timeout duration in minutes."
    )


# ==============================================================================
# Membership Serializers
# ==============================================================================

class OrganizationMembershipDetailSerializer(serializers.ModelSerializer):
    """
    Detailed read-only serializer mapping a User's workspace role and status.
    """
    user = UserMinimalSerializer(read_only=True)
    role = RoleDetailSerializer(read_only=True)
    invited_by = UserMinimalSerializer(read_only=True)

    class Meta:
        model = OrganizationMembership
        fields = [
            "id",
            "organization",
            "user",
            "role",
            "status",
            "invited_by",
            "joined_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class MembershipAddSerializer(serializers.Serializer):
    """
    Input serializer for adding a member directly to an organization.
    """
    user_id = serializers.UUIDField(
        help_text="Unique UUID of the User identity to map."
    )
    role_slug = serializers.CharField(
        max_length=100,
        help_text="The slug of the Role to assign."
    )
    status = serializers.ChoiceField(
        choices=MembershipStatus.choices,
        default=MembershipStatus.ACTIVE,
        help_text="Initial state of the membership mapping."
    )


class MembershipRoleUpdateSerializer(serializers.Serializer):
    """
    Input serializer for updating a member's role assignment.
    """
    role_slug = serializers.CharField(
        max_length=100,
        help_text="Slug of the new Role to assign to this member."
    )


class MembershipStatusUpdateSerializer(serializers.Serializer):
    """
    Input serializer for updating a member's status configuration.
    """
    status = serializers.ChoiceField(
        choices=MembershipStatus.choices,
        help_text="Target status state (e.g. ACTIVE, SUSPENDED)."
    )


# ==============================================================================
# Invitation Serializers
# ==============================================================================

class OrganizationInvitationDetailSerializer(serializers.ModelSerializer):
    """
    Detailed read-only serializer representing member recruitment invitations.
    """
    invited_by = UserMinimalSerializer(read_only=True)

    class Meta:
        model = OrganizationInvitation
        fields = [
            "id",
            "organization",
            "email",
            "invited_by",
            "token",
            "status",
            "expires_at",
            "accepted_at",
            "created_at",
        ]
        read_only_fields = fields


class InvitationCreateSerializer(serializers.Serializer):
    """
    Input serializer for issuing a member invitation.
    """
    email = serializers.EmailField(
        help_text="Email address of the invited user."
    )
    role_slug = serializers.CharField(
        max_length=100,
        required=False,
        default=RoleSlugs.EMPLOYEE,
        help_text="The role to assign upon token acceptance."
    )
    expires_in_days = serializers.IntegerField(
        required=False,
        default=7,
        min_value=1,
        help_text="Number of days before the token expires."
    )


# ==============================================================================
# Ownership Serializers
# ==============================================================================

class OwnershipTransferSerializer(serializers.Serializer):
    """
    Input serializer for transferring organization ownership.
    """
    new_owner_id = serializers.UUIDField(
        help_text="UUID of the active member taking ownership."
    )


# ==============================================================================
# Standard OpenAPI Response Envelope Schemas (Documentation Helpers)
# ==============================================================================

class ErrorDetailsMapSerializer(serializers.Serializer):
    """
    Structured dictionary mapping fields to list validation messages.
    """
    errors = serializers.DictField(
        child=serializers.ListField(child=serializers.CharField()),
        required=False,
        default={},
        help_text="Map of field-level errors."
    )


class StandardErrorEnvelopeSerializer(serializers.Serializer):
    """
    Standardized global error wrapper response body.
    """
    success = serializers.BooleanField(
        default=False,
        help_text="Always false for error response paths."
    )
    message = serializers.CharField(
        help_text="Status summary explanation."
    )
    errors = serializers.DictField(
        child=serializers.ListField(child=serializers.CharField()),
        default={},
        help_text="Dynamic dictionary mapping fields to error lists, if applicable."
    )

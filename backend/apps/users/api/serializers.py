from rest_framework import serializers

from apps.accounts.models import User


class UserListSerializer(serializers.ModelSerializer):
    """
    Serializer for listing users.
    """

    full_name = serializers.ReadOnlyField()

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "username",
            "first_name",
            "last_name",
            "full_name",
            "is_active",
            "is_verified",
            "is_locked",
            "created_at",
        )
        read_only_fields = fields


class UserOrganizationMembershipSerializer(serializers.ModelSerializer):
    """
    Custom serializer to represent user's organization membership details.
    """
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    organization_slug = serializers.CharField(source="organization.slug", read_only=True)
    role_name = serializers.CharField(source="role.name", read_only=True)
    role_slug = serializers.CharField(source="role.slug", read_only=True)

    class Meta:
        from apps.organizations.models import OrganizationMembership
        model = OrganizationMembership
        fields = [
            "id",
            "organization_name",
            "organization_slug",
            "role_name",
            "role_slug",
            "status",
            "joined_at",
        ]
        read_only_fields = fields


class UserDetailSerializer(serializers.ModelSerializer):
    """
    Serializer for detailed user view, including nested system roles and organization memberships.
    """
    full_name = serializers.ReadOnlyField()
    roles = serializers.SerializerMethodField()
    organizations = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "username",
            "first_name",
            "last_name",
            "full_name",
            "is_active",
            "is_verified",
            "is_locked",
            "locked_until",
            "created_at",
            "updated_at",
            "roles",
            "organizations",
        )
        read_only_fields = fields

    def get_roles(self, obj):
        from apps.authorization.services.authorization_service import AuthorizationService
        from apps.authorization.api.serializers import RoleDetailSerializer
        roles = AuthorizationService.get_effective_roles(obj)
        return RoleDetailSerializer(roles, many=True).data

    def get_organizations(self, obj):
        from apps.organizations.constants import MembershipStatus
        memberships = obj.organization_memberships.exclude(
            status=MembershipStatus.REMOVED
        ).select_related("organization", "role")
        return UserOrganizationMembershipSerializer(memberships, many=True).data


class UserUpdateSerializer(serializers.Serializer):
    """
    Input serializer for updating user profile fields.
    """
    first_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    username = serializers.CharField(max_length=150, required=False, allow_null=True, allow_blank=True)

    def validate_username(self, value):
        if value is not None:
            value = value.strip()
            if value == "":
                return None
            import re
            if not re.match(r"^[a-zA-Z0-9_-]+$", value):
                raise serializers.ValidationError(
                    "Username must contain only letters, numbers, underscores, or hyphens."
                )
            from apps.accounts.models import User
            user_id = self.context.get("user_id")
            qs = User.objects.filter(username__iexact=value)
            if user_id:
                qs = qs.exclude(id=user_id)
            if qs.exists():
                raise serializers.ValidationError("A user with that username already exists.")
        return value


class UserLockSerializer(serializers.Serializer):
    """
    Input serializer for locking a user account.
    """
    locked_until = serializers.DateTimeField(required=False, allow_null=True, default=None)

    def validate_locked_until(self, value):
        from django.utils import timezone
        if value and value <= timezone.now():
            raise serializers.ValidationError("Lock expiration timestamp must be in the future.")
        return value


class UserRoleAssignSerializer(serializers.Serializer):
    """
    Input serializer for assigning a system role to a user.
    """
    role_id = serializers.UUIDField(help_text="UUID of the role to assign.")
    expires_at = serializers.DateTimeField(required=False, allow_null=True, default=None)
    assignment_reason = serializers.CharField(max_length=255, required=False, allow_blank=True, default=None)

    def validate_expires_at(self, value):
        from django.utils import timezone
        if value and value <= timezone.now():
            raise serializers.ValidationError("Expiration timestamp must be in the future.")
        return value


class UserRoleRevokeSerializer(serializers.Serializer):
    """
    Input serializer for revoking a system role from a user.
    """
    role_id = serializers.UUIDField(help_text="UUID of the role to revoke.")
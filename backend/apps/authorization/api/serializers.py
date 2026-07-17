import re
from django.core.validators import RegexValidator
from django.utils import timezone
from rest_framework import serializers

from apps.authorization.models import Permission, Role, RolePermission, UserRole
from apps.authorization.services.permission_service import PermissionService
from apps.authorization.services.role_service import RoleService
from apps.authorization.services.user_role_service import UserRoleService
from apps.authorization.exceptions import (
    PermissionAlreadyExistsException,
    RoleAlreadyExistsException,
    SystemRoleModificationException,
    PermissionAssignmentException,
    RoleAssignmentException,
    InvalidRoleException,
)

# --------------------------------------------------------------------------
# Regex Validators matching model specifications
# --------------------------------------------------------------------------
code_validator = RegexValidator(
    regex=r"^[a-z0-9_:-]+$",
    message="Code must contain only lowercase letters, numbers, underscores, colons, or hyphens."
)

slug_validator = RegexValidator(
    regex=r"^[a-z0-9_-]+$",
    message="Slug must contain only lowercase letters, numbers, underscores, or hyphens."
)


# --------------------------------------------------------------------------
# Read-Only Output Serializers
# --------------------------------------------------------------------------

class PermissionDetailSerializer(serializers.ModelSerializer):
    """
    Detailed read-only serializer for Permission catalog items.
    """
    class Meta:
        model = Permission
        fields = [
            "id", "name", "code", "resource", "action", 
            "description", "is_system", "is_active", 
            "created_at", "updated_at"
        ]
        read_only_fields = fields


class RoleDetailSerializer(serializers.ModelSerializer):
    """
    Detailed read-only serializer for Role definitions.
    """
    class Meta:
        model = Role
        fields = [
            "id", "name", "slug", "description", "priority", 
            "is_system", "is_active", "created_at", "updated_at"
        ]
        read_only_fields = fields


class RolePermissionDetailSerializer(serializers.ModelSerializer):
    """
    Detailed read-only serializer for Role-Permission mapping records.
    """
    role = RoleDetailSerializer(read_only=True)
    permission = PermissionDetailSerializer(read_only=True)

    class Meta:
        model = RolePermission
        fields = [
            "id", "role", "permission", "assigned_by", 
            "assignment_reason", "is_active", "created_at", "updated_at"
        ]
        read_only_fields = fields


class UserRoleDetailSerializer(serializers.ModelSerializer):
    """
    Detailed read-only serializer for User-Role assignment records.
    """
    role = RoleDetailSerializer(read_only=True)

    class Meta:
        model = UserRole
        fields = [
            "id", "user", "role", "assigned_by", "assignment_reason", 
            "assigned_at", "expires_at", "is_active", 
            "created_at", "updated_at"
        ]
        read_only_fields = fields


# --------------------------------------------------------------------------
# Write-Only Input & Mutation Serializers
# --------------------------------------------------------------------------

class PermissionCreateSerializer(serializers.Serializer):
    """
    Serializer to validate payload and invoke PermissionService.create_permission.
    """
    name = serializers.CharField(max_length=100)
    resource = serializers.CharField(max_length=100, validators=[code_validator])
    action = serializers.CharField(max_length=100, validators=[slug_validator])
    description = serializers.CharField(required=False, allow_blank=True, default="")

    def create(self, validated_data):
        try:
            return PermissionService.create_permission(
                name=validated_data["name"],
                resource=validated_data["resource"],
                action=validated_data["action"],
                description=validated_data.get("description", ""),
            )
        except PermissionAlreadyExistsException as e:
            raise serializers.ValidationError({"code": str(e)})


class PermissionUpdateSerializer(serializers.Serializer):
    """
    Serializer to validate payload and invoke PermissionService.update_permission.
    """
    name = serializers.CharField(max_length=100, required=False)
    description = serializers.CharField(required=False, allow_blank=True)

    def update(self, instance, validated_data):
        return PermissionService.update_permission(
            permission_id=str(instance.id),
            name=validated_data.get("name"),
            description=validated_data.get("description")
        )


class RoleCreateSerializer(serializers.Serializer):
    """
    Serializer to validate payload and invoke RoleService.create_role.
    """
    name = serializers.CharField(max_length=100)
    slug = serializers.CharField(max_length=100, validators=[slug_validator])
    description = serializers.CharField(required=False, allow_blank=True, default="")
    priority = serializers.IntegerField(default=0, min_value=0)

    def validate_slug(self, value):
        # Strip and lowercase
        normalized_value = value.strip().lower()
        if not re.match(r"^[a-z0-9_-]+$", normalized_value):
            raise serializers.ValidationError(
                "Slug must contain only lowercase letters, numbers, underscores, or hyphens."
            )
        return normalized_value

    def create(self, validated_data):
        try:
            return RoleService.create_role(
                name=validated_data["name"],
                slug=validated_data["slug"],
                description=validated_data.get("description", ""),
                priority=validated_data.get("priority", 0)
            )
        except RoleAlreadyExistsException as e:
            raise serializers.ValidationError({"slug": str(e)})


class RoleUpdateSerializer(serializers.Serializer):
    """
    Serializer to validate payload and invoke RoleService.update_role.
    """
    name = serializers.CharField(max_length=100, required=False)
    description = serializers.CharField(required=False, allow_blank=True)
    priority = serializers.IntegerField(required=False, min_value=0)

    def update(self, instance, validated_data):
        try:
            return RoleService.update_role(
                role_id=str(instance.id),
                name=validated_data.get("name"),
                description=validated_data.get("description"),
                priority=validated_data.get("priority")
            )
        except (SystemRoleModificationException, InvalidRoleException) as e:
            raise serializers.ValidationError({"non_field_errors": str(e)})


class RolePermissionAssignSerializer(serializers.Serializer):
    """
    Serializer to validate mapping payload and assign catalog permission capability.
    """
    role_id = serializers.UUIDField()
    permission_id = serializers.UUIDField()
    assignment_reason = serializers.CharField(required=False, allow_blank=True, default="")

    def save(self, assigned_by_user):
        role_id = self.validated_data["role_id"]
        permission_id = self.validated_data["permission_id"]
        reason = self.validated_data.get("assignment_reason", "")

        try:
            return RoleService.assign_permission(
                role_id=str(role_id),
                permission_id=str(permission_id),
                assigned_by_user=assigned_by_user,
                assignment_reason=reason
            )
        except PermissionAssignmentException as e:
            raise serializers.ValidationError({"non_field_errors": str(e)})


class RolePermissionRemoveSerializer(serializers.Serializer):
    """
    Serializer to validate and remove permission capability mapping from a target role.
    """
    role_id = serializers.UUIDField()
    permission_id = serializers.UUIDField()

    def save(self, **kwargs):
        role_id = self.validated_data["role_id"]
        permission_id = self.validated_data["permission_id"]

        try:
            return RoleService.remove_permission(
                role_id=str(role_id),
                permission_id=str(permission_id)
            )
        except PermissionAssignmentException as e:
            raise serializers.ValidationError({"non_field_errors": str(e)})


class UserRoleAssignSerializer(serializers.Serializer):
    """
    Serializer to grant user account role membership access.
    """
    user_id = serializers.UUIDField()
    role_id = serializers.UUIDField()
    expires_at = serializers.DateTimeField(required=False, allow_null=True, default=None)
    assignment_reason = serializers.CharField(required=False, allow_blank=True, default="")

    def validate_expires_at(self, value):
        if value and value <= timezone.now():
            raise serializers.ValidationError("Expiration timestamp must be in the future.")
        return value

    def save(self, assigned_by_user):
        user_id = self.validated_data["user_id"]
        role_id = self.validated_data["role_id"]
        expires_at = self.validated_data.get("expires_at")
        reason = self.validated_data.get("assignment_reason", "")

        try:
            return UserRoleService.assign_role(
                user_id=str(user_id),
                role_id=str(role_id),
                assigned_by_user=assigned_by_user,
                expires_at=expires_at,
                assignment_reason=reason
            )
        except RoleAssignmentException as e:
            raise serializers.ValidationError({"non_field_errors": str(e)})


class UserRoleRevokeSerializer(serializers.Serializer):
    """
    Serializer to revoke user account role membership access.
    """
    user_id = serializers.UUIDField()
    role_id = serializers.UUIDField()

    def save(self, **kwargs):
        user_id = self.validated_data["user_id"]
        role_id = self.validated_data["role_id"]

        try:
            return UserRoleService.revoke_role(
                user_id=str(user_id),
                role_id=str(role_id)
            )
        except RoleAssignmentException as e:
            raise serializers.ValidationError({"non_field_errors": str(e)})


class UserRoleExtendSerializer(serializers.Serializer):
    """
    Serializer to extend active user role assignment expiration timeline.
    """
    assignment_id = serializers.UUIDField()
    expires_at = serializers.DateTimeField(allow_null=True)

    def validate_expires_at(self, value):
        if value and value <= timezone.now():
            raise serializers.ValidationError("New expiration timestamp must be in the future.")
        return value

    def save(self, **kwargs):
        assignment_id = self.validated_data["assignment_id"]
        expires_at = self.validated_data.get("expires_at")

        try:
            return UserRoleService.extend_assignment(
                assignment_id=str(assignment_id),
                expires_at=expires_at
            )
        except RoleAssignmentException as e:
            raise serializers.ValidationError({"non_field_errors": str(e)})

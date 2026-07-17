from django.test import TestCase
from django.contrib.auth import get_user_model

from apps.authorization.constants import PermissionCodes, RoleSlugs
from apps.authorization.models import Role, Permission, RolePermission
from apps.authorization.services.role_service import RoleService
from apps.authorization.exceptions import (
    RoleNotFoundException,
    RoleAlreadyExistsException,
    SystemRoleModificationException,
    PermissionAssignmentException,
    PermissionNotFoundException,
    InvalidRoleException,
)

User = get_user_model()


class RoleServiceTests(TestCase):
    """
    Comprehensive unit tests for the core RoleService layer.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="admin_test",
            email="admin@test.com",
            password="testpassword123"
        )

        self.role = Role.objects.create(
            name="Employee",
            slug=RoleSlugs.EMPLOYEE,
            description="Regular staff member.",
            priority=100,
            is_system=False,
            is_active=True
        )

        self.system_role = Role.objects.create(
            name="Super Admin",
            slug=RoleSlugs.SUPER_ADMIN,
            description="Global administrator role.",
            priority=1000,
            is_system=True,
            is_active=True
        )

        resource, action = PermissionCodes.USER_UPDATE.rsplit(":", 1)
        self.permission = Permission.objects.create(
            name="Edit Users",
            code=PermissionCodes.USER_UPDATE,
            resource=resource,
            action=action,
            is_system=False,
            is_active=True
        )

    def test_create_role_success(self):
        """
        Verifies creating a new enterprise role resolves successfully.
        """
        role = RoleService.create_role(
            name="Manager",
            slug=RoleSlugs.MANAGER,
            description="Branch manager role.",
            priority=50
        )
        self.assertEqual(role.name, "Manager")
        self.assertEqual(role.slug, RoleSlugs.MANAGER)
        self.assertEqual(role.priority, 50)
        self.assertFalse(role.is_system)
        self.assertTrue(role.is_active)

    def test_create_role_duplicate_slug_raises_conflict(self):
        """
        Verifies duplicate slugs trigger a RoleAlreadyExistsException.
        """
        with self.assertRaises(RoleAlreadyExistsException):
            RoleService.create_role(
                name="Another Employee",
                slug=RoleSlugs.EMPLOYEE
            )

    def test_create_role_invalid_priority_raises_validation(self):
        """
        Verifies negative priority values trigger an InvalidRoleException.
        """
        with self.assertRaises(InvalidRoleException):
            RoleService.create_role(
                name="Invalid Role",
                slug="invalid-role",
                priority=-10
            )

    def test_update_role_success(self):
        """
        Verifies updating mutable role fields resolves correctly.
        """
        updated = RoleService.update_role(
            role_id=str(self.role.id),
            name="Regular Employee",
            description="Staff member details update.",
            priority=99
        )
        self.assertEqual(updated.name, "Regular Employee")
        self.assertEqual(updated.description, "Staff member details update.")
        self.assertEqual(updated.priority, 99)

    def test_update_system_role_raises_modification_error(self):
        """
        Verifies modifying name/slug of a system role throws SystemRoleModificationException.
        """
        with self.assertRaises(SystemRoleModificationException):
            RoleService.update_role(
                role_id=str(self.system_role.id),
                name="Super Administrator Changed"
            )

    def test_deactivate_role_success(self):
        """
        Verifies toggling role activity state cleanly.
        """
        deactivated = RoleService.deactivate_role(str(self.role.id))
        self.assertFalse(deactivated.is_active)

    def test_deactivate_system_role_raises_modification_error(self):
        """
        Verifies deactivating a system role is blocked.
        """
        with self.assertRaises(SystemRoleModificationException):
            RoleService.deactivate_role(str(self.system_role.id))

    def test_soft_delete_role_success(self):
        """
        Verifies soft deleting a custom role deactivates the role cleanly.
        """
        deleted = RoleService.soft_delete_role(str(self.role.id))
        self.assertFalse(deleted.is_active)

    def test_soft_delete_system_role_raises_modification_error(self):
        """
        Verifies soft-deleting a system role is prohibited.
        """
        with self.assertRaises(SystemRoleModificationException):
            RoleService.soft_delete_role(str(self.system_role.id))

    def test_assign_permission_success(self):
        """
        Verifies mapping a capability to a role resolves successfully.
        """
        mapping = RoleService.assign_permission(
            role_id=str(self.role.id),
            permission_id=str(self.permission.id),
            assigned_by_user=self.user,
            assignment_reason="Need user edit capability."
        )
        self.assertEqual(mapping.role.id, self.role.id)
        self.assertEqual(mapping.permission.id, self.permission.id)
        self.assertTrue(mapping.is_active)

    def test_assign_permission_inactive_role_raises_error(self):
        """
        Verifies mapping a capability to a deactivated role is blocked.
        """
        self.role.is_active = False
        self.role.save()

        with self.assertRaises(PermissionAssignmentException):
            RoleService.assign_permission(
                role_id=str(self.role.id),
                permission_id=str(self.permission.id),
                assigned_by_user=self.user
            )

    def test_remove_permission_success(self):
        """
        Verifies removing a privilege from a role soft-deactivates the mapping record.
        """
        RoleService.assign_permission(
            role_id=str(self.role.id),
            permission_id=str(self.permission.id),
            assigned_by_user=self.user
        )

        removed_mapping = RoleService.remove_permission(
            role_id=str(self.role.id),
            permission_id=str(self.permission.id)
        )
        self.assertFalse(removed_mapping.is_active)

    def test_clear_permissions_success(self):
        """
        Verifies clearing all mappings on a role deactivates them all cleanly.
        """
        RoleService.assign_permission(
            role_id=str(self.role.id),
            permission_id=str(self.permission.id),
            assigned_by_user=self.user
        )

        RoleService.clear_permissions(str(self.role.id))
        self.assertEqual(
            RolePermission.objects.filter(role=self.role, is_active=True).count(),
            0
        )

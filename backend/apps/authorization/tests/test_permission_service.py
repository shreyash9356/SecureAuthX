from django.test import TestCase

from apps.authorization.constants import PermissionCodes
from apps.authorization.models import Permission
from apps.authorization.services.permission_service import (
    PermissionService,
    PermissionNotFoundException,
    PermissionAlreadyExistsException,
    SystemPermissionModificationException,
    InvalidPermissionException,
)


def _split_code(code: str) -> tuple[str, str]:
    return code.rsplit(":", 1)


class PermissionServiceTests(TestCase):
    """
    Comprehensive unit tests for the core PermissionService layer.
    """

    def setUp(self):
        resource, action = _split_code(PermissionCodes.USER_READ)
        self.permission = Permission.objects.create(
            name="Test Permission",
            code=PermissionCodes.USER_READ,
            resource=resource,
            action=action,
            description="Testing capability mapping.",
            is_system=False,
            is_active=True
        )

        sys_resource, sys_action = _split_code(PermissionCodes.PERMISSION_MANAGE)
        self.system_permission = Permission.objects.create(
            name="System Capability",
            code=PermissionCodes.PERMISSION_MANAGE,
            resource=sys_resource,
            action=sys_action,
            description="System reserved capability.",
            is_system=True,
            is_active=True
        )

    def test_create_permission_success(self):
        """
        Verifies registering a brand new catalog permission resolves successfully.
        """
        resource, action = _split_code(PermissionCodes.ORGANIZATION_CREATE)
        perm = PermissionService.create_permission(
            name="New Capability",
            resource=resource,
            action=action,
            description="Allows creating organizations."
        )
        self.assertEqual(perm.name, "New Capability")
        self.assertEqual(perm.code, PermissionCodes.ORGANIZATION_CREATE)
        self.assertFalse(perm.is_system)
        self.assertTrue(perm.is_active)

    def test_create_permission_duplicate_raises_conflict(self):
        """
        Verifies duplicate registrations trigger a PermissionAlreadyExistsException.
        """
        resource, action = _split_code(PermissionCodes.USER_READ)
        with self.assertRaises(PermissionAlreadyExistsException):
            PermissionService.create_permission(
                name="Test Permission",
                resource=resource,
                action=action,
                description="Duplicate code catalog test."
            )

    def test_create_permission_invalid_code_raises_validation(self):
        """
        Verifies namespace structural mismatch triggers InvalidPermissionException.
        """
        with self.assertRaises(InvalidPermissionException):
            PermissionService.create_permission(
                name="Invalid Code Layout",
                resource="identity",
                action="INVALID_ACTION_FORMAT!",
                description="Invalid code layout check."
            )

    def test_update_permission_success(self):
        """
        Verifies updating human descriptions and names resolves correctly.
        """
        updated = PermissionService.update_permission(
            permission_id=str(self.permission.id),
            name="Updated Title",
            description="Updated details info."
        )
        self.assertEqual(updated.name, "Updated Title")
        self.assertEqual(updated.description, "Updated details info.")

    def test_update_system_permission_raises_modification_error(self):
        """
        Verifies editing names/details of system permissions is prohibited.
        """
        with self.assertRaises(SystemPermissionModificationException):
            PermissionService.update_permission(
                permission_id=str(self.system_permission.id),
                name="New Title"
            )

    def test_deactivate_permission_success(self):
        """
        Verifies toggling active states resolves cleanly.
        """
        deactivated = PermissionService.deactivate_permission(str(self.permission.id))
        self.assertFalse(deactivated.is_active)

    def test_deactivate_system_permission_raises_modification_error(self):
        """
        Verifies deactivating a system capability is blocked to prevent system lockout.
        """
        with self.assertRaises(SystemPermissionModificationException):
            PermissionService.deactivate_permission(str(self.system_permission.id))

    def test_activate_permission_success(self):
        """
        Verifies activating an inactive permission resolves successfully.
        """
        self.permission.is_active = False
        self.permission.save()

        activated = PermissionService.activate_permission(str(self.permission.id))
        self.assertTrue(activated.is_active)

    def test_get_permission_by_code_success(self):
        """
        Verifies finding a permission by its unique namespace code.
        """
        perm = PermissionService.get_permission_by_code(PermissionCodes.USER_READ)
        self.assertEqual(perm.id, self.permission.id)

    def test_get_permission_by_code_not_found(self):
        """
        Verifies query lookups on missing catalog items raise PermissionNotFoundException.
        """
        with self.assertRaises(PermissionNotFoundException):
            PermissionService.get_permission_by_code("non:existent:code")

    def test_permission_exists_resolves_boolean(self):
        """
        Verifies existence lookup evaluates correctly.
        """
        self.assertTrue(PermissionService.permission_exists(PermissionCodes.USER_READ))
        self.assertFalse(PermissionService.permission_exists("non:existent:code"))

from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.test import TestCase

from apps.authorization.constants import PermissionCodes
from apps.authorization.models import Permission


class PermissionModelTest(TestCase):
    """
    Unit test suite for the Permission Model (Authorization Permission Catalog).
    """

    def setUp(self):
        resource, action = PermissionCodes.USER_CREATE.rsplit(":", 1)
        self.valid_data = {
            "name": "Create Identity User",
            "code": PermissionCodes.USER_CREATE,
            "resource": resource,
            "action": action,
            "description": "Allows creation of user accounts inside the identity domain.",
        }

    def test_permission_creation_success(self):
        """
        Tests that a permission with valid details can be registered in the catalog.
        """
        permission = Permission.objects.create(**self.valid_data)

        self.assertIsNotNone(permission.id)
        self.assertEqual(permission.name, self.valid_data["name"])
        self.assertEqual(permission.code, self.valid_data["code"])
        self.assertEqual(permission.resource, self.valid_data["resource"])
        self.assertEqual(permission.action, self.valid_data["action"])
        self.assertEqual(permission.description, self.valid_data["description"])
        self.assertFalse(permission.is_system)
        self.assertTrue(permission.is_active)
        self.assertIsNotNone(permission.created_at)
        self.assertIsNotNone(permission.updated_at)

    def test_str_representation(self):
        """
        Tests that the string representation matches the expected format.
        """
        permission = Permission.objects.create(**self.valid_data)
        self.assertEqual(str(permission), f"{PermissionCodes.USER_CREATE} (Active)")

        permission.is_active = False
        permission.save()
        self.assertEqual(str(permission), f"{PermissionCodes.USER_CREATE} (Disabled)")

    def test_code_naming_convention_validation(self):
        """
        Tests that the code regex validator rejects invalid formats.
        """
        invalid_codes = [
            "identity user create",  # spaces
            "identity:User:create",  # uppercase
            "identity:user:create!",  # special characters
            "identity/user/create",  # forward slash
        ]

        for code in invalid_codes:
            with self.subTest(code=code):
                invalid_data = self.valid_data.copy()
                invalid_data["code"] = code
                with self.assertRaises(ValidationError) as context:
                    permission = Permission(**invalid_data)
                    permission.full_clean()
                self.assertIn("code", context.exception.message_dict)

    def test_clean_enforces_code_matches_resource_action(self):
        """
        Tests that the clean method raises a ValidationError if code doesn't match resource:action.
        """
        invalid_data = self.valid_data.copy()
        invalid_data["code"] = PermissionCodes.USER_DELETE  # mismatched action

        permission = Permission(**invalid_data)
        with self.assertRaises(ValidationError) as context:
            permission.full_clean()

        self.assertIn("code", context.exception.message_dict)
        expected = (
            "Permission code must match resource and action namespace. "
            f"Expected: '{PermissionCodes.USER_CREATE}'"
        )
        self.assertIn(expected, context.exception.message_dict["code"][0])

    def test_resource_regex_validation(self):
        """
        Tests that resource classification field rejects invalid characters.
        """
        invalid_resources = [
            "identity user",  # space
            "Identity:User",  # uppercase
            "identity:user$",  # special character
        ]

        for resource in invalid_resources:
            with self.subTest(resource=resource):
                invalid_data = {
                    "name": "Test",
                    "resource": resource,
                    "action": "read",
                    "code": f"{resource}:read",
                }
                permission = Permission(**invalid_data)
                with self.assertRaises(ValidationError) as context:
                    permission.full_clean()
                self.assertIn("resource", context.exception.message_dict)

    def test_action_regex_validation(self):
        """
        Tests that the action verb rejects invalid characters.
        """
        invalid_actions = [
            "read action",  # space
            "Read",  # uppercase
            "read*",  # special character
            "read:all",  # colon (not allowed in actions)
        ]
        resource, _ = PermissionCodes.USER_CREATE.rsplit(":", 1)

        for action in invalid_actions:
            with self.subTest(action=action):
                invalid_data = {
                    "name": "Test",
                    "resource": resource,
                    "action": action,
                    "code": f"{resource}:{action}",
                }
                permission = Permission(**invalid_data)
                with self.assertRaises(ValidationError) as context:
                    permission.full_clean()
                self.assertIn("action", context.exception.message_dict)

    def test_global_code_uniqueness(self):
        """
        Tests that global unique constraint on the code field is enforced at the database level.
        """
        Permission.objects.create(**self.valid_data)

        duplicate_perm = Permission(
            name="Another Name",
            code=self.valid_data["code"],
            resource="identity:user-alt",
            action="create-alt",
        )

        with self.assertRaises((ValidationError, IntegrityError)):
            duplicate_perm.save()

    def test_resource_action_uniqueness(self):
        """
        Tests that unique constraint on (resource, action) pair is enforced.
        """
        Permission.objects.create(**self.valid_data)

        duplicate_perm = Permission(
            name="Different Name",
            code=PermissionCodes.USER_CREATE,
            resource=self.valid_data["resource"],
            action=self.valid_data["action"],
        )

        with self.assertRaises((ValidationError, IntegrityError)):
            duplicate_perm.save()

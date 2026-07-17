"""
Unit and integration tests for DRF RBAC permission classes.
"""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from apps.authorization.constants import PermissionCodes, RoleSlugs
from apps.authorization.models import Permission, Role, RolePermission, UserRole
from apps.authorization.permissions import HasPermission, IsSuperAdmin
from apps.authorization.api.views import (
    PermissionListCreateAPIView,
    RoleListCreateAPIView,
)

User = get_user_model()


def _build_catalog(*, user, role_slug, permission_code, role_active=True,
                   assignment_active=True, permission_active=True,
                   mapping_active=True, expires_at=None):
    """Create a minimal effective RBAC graph for a user."""
    permission = Permission.objects.create(
        name=f"Perm {permission_code}",
        code=permission_code,
        resource=":".join(permission_code.split(":")[:2]),
        action=permission_code.split(":")[-1],
        is_system=False,
        is_active=permission_active,
    )
    role = Role.objects.create(
        name=f"Role {role_slug}",
        slug=role_slug,
        priority=500,
        is_system=False,
        is_active=role_active,
    )
    RolePermission.objects.create(
        role=role,
        permission=permission,
        is_active=mapping_active,
    )
    UserRole.objects.create(
        user=user,
        role=role,
        is_active=assignment_active,
        expires_at=expires_at,
    )
    return permission, role


class HasPermissionUnitTests(TestCase):
    """Direct unit tests for the HasPermission DRF class."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(
            email="rbac-user@example.com",
            password="SecurePass123!",
        )
        self.gate = HasPermission()

    def test_denies_unauthenticated_user(self):
        request = self.factory.get("/")
        request.user = User()  # anonymous-like: is_authenticated False via AnonymousUser normally
        from django.contrib.auth.models import AnonymousUser
        request.user = AnonymousUser()

        view = type("V", (), {"required_permission": PermissionCodes.PERMISSION_READ})()
        self.assertFalse(self.gate.has_permission(request, view))

    def test_denies_when_no_required_permission_configured(self):
        request = self.factory.get("/")
        force_authenticate(request, user=self.user)
        request.user = self.user

        view = type("V", (), {})()
        self.assertFalse(self.gate.has_permission(request, view))

    def test_allows_when_user_holds_required_permission(self):
        _build_catalog(
            user=self.user,
            role_slug="perm-reader",
            permission_code=PermissionCodes.PERMISSION_READ,
        )
        request = self.factory.get("/")
        force_authenticate(request, user=self.user)
        request.user = self.user

        view = type(
            "V",
            (),
            {"required_permission": PermissionCodes.PERMISSION_READ},
        )()
        self.assertTrue(self.gate.has_permission(request, view))

    def test_denies_when_user_lacks_required_permission(self):
        request = self.factory.get("/")
        force_authenticate(request, user=self.user)
        request.user = self.user

        view = type(
            "V",
            (),
            {"required_permission": PermissionCodes.PERMISSION_CREATE},
        )()
        self.assertFalse(self.gate.has_permission(request, view))

    def test_required_permissions_requires_all_codes(self):
        _build_catalog(
            user=self.user,
            role_slug="partial",
            permission_code=PermissionCodes.ROLE_READ,
        )
        request = self.factory.get("/")
        force_authenticate(request, user=self.user)
        request.user = self.user

        view = type(
            "V",
            (),
            {
                "required_permissions": [
                    PermissionCodes.ROLE_READ,
                    PermissionCodes.ROLE_CREATE,
                ]
            },
        )()
        self.assertFalse(self.gate.has_permission(request, view))

    def test_required_permission_map_uses_http_method(self):
        _build_catalog(
            user=self.user,
            role_slug="role-reader",
            permission_code=PermissionCodes.ROLE_READ,
        )
        request = self.factory.get("/")
        force_authenticate(request, user=self.user)
        request.user = self.user

        view = type(
            "V",
            (),
            {
                "required_permission_map": {
                    "GET": PermissionCodes.ROLE_READ,
                    "POST": PermissionCodes.ROLE_CREATE,
                }
            },
        )()
        self.assertTrue(self.gate.has_permission(request, view))

    def test_denies_when_role_inactive(self):
        permission, role = _build_catalog(
            user=self.user,
            role_slug="inactive-role",
            permission_code=PermissionCodes.PERMISSION_READ,
        )
        role.is_active = False
        role.save(update_fields=["is_active"])

        request = self.factory.get("/")
        force_authenticate(request, user=self.user)
        request.user = self.user

        view = type(
            "V",
            (),
            {"required_permission": PermissionCodes.PERMISSION_READ},
        )()
        self.assertFalse(self.gate.has_permission(request, view))

    def test_denies_when_user_role_expired(self):
        permission, role = _build_catalog(
            user=self.user,
            role_slug="expired-role",
            permission_code=PermissionCodes.PERMISSION_READ,
        )
        assignment = UserRole.objects.get(user=self.user, role=role)
        # Bypass model clean() which rejects past expires_at on create.
        UserRole.objects.filter(pk=assignment.pk).update(
            expires_at=timezone.now() - timedelta(hours=1)
        )

        request = self.factory.get("/")
        force_authenticate(request, user=self.user)
        request.user = self.user

        view = type(
            "V",
            (),
            {"required_permission": PermissionCodes.PERMISSION_READ},
        )()
        self.assertFalse(self.gate.has_permission(request, view))

    def test_denies_when_permission_inactive(self):
        permission, role = _build_catalog(
            user=self.user,
            role_slug="dead-perm",
            permission_code=PermissionCodes.PERMISSION_READ,
        )
        permission.is_active = False
        permission.save(update_fields=["is_active"])

        request = self.factory.get("/")
        force_authenticate(request, user=self.user)
        request.user = self.user

        view = type(
            "V",
            (),
            {"required_permission": PermissionCodes.PERMISSION_READ},
        )()
        self.assertFalse(self.gate.has_permission(request, view))


class IsSuperAdminUnitTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(
            email="super@example.com",
            password="SecurePass123!",
        )
        self.gate = IsSuperAdmin()

    def test_allows_super_admin_slug(self):
        role = Role.objects.create(
            name="Super Administrator",
            slug=RoleSlugs.SUPER_ADMIN,
            priority=1000,
            is_system=True,
            is_active=True,
        )
        UserRole.objects.create(user=self.user, role=role, is_active=True)

        request = self.factory.get("/")
        force_authenticate(request, user=self.user)
        request.user = self.user
        self.assertTrue(self.gate.has_permission(request, type("V", (), {})()))

    def test_denies_non_super_admin(self):
        request = self.factory.get("/")
        force_authenticate(request, user=self.user)
        request.user = self.user
        self.assertFalse(self.gate.has_permission(request, type("V", (), {})()))


class AuthorizationAPIRBACTests(TestCase):
    """End-to-end HTTP status checks for 401 / 403 / 200 on authorization APIs."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(
            email="api-rbac@example.com",
            password="SecurePass123!",
        )

    def _dispatch(self, view_cls, method="get", user=None, data=None):
        factory_method = getattr(self.factory, method)
        request = factory_method(
            "/api/v1/authorization/permissions/",
            data=data or {},
            format="json",
        )
        if user is not None:
            force_authenticate(request, user=user)
        return view_cls.as_view()(request)

    def test_unauthenticated_returns_401(self):
        response = self._dispatch(PermissionListCreateAPIView, method="get")
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.data.get("success", True))

    def test_authenticated_without_permission_returns_403(self):
        response = self._dispatch(
            PermissionListCreateAPIView, method="get", user=self.user
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data["success"], False)
        self.assertIn("permission", response.data["message"].lower())

    def test_authenticated_with_permission_returns_200(self):
        _build_catalog(
            user=self.user,
            role_slug="catalog-reader",
            permission_code=PermissionCodes.PERMISSION_READ,
        )
        response = self._dispatch(
            PermissionListCreateAPIView, method="get", user=self.user
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["success"])

    def test_post_requires_create_permission_not_read(self):
        _build_catalog(
            user=self.user,
            role_slug="catalog-reader-only",
            permission_code=PermissionCodes.PERMISSION_READ,
        )
        response = self._dispatch(
            PermissionListCreateAPIView,
            method="post",
            user=self.user,
            data={
                "name": "X",
                "resource": "organization",
                "action": "create",
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_role_list_allowed_with_role_read(self):
        _build_catalog(
            user=self.user,
            role_slug="role-lister",
            permission_code=PermissionCodes.ROLE_READ,
        )
        response = self._dispatch(
            RoleListCreateAPIView, method="get", user=self.user
        )
        self.assertEqual(response.status_code, 200)

from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

User = get_user_model()


class UserListingAPITests(APITestCase):
    """
    Test suite for Milestone 1: User Listing endpoint
    """

    def setUp(self):
        self.user1 = User.objects.create_user(
            username="user_one",
            email="user1@test.com",
            password="password123",
            first_name="First1",
            last_name="Last1",
        )
        self.user2 = User.objects.create_user(
            username="user_two",
            email="user2@test.com",
            password="password123",
            first_name="First2",
            last_name="Last2",
        )

    def _grant_user_read(self, user):
        from apps.authorization.models import Role, Permission, RolePermission, UserRole
        from apps.authorization.constants import PermissionCodes
        admin_role, _ = Role.objects.get_or_create(name="Admin Role", slug="admin-test", defaults={"priority": 900})
        perm, _ = Permission.objects.get_or_create(
            code=PermissionCodes.USER_READ,
            defaults={"name": "Read Users", "resource": "identity:user", "action": "read"}
        )
        RolePermission.objects.get_or_create(role=admin_role, permission=perm)
        UserRole.objects.get_or_create(user=user, role=admin_role)

    def test_list_users_authenticated(self):
        """
        An authenticated user should be able to retrieve the user list.
        """
        self._grant_user_read(self.user1)
        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-list")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["success"])
        self.assertEqual(response.data["message"], "Data retrieved successfully.")

        users_data = response.data["data"]["results"]
        self.assertEqual(len(users_data), 2)

        # Check list fields formatting
        emails = [u["email"] for u in users_data]
        self.assertIn("user1@test.com", emails)
        self.assertIn("user2@test.com", emails)

        # Ensure full_name read-only property is present
        user1_data = next(u for u in users_data if u["email"] == "user1@test.com")
        self.assertEqual(user1_data["full_name"], "First1 Last1")

    def test_list_users_unauthenticated(self):
        """
        An unauthenticated request should be rejected with 401.
        """
        url = reverse("users:user-list")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_user_detail_self(self):
        """
        A user should be allowed to fetch their own details.
        """
        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-detail", kwargs={"pk": self.user1.id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["data"]["email"], self.user1.email)
        self.assertEqual(response.data["data"]["full_name"], "First1 Last1")

    def test_get_user_detail_other_forbidden(self):
        """
        A user should be blocked from reading another user's profile details.
        """
        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-detail", kwargs={"pk": self.user2.id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(response.data["success"])

    def test_get_user_detail_other_admin_allowed(self):
        """
        A user with identity:user:read permission should be allowed to view details of others.
        """
        from apps.authorization.models import Role, Permission, RolePermission, UserRole
        from apps.authorization.constants import PermissionCodes

        # Setup Admin Role & Permission
        admin_role = Role.objects.create(name="Admin Role", slug="admin-test", priority=900)
        perm, _ = Permission.objects.get_or_create(
            code=PermissionCodes.USER_READ,
            defaults={"name": "Read Users", "resource": "identity:user", "action": "read"}
        )
        RolePermission.objects.get_or_create(role=admin_role, permission=perm)
        UserRole.objects.create(user=self.user1, role=admin_role)

        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-detail", kwargs={"pk": self.user2.id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["data"]["email"], self.user2.email)

    def test_update_user_profile_self(self):
        """
        A user can update their own profile fields.
        """
        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-detail", kwargs={"pk": self.user1.id})
        data = {
            "first_name": "UpdatedFirst",
            "last_name": "UpdatedLast",
            "username": "updated_one"
        }
        response = self.client.patch(url, data=data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["success"])
        self.assertEqual(response.data["data"]["first_name"], "UpdatedFirst")
        self.assertEqual(response.data["data"]["last_name"], "UpdatedLast")
        self.assertEqual(response.data["data"]["username"], "updated_one")

    def test_update_user_profile_other_forbidden(self):
        """
        A user cannot update another user's profile details.
        """
        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-detail", kwargs={"pk": self.user2.id})
        data = {
            "first_name": "HackName"
        }
        response = self.client.patch(url, data=data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_update_user_profile_other_admin_allowed(self):
        """
        A user with identity:user:update can edit others' profiles.
        """
        from apps.authorization.models import Role, Permission, RolePermission, UserRole
        from apps.authorization.constants import PermissionCodes

        # Setup Admin Role with USER_UPDATE permission
        admin_role = Role.objects.create(name="Admin Update Role", slug="admin-update", priority=900)
        perm, _ = Permission.objects.get_or_create(
            code=PermissionCodes.USER_UPDATE,
            defaults={"name": "Update Users", "resource": "identity:user", "action": "update"}
        )
        RolePermission.objects.get_or_create(role=admin_role, permission=perm)
        UserRole.objects.create(user=self.user1, role=admin_role)

        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-detail", kwargs={"pk": self.user2.id})
        data = {
            "first_name": "AdminUpdated"
        }
        response = self.client.patch(url, data=data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["data"]["first_name"], "AdminUpdated")

    def test_update_user_profile_duplicate_username(self):
        """
        Validation should reject a duplicate username request.
        """
        self.user2.username = "duplicate_user"
        self.user2.save()

        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-detail", kwargs={"pk": self.user1.id})
        data = {
            "username": "duplicate_user"
        }
        response = self.client.patch(url, data=data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["success"])
        self.assertIn("username", response.data["errors"])

    def test_activate_user_success(self):
        """
        An admin can activate a deactivated user account.
        """
        from apps.authorization.models import Role, Permission, RolePermission, UserRole
        from apps.authorization.constants import PermissionCodes

        # Setup Admin Role with USER_MANAGE permission
        admin_role = Role.objects.create(name="Admin Manage Role", slug="admin-manage", priority=900)
        perm, _ = Permission.objects.get_or_create(
            code=PermissionCodes.USER_MANAGE,
            defaults={"name": "Manage Users", "resource": "identity:user", "action": "manage"}
        )
        RolePermission.objects.get_or_create(role=admin_role, permission=perm)
        UserRole.objects.create(user=self.user1, role=admin_role)

        # Set user2 active=False
        self.user2.is_active = False
        self.user2.save()

        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-activate", kwargs={"pk": self.user2.id})
        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user2.refresh_from_db()
        self.assertTrue(self.user2.is_active)

    def test_deactivate_user_success(self):
        """
        An admin can deactivate an active user account.
        """
        from apps.authorization.models import Role, Permission, RolePermission, UserRole
        from apps.authorization.constants import PermissionCodes

        # Setup Admin Role with USER_MANAGE permission
        admin_role = Role.objects.create(name="Admin Manage Role", slug="admin-manage", priority=900)
        perm, _ = Permission.objects.get_or_create(
            code=PermissionCodes.USER_MANAGE,
            defaults={"name": "Manage Users", "resource": "identity:user", "action": "manage"}
        )
        RolePermission.objects.get_or_create(role=admin_role, permission=perm)
        UserRole.objects.create(user=self.user1, role=admin_role)

        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-deactivate", kwargs={"pk": self.user2.id})
        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user2.refresh_from_db()
        self.assertFalse(self.user2.is_active)

    def test_deactivate_self_fails(self):
        """
        A user cannot deactivate their own account.
        """
        from apps.authorization.models import Role, Permission, RolePermission, UserRole
        from apps.authorization.constants import PermissionCodes

        # Setup Admin Role with USER_MANAGE permission
        admin_role = Role.objects.create(name="Admin Manage Role", slug="admin-manage", priority=900)
        perm, _ = Permission.objects.get_or_create(
            code=PermissionCodes.USER_MANAGE,
            defaults={"name": "Manage Users", "resource": "identity:user", "action": "manage"}
        )
        RolePermission.objects.get_or_create(role=admin_role, permission=perm)
        UserRole.objects.create(user=self.user1, role=admin_role)

        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-deactivate", kwargs={"pk": self.user1.id})
        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["success"])
        self.assertEqual(response.data["message"], "You cannot deactivate your own account.")

    def test_deactivate_owner_fails(self):
        """
        Deactivating an organization owner should fail.
        """
        from apps.authorization.models import Role, Permission, RolePermission, UserRole
        from apps.authorization.constants import PermissionCodes
        from apps.organizations.models import Organization

        # Setup Admin Role with USER_MANAGE permission
        admin_role = Role.objects.create(name="Admin Manage Role", slug="admin-manage", priority=900)
        perm, _ = Permission.objects.get_or_create(
            code=PermissionCodes.USER_MANAGE,
            defaults={"name": "Manage Users", "resource": "identity:user", "action": "manage"}
        )
        RolePermission.objects.get_or_create(role=admin_role, permission=perm)
        UserRole.objects.create(user=self.user1, role=admin_role)

        # Make user2 an owner of an organization
        Organization.objects.create(
            name="Test Org",
            slug="test-org",
            owner=self.user2
        )

        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-deactivate", kwargs={"pk": self.user2.id})
        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["success"])
        self.assertIn("owner of an active organization", response.data["message"])

    def test_lock_user_success(self):
        """
        An admin can lock a user account.
        """
        from apps.authorization.models import Role, Permission, RolePermission, UserRole
        from apps.authorization.constants import PermissionCodes

        # Setup Admin Role with USER_MANAGE permission
        admin_role = Role.objects.create(name="Admin Manage Role", slug="admin-manage", priority=900)
        perm, _ = Permission.objects.get_or_create(
            code=PermissionCodes.USER_MANAGE,
            defaults={"name": "Manage Users", "resource": "identity:user", "action": "manage"}
        )
        RolePermission.objects.get_or_create(role=admin_role, permission=perm)
        UserRole.objects.create(user=self.user1, role=admin_role)

        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-lock", kwargs={"pk": self.user2.id})
        future_time = timezone.now() + timezone.timedelta(days=1)
        data = {
            "locked_until": future_time.isoformat()
        }
        response = self.client.post(url, data=data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user2.refresh_from_db()
        self.assertTrue(self.user2.is_locked)
        self.assertIsNotNone(self.user2.locked_until)

    def test_lock_user_past_date_fails(self):
        """
        An admin cannot lock a user account with a past date.
        """
        from apps.authorization.models import Role, Permission, RolePermission, UserRole
        from apps.authorization.constants import PermissionCodes

        # Setup Admin Role with USER_MANAGE permission
        admin_role = Role.objects.create(name="Admin Manage Role", slug="admin-manage", priority=900)
        perm, _ = Permission.objects.get_or_create(
            code=PermissionCodes.USER_MANAGE,
            defaults={"name": "Manage Users", "resource": "identity:user", "action": "manage"}
        )
        RolePermission.objects.get_or_create(role=admin_role, permission=perm)
        UserRole.objects.create(user=self.user1, role=admin_role)

        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-lock", kwargs={"pk": self.user2.id})
        past_time = timezone.now() - timezone.timedelta(days=1)
        data = {
            "locked_until": past_time.isoformat()
        }
        response = self.client.post(url, data=data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["success"])
        self.assertIn("locked_until", response.data["errors"])

    def test_lock_self_fails(self):
        """
        A user cannot lock their own account.
        """
        from apps.authorization.models import Role, Permission, RolePermission, UserRole
        from apps.authorization.constants import PermissionCodes

        # Setup Admin Role with USER_MANAGE permission
        admin_role = Role.objects.create(name="Admin Manage Role", slug="admin-manage", priority=900)
        perm, _ = Permission.objects.get_or_create(
            code=PermissionCodes.USER_MANAGE,
            defaults={"name": "Manage Users", "resource": "identity:user", "action": "manage"}
        )
        RolePermission.objects.get_or_create(role=admin_role, permission=perm)
        UserRole.objects.create(user=self.user1, role=admin_role)

        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-lock", kwargs={"pk": self.user1.id})
        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["success"])
        self.assertEqual(response.data["message"], "You cannot lock your own account.")

    def test_unlock_user_success(self):
        """
        An admin can unlock a user account.
        """
        from apps.authorization.models import Role, Permission, RolePermission, UserRole
        from apps.authorization.constants import PermissionCodes

        # Setup Admin Role with USER_MANAGE permission
        admin_role = Role.objects.create(name="Admin Manage Role", slug="admin-manage", priority=900)
        perm, _ = Permission.objects.get_or_create(
            code=PermissionCodes.USER_MANAGE,
            defaults={"name": "Manage Users", "resource": "identity:user", "action": "manage"}
        )
        RolePermission.objects.get_or_create(role=admin_role, permission=perm)
        UserRole.objects.create(user=self.user1, role=admin_role)

        # Pre-lock user2
        self.user2.is_locked = True
        self.user2.locked_until = timezone.now() + timezone.timedelta(days=1)
        self.user2.failed_login_attempts = 5
        self.user2.save()

        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-unlock", kwargs={"pk": self.user2.id})
        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user2.refresh_from_db()
        self.assertFalse(self.user2.is_locked)
        self.assertIsNone(self.user2.locked_until)
        self.assertEqual(self.user2.failed_login_attempts, 0)

    def test_list_users_pagination(self):
        """
        Verify users listing endpoint behaves correctly with pagination.
        """
        self._grant_user_read(self.user1)
        # Create 25 additional users (total 27 with user1 and user2)
        for i in range(25):
            User.objects.create_user(
                username=f"paginated_user_{i}",
                email=f"page_user_{i}@test.com",
                password="password123"
            )

        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-list")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["success"])
        # Standard page size limit is 20
        self.assertEqual(len(response.data["data"]["results"]), 20)
        self.assertEqual(response.data["data"]["count"], 27)
        self.assertIsNotNone(response.data["data"]["next"])

    def test_list_users_search(self):
        """
        Verify search parameter returns only matching records.
        """
        self._grant_user_read(self.user1)
        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-list")
        response = self.client.get(url, {"search": "user_two"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Search returns pagination envelope when pagination is applied, or if standard lists
        results = response.data["data"]["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["email"], "user2@test.com")

    def test_list_users_filtering(self):
        """
        Verify active status filter excludes inactive accounts.
        """
        self._grant_user_read(self.user1)
        self.user2.is_active = False
        self.user2.save()

        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-list")
        response = self.client.get(url, {"is_active": "false"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = response.data["data"]["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["email"], "user2@test.com")

    def test_list_users_ordering(self):
        """
        Verify ordering returns records in correct alphanumeric sequences.
        """
        self._grant_user_read(self.user1)
        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-list")

        # Ascending email order: user1@test.com before user2@test.com
        response = self.client.get(url, {"ordering": "email"})
        results = response.data["data"]["results"]
        self.assertEqual(results[0]["email"], "user1@test.com")
        self.assertEqual(results[1]["email"], "user2@test.com")

        # Descending email order: user2@test.com before user1@test.com
        response = self.client.get(url, {"ordering": "-email"})
        results = response.data["data"]["results"]
        self.assertEqual(results[0]["email"], "user2@test.com")
        self.assertEqual(results[1]["email"], "user1@test.com")

    def test_assign_system_role_success(self):
        """
        An admin with user:manage can assign a role to a user.
        """
        from apps.authorization.models import Role, Permission, RolePermission, UserRole
        from apps.authorization.constants import PermissionCodes

        # Setup Admin Role with USER_MANAGE permission
        admin_role = Role.objects.create(name="Admin Manage Role", slug="admin-manage", priority=900)
        perm, _ = Permission.objects.get_or_create(
            code=PermissionCodes.USER_MANAGE,
            defaults={"name": "Manage Users", "resource": "identity:user", "action": "manage"}
        )
        RolePermission.objects.get_or_create(role=admin_role, permission=perm)
        UserRole.objects.create(user=self.user1, role=admin_role)

        # Target Role to assign
        target_role = Role.objects.create(name="Target Role", slug="target-role", priority=500)

        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-assign-role", kwargs={"pk": self.user2.id})
        data = {
            "role_id": str(target_role.id),
            "assignment_reason": "Testing assign system role"
        }
        response = self.client.post(url, data=data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(UserRole.objects.filter(user=self.user2, role=target_role, is_active=True).exists())

    def test_revoke_system_role_success(self):
        """
        An admin with user:manage can revoke a role from a user.
        """
        from apps.authorization.models import Role, Permission, RolePermission, UserRole
        from apps.authorization.constants import PermissionCodes

        # Setup Admin Role with USER_MANAGE permission
        admin_role = Role.objects.create(name="Admin Manage Role", slug="admin-manage", priority=900)
        perm, _ = Permission.objects.get_or_create(
            code=PermissionCodes.USER_MANAGE,
            defaults={"name": "Manage Users", "resource": "identity:user", "action": "manage"}
        )
        RolePermission.objects.get_or_create(role=admin_role, permission=perm)
        UserRole.objects.create(user=self.user1, role=admin_role)

        # Target Role to revoke
        target_role = Role.objects.create(name="Target Role", slug="target-role", priority=500)
        UserRole.objects.create(user=self.user2, role=target_role, assigned_by=self.user1, is_active=True)

        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-revoke-role", kwargs={"pk": self.user2.id})
        data = {
            "role_id": str(target_role.id)
        }
        response = self.client.post(url, data=data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(UserRole.objects.filter(user=self.user2, role=target_role, is_active=True).exists())

    def test_assign_role_unauthorized(self):
        """
        An unauthorized user without user:manage is blocked from assigning roles.
        """
        from apps.authorization.models import Role

        target_role = Role.objects.create(name="Target Role", slug="target-role", priority=500)

        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-assign-role", kwargs={"pk": self.user2.id})
        data = {
            "role_id": str(target_role.id)
        }
        response = self.client.post(url, data=data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_users_tenant_isolation(self):
        """
        Verify tenant isolation ensures users only see other members in their shared organizations.
        """
        from apps.organizations.models import Organization, OrganizationMembership
        from apps.organizations.constants import MembershipStatus
        from apps.authorization.models import Role as AuthRole

        # Set up a member role
        member_role = AuthRole.objects.create(name="Member Role", slug="member-test", priority=100)

        # Create Org A and Org B
        org_a = Organization.objects.create(name="Org A", slug="org-a", owner=self.user1)
        org_b = Organization.objects.create(name="Org B", slug="org-b", owner=self.user2)

        # User 3 (new user) will join Org A
        user3 = User.objects.create_user(
            username="user_three",
            email="user3@test.com",
            password="password123"
        )

        # Create memberships: user1 and user3 in Org A. user2 is in Org B.
        OrganizationMembership.objects.create(
            organization=org_a,
            user=self.user1,
            role=member_role,
            status=MembershipStatus.ACTIVE
        )
        OrganizationMembership.objects.create(
            organization=org_a,
            user=user3,
            role=member_role,
            status=MembershipStatus.ACTIVE
        )
        OrganizationMembership.objects.create(
            organization=org_b,
            user=self.user2,
            role=member_role,
            status=MembershipStatus.ACTIVE
        )

        # Force authenticate as user1 (who has no global USER_READ permission)
        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-list")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = response.data["data"]["results"]
        emails = [u["email"] for u in results]

        # user1 should only see themselves (user1) and user3 (shared Org A), but NOT user2 (Org B)
        self.assertIn("user1@test.com", emails)
        self.assertIn("user3@test.com", emails)
        self.assertNotIn("user2@test.com", emails)

    def test_list_users_filter_by_organization_slug(self):
        """
        Verify that lists can be filtered by organization slug for authorized users.
        """
        from apps.organizations.models import Organization, OrganizationMembership
        from apps.organizations.constants import MembershipStatus
        from apps.authorization.models import Role as AuthRole, Permission, RolePermission, UserRole
        from apps.authorization.constants import PermissionCodes

        # Setup Admin role for user1 to bypass tenant isolation
        admin_role = AuthRole.objects.create(name="Admin Manage Role", slug="admin-manage", priority=900)
        perm, _ = Permission.objects.get_or_create(
            code=PermissionCodes.USER_READ,
            defaults={"name": "Read Users", "resource": "identity:user", "action": "read"}
        )
        RolePermission.objects.get_or_create(role=admin_role, permission=perm)
        UserRole.objects.create(user=self.user1, role=admin_role)

        member_role = AuthRole.objects.create(name="Member Role", slug="member-test", priority=100)

        # Create Org A
        org_a = Organization.objects.create(name="Org A", slug="org-a", owner=self.user1)

        # Add user2 to Org A
        OrganizationMembership.objects.create(
            organization=org_a,
            user=self.user2,
            role=member_role,
            status=MembershipStatus.ACTIVE
        )

        # Add user1 to Org A
        OrganizationMembership.objects.create(
            organization=org_a,
            user=self.user1,
            role=member_role,
            status=MembershipStatus.ACTIVE
        )

        self.client.force_authenticate(user=self.user1)
        url = reverse("users:user-list")

        # Filter by org-a slug: should return user2 (in org_a) and user1 (owner/member org_a)
        response = self.client.get(url, {"organization_slug": "org-a"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = response.data["data"]["results"]
        emails = [u["email"] for u in results]
        self.assertIn("user1@test.com", emails)
        self.assertIn("user2@test.com", emails)








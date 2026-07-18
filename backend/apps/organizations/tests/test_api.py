import uuid
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from apps.authorization.models import Role, UserRole
from apps.authorization.constants import RoleSlugs, PermissionCodes
from apps.organizations.models import Organization, OrganizationMembership, OrganizationInvitation, OrganizationSettings
from apps.organizations.constants import OrganizationStatus, MembershipStatus, InvitationStatus

User = get_user_model()


class OrganizationAPITests(APITestCase):
    """
    Integration and end-to-end tests for the Organizations REST API endpoints.
    """

    def setUp(self):
        self.owner = User.objects.create_user(
            username="org_owner",
            email="owner@test.com",
            password="password123"
        )
        self.member = User.objects.create_user(
            username="org_member",
            email="member@test.com",
            password="password123"
        )
        self.non_member = User.objects.create_user(
            username="non_member",
            email="other@test.com",
            password="password123"
        )

        # Seed roles
        self.admin_role = Role.objects.create(
            name="Administrator",
            slug=RoleSlugs.ADMIN,
            priority=800
        )
        self.employee_role = Role.objects.create(
            name="Employee",
            slug=RoleSlugs.EMPLOYEE,
            priority=100
        )

        # Map global permissions to owner (so they pass PermissionCodes gates)
        # We can map global permissions using user roles if the permission class evaluates them
        self.owner_global_role = Role.objects.create(
            name="Super Admin",
            slug="global-admin",
            priority=1000
        )
        from apps.authorization.models import Permission, RolePermission
        for code in [PermissionCodes.ORGANIZATION_CREATE, PermissionCodes.ORGANIZATION_READ, PermissionCodes.ORGANIZATION_UPDATE, PermissionCodes.ORGANIZATION_DELETE, PermissionCodes.ORGANIZATION_MANAGE]:
            resource, action = code.rsplit(":", 1)
            perm, _ = Permission.objects.get_or_create(
                code=code,
                defaults={
                    "name": code,
                    "resource": resource,
                    "action": action
                }
            )
            RolePermission.objects.create(role=self.owner_global_role, permission=perm)

        UserRole.objects.create(user=self.owner, role=self.owner_global_role)

        # Authenticate owner by default
        self.client.force_authenticate(user=self.owner)

    def test_create_organization_api(self):
        url = reverse("organizations:organization-list-create")
        data = {
            "name": "Acme Inc",
            "slug": "acme-inc",
            "description": "Acme corporate workspace",
            "timezone": "EST",
            "country": "US",
            "session_timeout_minutes": 45
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["success"], True)
        self.assertEqual(response.data["data"]["name"], "Acme Inc")
        self.assertEqual(response.data["data"]["slug"], "acme-inc")

    def test_retrieve_organization_api(self):
        org = Organization.objects.create(
            name="Org Test",
            slug="org-test",
            owner=self.owner,
            status=OrganizationStatus.ACTIVE
        )
        # Add settings
        OrganizationSettings.objects.create(organization=org, timezone="UTC")
        # Add owner membership
        OrganizationMembership.objects.create(
            organization=org,
            user=self.owner,
            role=self.admin_role,
            status=MembershipStatus.ACTIVE
        )

        url = reverse("organizations:organization-detail", kwargs={"pk": org.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["data"]["id"], str(org.id))

    def test_retrieve_organization_unauthorized_barrier(self):
        org = Organization.objects.create(
            name="Org Test Unauth",
            slug="org-test-unauth",
            owner=self.owner,
            status=OrganizationStatus.ACTIVE
        )
        # Authenticate a user who has no membership/association with this org
        self.client.force_authenticate(user=self.non_member)

        url = reverse("organizations:organization-detail", kwargs={"pk": org.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_update_settings_api(self):
        org = Organization.objects.create(
            name="Settings Org",
            slug="settings-org",
            owner=self.owner,
            status=OrganizationStatus.ACTIVE
        )
        OrganizationSettings.objects.create(organization=org, timezone="UTC")
        OrganizationMembership.objects.create(
            organization=org,
            user=self.owner,
            role=self.admin_role,
            status=MembershipStatus.ACTIVE
        )

        url = reverse("organizations:settings-detail", kwargs={"pk": org.id})
        data = {
            "timezone": "PST",
            "branding_name": "Acme Brand",
            "session_timeout_minutes": 15
        }
        response = self.client.patch(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["data"]["timezone"], "PST")
        self.assertEqual(response.data["data"]["session_timeout_minutes"], 15)

    def test_invite_member_api(self):
        org = Organization.objects.create(
            name="Invite Org",
            slug="invite-org",
            owner=self.owner,
            status=OrganizationStatus.ACTIVE
        )
        OrganizationMembership.objects.create(
            organization=org,
            user=self.owner,
            role=self.admin_role,
            status=MembershipStatus.ACTIVE
        )

        url = reverse("organizations:invitation-list-create", kwargs={"pk": org.id})
        data = {
            "email": "invitee@test.com",
            "role_slug": RoleSlugs.EMPLOYEE,
            "expires_in_days": 3
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["data"]["email"], "invitee@test.com")

    def test_accept_invitation_api(self):
        org = Organization.objects.create(
            name="Accept Org",
            slug="accept-org",
            owner=self.owner,
            status=OrganizationStatus.ACTIVE
        )
        # Pre-register member profile in system
        invitee = User.objects.create_user(
            username="invitee_user",
            email="invitee@test.com",
            password="password123"
        )
        invitation = OrganizationInvitation.objects.create(
            organization=org,
            email="invitee@test.com",
            invited_by=self.owner,
            status=InvitationStatus.PENDING,
            expires_at=timezone.now() + timezone.timedelta(days=7) if hasattr(self, "timezone") else (org.created_at + timezone.timedelta(days=7))
        )

        # Authenticate the invitee
        self.client.force_authenticate(user=invitee)

        url = reverse("organizations:invitation-accept", kwargs={"token": invitation.token})
        response = self.client.post(url, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["data"]["status"], MembershipStatus.ACTIVE)

    def test_transfer_ownership_api(self):
        org = Organization.objects.create(
            name="Transfer Org",
            slug="transfer-org",
            owner=self.owner,
            status=OrganizationStatus.ACTIVE
        )
        # Map memberships
        self.owner_membership = OrganizationMembership.objects.create(
            organization=org,
            user=self.owner,
            role=self.admin_role,
            status=MembershipStatus.ACTIVE
        )
        self.new_owner_membership = OrganizationMembership.objects.create(
            organization=org,
            user=self.member,
            role=self.admin_role,
            status=MembershipStatus.ACTIVE
        )

        url = reverse("organizations:ownership-transfer", kwargs={"pk": org.id})
        data = {
            "new_owner_id": str(self.member.id)
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["data"]["owner"]["id"], str(self.member.id))

    def test_soft_delete_lifecycle_api(self):
        org = Organization.objects.create(
            name="Lifecycle Org",
            slug="lifecycle-org",
            owner=self.owner,
            status=OrganizationStatus.ACTIVE
        )
        OrganizationSettings.objects.create(organization=org, timezone="UTC")
        OrganizationMembership.objects.create(
            organization=org,
            user=self.owner,
            role=self.admin_role,
            status=MembershipStatus.ACTIVE
        )

        detail_url = reverse("organizations:organization-detail", kwargs={"pk": org.id})
        list_url = reverse("organizations:organization-list-create")

        # 1. DELETE /organizations/{id}/ should succeed and soft-delete organization
        delete_response = self.client.delete(detail_url)
        self.assertEqual(delete_response.status_code, status.HTTP_200_OK)

        # 2. GET /organizations/ should NOT return the deleted organization
        list_response = self.client.get(list_url)
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        # The list payload wraps results in a paginated dictionary structure
        results = list_response.data["data"]["results"]
        org_ids = [item["id"] for item in results]
        self.assertNotIn(str(org.id), org_ids)

        # 3. GET /organizations/{id}/ should return 404 Not Found
        get_response = self.client.get(detail_url)
        self.assertEqual(get_response.status_code, status.HTTP_404_NOT_FOUND)

        # 4. PATCH /organizations/{id}/ should return 404 Not Found
        patch_response = self.client.patch(detail_url, {"name": "New Name"}, format="json")
        self.assertEqual(patch_response.status_code, status.HTTP_404_NOT_FOUND)

        # 5. DELETE /organizations/{id}/ should return 404 Not Found
        delete_again_response = self.client.delete(detail_url)
        self.assertEqual(delete_again_response.status_code, status.HTTP_404_NOT_FOUND)

    def test_membership_soft_removal_api(self):
        org = Organization.objects.create(
            name="Membership Lifecycle Org",
            slug="membership-lifecycle-org",
            owner=self.owner,
            status=OrganizationStatus.ACTIVE
        )
        OrganizationSettings.objects.create(organization=org, timezone="UTC")
        owner_membership = OrganizationMembership.objects.create(
            organization=org,
            user=self.owner,
            role=self.admin_role,
            status=MembershipStatus.ACTIVE
        )
        member_membership = OrganizationMembership.objects.create(
            organization=org,
            user=self.member,
            role=self.employee_role,
            status=MembershipStatus.ACTIVE
        )

        members_list_url = reverse("organizations:membership-list-create", kwargs={"pk": org.id})
        member_detail_url = reverse("organizations:membership-detail", kwargs={"pk": org.id, "membership_id": member_membership.id})

        # 1. Verify GET /organizations/{id}/members/ returns both members
        get_response = self.client.get(members_list_url)
        self.assertEqual(get_response.status_code, status.HTTP_200_OK)
        results = get_response.data["data"]["results"]
        member_ids = [item["id"] for item in results]
        self.assertIn(str(owner_membership.id), member_ids)
        self.assertIn(str(member_membership.id), member_ids)

        # 2. DELETE /organizations/{id}/members/{membership_id}/ should succeed
        delete_response = self.client.delete(member_detail_url)
        self.assertEqual(delete_response.status_code, status.HTTP_200_OK)

        # 3. Subsequent GET /organizations/{id}/members/ must NOT return the removed member
        get_after_response = self.client.get(members_list_url)
        self.assertEqual(get_after_response.status_code, status.HTTP_200_OK)
        results_after = get_after_response.data["data"]["results"]
        member_ids_after = [item["id"] for item in results_after]
        self.assertIn(str(owner_membership.id), member_ids_after)
        self.assertNotIn(str(member_membership.id), member_ids_after)

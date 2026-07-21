from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from apps.authorization.constants import PermissionCodes
from apps.authorization.permissions import HasPermission
from apps.authorization.services.authorization_service import AuthorizationService
from apps.authorization.services.user_role_service import UserRoleService
from apps.common.responses import success_response, error_response
from apps.common.pagination import StandardPageNumberPagination
from apps.core.swagger import user_list_swagger_decorator, user_action_swagger_decorator
from apps.users.api.serializers import (
    UserListSerializer,
    UserDetailSerializer,
    UserUpdateSerializer,
    UserLockSerializer,
    UserRoleAssignSerializer,
    UserRoleRevokeSerializer,
)
from apps.users.services.listing_service import UserListingService
from apps.users.services.profile_service import UserProfileService
from apps.users.services.status_service import UserStatusService


@user_list_swagger_decorator()
class UserListAPIView(APIView):
    """
    API endpoint for listing users with filtering, searching, ordering, and pagination.
    """

    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ["is_active", "is_verified", "is_locked"]
    search_fields = ["email", "username", "first_name", "last_name"]
    ordering_fields = ["email", "username", "created_at"]
    ordering = ["-created_at"]

    def get(self, request):
        queryset = UserListingService.list_users()

        # Tenant Isolation Boundary: restrict non-admins to users sharing an active organization
        if not AuthorizationService.has_permission(request.user, PermissionCodes.USER_READ):
            from apps.organizations.models import OrganizationMembership
            from apps.organizations.constants import MembershipStatus
            actor_org_ids = request.user.organization_memberships.filter(
                status=MembershipStatus.ACTIVE
            ).values_list("organization_id", flat=True)
            shared_member_ids = OrganizationMembership.objects.filter(
                organization_id__in=actor_org_ids,
                status=MembershipStatus.ACTIVE
            ).values_list("user_id", flat=True)
            queryset = queryset.filter(id__in=shared_member_ids)

        # Organization ID/Slug filtering lookups
        org_id = request.query_params.get("organization_id")
        if org_id:
            from apps.organizations.constants import MembershipStatus
            queryset = queryset.filter(
                organization_memberships__organization_id=org_id,
                organization_memberships__status=MembershipStatus.ACTIVE
            )

        org_slug = request.query_params.get("organization_slug")
        if org_slug:
            from apps.organizations.constants import MembershipStatus
            queryset = queryset.filter(
                organization_memberships__organization__slug=org_slug,
                organization_memberships__status=MembershipStatus.ACTIVE
            )

        for backend in self.filter_backends:
            queryset = backend().filter_queryset(request, queryset, self)

        paginator = StandardPageNumberPagination()
        page = paginator.paginate_queryset(queryset, request, view=self)
        if page is not None:
            serializer = UserListSerializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)

        serializer = UserListSerializer(queryset, many=True)
        return success_response(
            data=serializer.data,
            message="Users retrieved successfully.",
        )


class UserDetailAPIView(APIView):
    """
    API endpoint for retrieving and updating user details.
    """

    permission_classes = [IsAuthenticated]

    @user_action_swagger_decorator(
        summary="Retrieve User Detail",
        description="Retrieve detailed profile information, system roles, and organization memberships of a single user.",
        responses={200: UserDetailSerializer}
    )
    def get(self, request, pk):
        user = UserListingService.get_user_detail(pk)

        # BOLA Validation: caller must be self, or hold identity:user:read permission
        if str(request.user.id) != str(user.id) and not AuthorizationService.has_permission(
            request.user, PermissionCodes.USER_READ
        ):
            raise PermissionDenied("You do not have permission to view this user's details.")

        serializer = UserDetailSerializer(user)
        return success_response(
            data=serializer.data,
            message="User retrieved successfully.",
        )

    @user_action_swagger_decorator(
        summary="Update User Profile",
        description="Update profile fields (first_name, last_name, username) of a user account.",
        request=UserUpdateSerializer,
        responses={200: UserDetailSerializer}
    )
    def patch(self, request, pk):
        serializer = UserUpdateSerializer(data=request.data, context={"user_id": pk})
        if not serializer.is_valid():
            return error_response(
                errors=serializer.errors,
                message="Profile update validation failed.",
            )

        updated_user = UserProfileService.update_user_profile(
            user_id=pk,
            data=serializer.validated_data,
            actor=request.user,
        )

        output_serializer = UserDetailSerializer(updated_user)
        return success_response(
            data=output_serializer.data,
            message="User profile updated successfully.",
        )


class UserActivateAPIView(APIView):
    """
    API endpoint for administratively activating a user account.
    """

    permission_classes = [IsAuthenticated, HasPermission]
    required_permission = PermissionCodes.USER_MANAGE

    @user_action_swagger_decorator(
        summary="Activate User",
        description="Administratively activate a deactivated user account."
    )
    def post(self, request, pk):
        UserStatusService.activate_user(user_id=pk, actor=request.user)
        return success_response(
            data={},
            message="User activated successfully.",
        )


class UserDeactivateAPIView(APIView):
    """
    API endpoint for administratively deactivating a user account.
    """

    permission_classes = [IsAuthenticated, HasPermission]
    required_permission = PermissionCodes.USER_MANAGE

    @user_action_swagger_decorator(
        summary="Deactivate User",
        description="Administratively deactivate an active user account. Prevents self-deactivation and organization owner deactivation."
    )
    def post(self, request, pk):
        UserStatusService.deactivate_user(user_id=pk, actor=request.user)
        return success_response(
            data={},
            message="User deactivated successfully.",
        )


class UserLockAPIView(APIView):
    """
    API endpoint for administratively locking a user account.
    """

    permission_classes = [IsAuthenticated, HasPermission]
    required_permission = PermissionCodes.USER_MANAGE

    @user_action_swagger_decorator(
        summary="Lock User",
        description="Administratively lock a user account until a specific time.",
        request=UserLockSerializer
    )
    def post(self, request, pk):
        serializer = UserLockSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(
                errors=serializer.errors,
                message="Lock validation failed.",
            )

        UserStatusService.lock_user(
            user_id=pk,
            locked_until=serializer.validated_data.get("locked_until"),
            actor=request.user,
        )
        return success_response(
            data={},
            message="User locked successfully.",
        )


class UserUnlockAPIView(APIView):
    """
    API endpoint for administratively unlocking a user account.
    """

    permission_classes = [IsAuthenticated, HasPermission]
    required_permission = PermissionCodes.USER_MANAGE

    @user_action_swagger_decorator(
        summary="Unlock User",
        description="Administratively unlock a locked user account."
    )
    def post(self, request, pk):
        UserStatusService.unlock_user(user_id=pk, actor=request.user)
        return success_response(
            data={},
            message="User unlocked successfully.",
        )


class UserRoleAssignAPIView(APIView):
    """
    API endpoint for assigning a system role to a user.
    """

    permission_classes = [IsAuthenticated, HasPermission]
    required_permission = PermissionCodes.USER_MANAGE

    @user_action_swagger_decorator(
        summary="Assign System Role",
        description="Assign a global security system role to a user identity.",
        request=UserRoleAssignSerializer
    )
    def post(self, request, pk):
        serializer = UserRoleAssignSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(
                errors=serializer.errors,
                message="Role assignment validation failed.",
            )

        UserRoleService.assign_role(
            user_id=str(pk),
            role_id=str(serializer.validated_data["role_id"]),
            assigned_by_user=request.user,
            expires_at=serializer.validated_data.get("expires_at"),
            assignment_reason=serializer.validated_data.get("assignment_reason"),
        )

        return success_response(
            data={},
            message="Role assigned successfully.",
        )


class UserRoleRevokeAPIView(APIView):
    """
    API endpoint for revoking a system role from a user.
    """

    permission_classes = [IsAuthenticated, HasPermission]
    required_permission = PermissionCodes.USER_MANAGE

    @user_action_swagger_decorator(
        summary="Revoke System Role",
        description="Revoke an actively assigned global security system role from a user identity.",
        request=UserRoleRevokeSerializer
    )
    def post(self, request, pk):
        serializer = UserRoleRevokeSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(
                errors=serializer.errors,
                message="Role revocation validation failed.",
            )

        UserRoleService.revoke_role(
            user_id=str(pk),
            role_id=str(serializer.validated_data["role_id"]),
        )

        return success_response(
            data={},
            message="Role revoked successfully.",
        )
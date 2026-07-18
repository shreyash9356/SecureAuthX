import logging
import uuid
from typing import Any
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError as DjangoValidationError

User = get_user_model()
from django.db import models
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.pagination import LimitOffsetPagination
from drf_spectacular.utils import (
    extend_schema,
    extend_schema_view,
    OpenApiExample,
    OpenApiResponse,
    OpenApiParameter,
)
from drf_spectacular.types import OpenApiTypes

from apps.authorization.constants import PermissionCodes, RoleSlugs
from apps.authorization.permissions import HasPermission
from apps.authorization.services.authorization_service import AuthorizationService

from apps.organizations.models import Organization, OrganizationMembership, OrganizationInvitation
from apps.organizations.constants import (
    OrganizationStatus,
    MembershipStatus,
    InvitationStatus,
)
from apps.organizations.exceptions import OrganizationException
from apps.organizations.selectors import (
    OrganizationSelector,
    MembershipSelector,
    InvitationSelector,
    SettingsSelector,
)
from apps.organizations.services.organization_service import OrganizationService
from apps.organizations.services.membership_service import MembershipService
from apps.organizations.services.invitation_service import InvitationService
from apps.organizations.services.ownership_service import OwnershipService
from apps.organizations.services.settings_service import SettingsService

from apps.organizations.api.serializers import (
    OrganizationDetailSerializer,
    OrganizationCreateSerializer,
    OrganizationUpdateSerializer,
    OrganizationSettingsDetailSerializer,
    OrganizationSettingsUpdateSerializer,
    OrganizationMembershipDetailSerializer,
    MembershipAddSerializer,
    MembershipRoleUpdateSerializer,
    MembershipStatusUpdateSerializer,
    OrganizationInvitationDetailSerializer,
    InvitationCreateSerializer,
    OwnershipTransferSerializer,
    StandardErrorEnvelopeSerializer,
)

logger = logging.getLogger(__name__)

# ==============================================================================
# Helper Payload Formatters
# ==============================================================================

def success_response(data: Any, message: str = "Operation successful.", status_code: int = status.HTTP_200_OK) -> Response:
    """
    Standard Success JSON response wrapper.
    """
    return Response({
        "success": True,
        "message": message,
        "data": data
    }, status=status_code)


def error_response(errors: Any, message: str = "Operation failed.", status_code: int = status.HTTP_400_BAD_REQUEST) -> Response:
    """
    Standard Error JSON response wrapper.
    """
    return Response({
        "success": False,
        "message": message,
        "errors": errors
    }, status=status_code)


# ==============================================================================
# Base Organization API Controller
# ==============================================================================

class BaseOrgAPIView(APIView):
    """
    Base API view for Organization endpoints, configuring JWT authentication,
    global permission controls, and mapping core domain exception logic.
    """
    permission_classes = [IsAuthenticated, HasPermission]

    def handle_exception(self, exc: Exception) -> Response:
        """
        Translates organizational domain exceptions and Django validation constraints
        into standardized, user-facing error response payloads.
        """
        if isinstance(exc, OrganizationException):
            logger.warning("Organization Domain Exception handled: %s", str(exc))
            status_map = {
                "OrganizationNotFoundException": status.HTTP_404_NOT_FOUND,
                "MembershipNotFoundException": status.HTTP_404_NOT_FOUND,
                "InvitationNotFoundException": status.HTTP_404_NOT_FOUND,
                "OrganizationAlreadyExistsException": status.HTTP_409_CONFLICT,
                "MembershipAlreadyExistsException": status.HTTP_409_CONFLICT,
                "InvitationAlreadyAcceptedException": status.HTTP_409_CONFLICT,
                "InvitationExpiredException": status.HTTP_400_BAD_REQUEST,
                "InvalidInvitationStateException": status.HTTP_400_BAD_REQUEST,
                "InvalidMembershipException": status.HTTP_400_BAD_REQUEST,
                "OwnershipTransferException": status.HTTP_400_BAD_REQUEST,
            }
            exc_class = exc.__class__.__name__
            status_code = status_map.get(exc_class, status.HTTP_400_BAD_REQUEST)
            return error_response(errors={}, message=str(exc), status_code=status_code)

        if isinstance(exc, DjangoValidationError):
            logger.warning("Django ValidationError handled: %s", str(exc))
            errors = exc.message_dict if hasattr(exc, "message_dict") else {"detail": exc.messages}
            return error_response(errors=errors, message="Semantic validation check failed.", status_code=status.HTTP_400_BAD_REQUEST)

        return super().handle_exception(exc)

    def check_org_member(self, organization_id: uuid.UUID | str) -> Organization:
        """
        Secures organization read-access by checking membership.
        """
        org = OrganizationSelector.get_organization_by_id(organization_id)
        if org.owner == self.request.user:
            return org
        membership = MembershipSelector.get_user_membership(org.id, self.request.user.id)
        if membership and membership.status == MembershipStatus.ACTIVE:
            return org
        raise PermissionDenied("You are not a member of this organization.")

    def check_org_admin(self, organization_id: uuid.UUID | str) -> Organization:
        """
        Secures organization administration by checking owner/admin roles.
        """
        org = OrganizationSelector.get_organization_by_id(organization_id)
        if org.owner == self.request.user:
            return org
        membership = MembershipSelector.get_user_membership(org.id, self.request.user.id)
        if membership and membership.status == MembershipStatus.ACTIVE and membership.role.slug == RoleSlugs.ADMIN:
            return org
        raise PermissionDenied("You do not have administrative access to this organization.")

    def check_org_owner(self, organization_id: uuid.UUID | str) -> Organization:
        """
        Secures critical operations that only the tenant owner can execute.
        """
        org = OrganizationSelector.get_organization_by_id(organization_id)
        if org.owner == self.request.user:
            return org
        raise PermissionDenied("Only the organization owner can perform this action.")


# ==============================================================================
# Organization Controllers
# ==============================================================================

class OrganizationListCreateAPIView(BaseOrgAPIView):
    """
    Handles organization catalog listings and registrations.
    """
    required_permission_map = {
        "GET": PermissionCodes.ORGANIZATION_READ,
        "POST": PermissionCodes.ORGANIZATION_CREATE,
    }

    @extend_schema(
        summary="List Active Organizations",
        description="Retrieves a list of all active organizations the calling user belongs to, or all organizations if the user has global read access.",
        tags=["Organizations"],
        responses={
            200: OrganizationDetailSerializer(many=True),
            401: StandardErrorEnvelopeSerializer,
            403: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Listing",
                value={
                    "success": True,
                    "message": "Organizations retrieved successfully.",
                    "data": [
                        {
                            "id": "11111111-1111-1111-1111-111111111111",
                            "name": "Alpha Corp",
                            "slug": "alpha-corp",
                            "description": "Enterprise tenant",
                            "owner": {"id": "22222222-2222-2222-2222-222222222222", "email": "owner@alpha.com", "first_name": "Admin", "last_name": "User"},
                            "status": "ACTIVE",
                            "settings": {"timezone": "UTC", "country": "US", "branding_name": "Alpha Corp", "logo": "", "session_timeout_minutes": 60},
                            "created_at": "2026-07-17T12:00:00Z",
                            "updated_at": "2026-07-17T12:00:00Z"
                        }
                    ]
                },
                response_only=True
            ),
            OpenApiExample(
                "Permission Denied",
                value={
                    "success": False,
                    "message": "You do not have permission to perform this action.",
                    "errors": {}
                },
                response_only=True
            )
        ]
    )
    def get(self, request):
        user = request.user
        if AuthorizationService.has_permission(user, PermissionCodes.ORGANIZATION_READ):
            queryset = OrganizationSelector.list_all_organizations()
        else:
            queryset = OrganizationSelector.list_all_organizations().filter(
                models.Q(owner=user) | models.Q(memberships__user=user)
            ).distinct()

        # Enforce limit/offset pagination to optimize serialization overhead
        paginator = LimitOffsetPagination()
        page = paginator.paginate_queryset(queryset, request, view=self)
        serializer = OrganizationDetailSerializer(page, many=True)
        paginated_data = {
            "count": queryset.count(),
            "next": paginator.get_next_link(),
            "previous": paginator.get_previous_link(),
            "results": serializer.data
        }
        return success_response(data=paginated_data, message="Organizations retrieved successfully.")

    @extend_schema(
        summary="Create Organization",
        description="Creates a new organization tenant, registers the caller as the owner with Administrator privileges, and bootstraps tenant settings.",
        tags=["Organizations"],
        request=OrganizationCreateSerializer,
        responses={
            201: OrganizationDetailSerializer,
            400: StandardErrorEnvelopeSerializer,
            401: StandardErrorEnvelopeSerializer,
            409: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Creation",
                value={
                    "success": True,
                    "message": "Organization created successfully.",
                    "data": {
                        "id": "11111111-1111-1111-1111-111111111111",
                        "name": "Alpha Corp",
                        "slug": "alpha-corp",
                        "description": "Enterprise tenant",
                        "owner": {"id": "22222222-2222-2222-2222-222222222222", "email": "owner@alpha.com", "first_name": "Admin", "last_name": "User"},
                        "status": "ACTIVE",
                        "settings": {"timezone": "UTC", "country": "US", "branding_name": "Alpha Corp", "logo": "", "session_timeout_minutes": 60},
                        "created_at": "2026-07-17T12:00:00Z",
                        "updated_at": "2026-07-17T12:00:00Z"
                    }
                },
                response_only=True
            ),
            OpenApiExample(
                "Duplicate Name Error",
                value={
                    "success": False,
                    "message": "Organization with name 'Alpha Corp' already exists.",
                    "errors": {}
                },
                response_only=True
            ),
            OpenApiExample(
                "Validation Failed",
                value={
                    "success": False,
                    "message": "Operation failed.",
                    "errors": {"name": ["This field is required."]}
                },
                response_only=True
            )
        ]
    )
    def post(self, request):
        serializer = OrganizationCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors, message="Request validation failed.")

        validated = serializer.validated_data
        settings_payload = {
            "timezone": validated.get("timezone", "UTC"),
            "country": validated.get("country", ""),
            "branding_name": validated.get("branding_name", validated["name"]),
            "logo": validated.get("logo", ""),
            "session_timeout_minutes": validated.get("session_timeout_minutes", 60)
        }

        org = OrganizationService.create_organization(
            name=validated["name"],
            owner=request.user,
            slug=validated.get("slug"),
            description=validated.get("description", ""),
            settings_data=settings_payload
        )
        return success_response(
            data=OrganizationDetailSerializer(org).data,
            message="Organization created successfully.",
            status_code=status.HTTP_201_CREATED
        )


class OrganizationDetailAPIView(BaseOrgAPIView):
    """
    Handles single organization details, metadata updates, and soft deletions.
    """
    required_permission_map = {
        "GET": PermissionCodes.ORGANIZATION_READ,
        "PATCH": PermissionCodes.ORGANIZATION_UPDATE,
        "DELETE": PermissionCodes.ORGANIZATION_DELETE,
    }

    @extend_schema(
        summary="Retrieve Organization",
        description="Fetches full details of a specific organization if the user is a registered member.",
        tags=["Organizations"],
        responses={
            200: OrganizationDetailSerializer,
            401: StandardErrorEnvelopeSerializer,
            403: StandardErrorEnvelopeSerializer,
            404: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Retrieval",
                value={
                    "success": True,
                    "message": "Organization retrieved successfully.",
                    "data": {
                        "id": "11111111-1111-1111-1111-111111111111",
                        "name": "Alpha Corp",
                        "slug": "alpha-corp",
                        "description": "Enterprise tenant",
                        "status": "ACTIVE",
                    }
                },
                response_only=True
            ),
            OpenApiExample(
                "Organization Not Found",
                value={
                    "success": False,
                    "message": "Organization not found.",
                    "errors": {}
                },
                response_only=True
            )
        ]
    )
    def get(self, request, pk):
        org = self.check_org_member(pk)
        return success_response(data=OrganizationDetailSerializer(org).data, message="Organization retrieved successfully.")

    @extend_schema(
        summary="Update Organization",
        description="Updates metadata parameter blocks for an organization. Requires owner or workspace administrator privileges.",
        tags=["Organizations"],
        request=OrganizationUpdateSerializer,
        responses={
            200: OrganizationDetailSerializer,
            400: StandardErrorEnvelopeSerializer,
            403: StandardErrorEnvelopeSerializer,
            404: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Update",
                value={
                    "success": True,
                    "message": "Organization updated successfully.",
                    "data": {
                        "id": "11111111-1111-1111-1111-111111111111",
                        "name": "Alpha Corp (Updated)",
                        "slug": "alpha-corp",
                        "description": "New description details",
                        "status": "ACTIVE"
                    }
                },
                response_only=True
            )
        ]
    )
    def patch(self, request, pk):
        org = self.check_org_admin(pk)
        serializer = OrganizationUpdateSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors, message="Request validation failed.")

        updated = OrganizationService.update_organization(
            org.id,
            name=serializer.validated_data.get("name"),
            description=serializer.validated_data.get("description"),
            status=serializer.validated_data.get("status")
        )
        return success_response(data=OrganizationDetailSerializer(updated).data, message="Organization updated successfully.")

    @extend_schema(
        summary="Delete Organization",
        description="Soft-deletes the organization tenant and revokes all active memberships. Requires owner or workspace administrator privileges.",
        tags=["Organizations"],
        responses={
            200: StandardErrorEnvelopeSerializer,
            403: StandardErrorEnvelopeSerializer,
            404: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Soft Delete",
                value={
                    "success": True,
                    "message": "Organization soft-deleted successfully.",
                    "data": {}
                },
                response_only=True
            )
        ]
    )
    def delete(self, request, pk):
        org = self.check_org_admin(pk)
        OrganizationService.delete_organization(org.id)
        return success_response(data={}, message="Organization soft-deleted successfully.")


# ==============================================================================
# Settings Controllers
# ==============================================================================

class SettingsDetailAPIView(BaseOrgAPIView):
    """
    Handles viewing and editing tenant-wide preferences and session limits.
    """
    required_permission_map = {
        "GET": PermissionCodes.ORGANIZATION_READ,
        "PATCH": PermissionCodes.ORGANIZATION_UPDATE,
    }

    @extend_schema(
        summary="Retrieve Settings",
        description="Fetches current tenant configuration parameters like timezone, session timeout thresholds, branding details, and logo URI.",
        tags=["Organization Settings"],
        responses={
            200: OrganizationSettingsDetailSerializer,
            403: StandardErrorEnvelopeSerializer,
            404: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Retrieval",
                value={
                    "success": True,
                    "message": "Settings retrieved successfully.",
                    "data": {
                        "timezone": "UTC",
                        "country": "US",
                        "branding_name": "Alpha Corp",
                        "logo": "https://alpha.com/logo.png",
                        "session_timeout_minutes": 60
                    }
                },
                response_only=True
            )
        ]
    )
    def get(self, request, pk):
        self.check_org_member(pk)
        settings = SettingsSelector.get_settings_by_organization_id(pk)
        return success_response(data=OrganizationSettingsDetailSerializer(settings).data, message="Settings retrieved successfully.")

    @extend_schema(
        summary="Update Settings",
        description="Modifies tenant-wide settings parameters. Requires workspace admin or owner status.",
        tags=["Organization Settings"],
        request=OrganizationSettingsUpdateSerializer,
        responses={
            200: OrganizationSettingsDetailSerializer,
            400: StandardErrorEnvelopeSerializer,
            403: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Update",
                value={
                    "success": True,
                    "message": "Settings updated successfully.",
                    "data": {
                        "timezone": "EST",
                        "country": "US",
                        "branding_name": "Alpha Premium",
                        "logo": "https://alpha.com/new-logo.png",
                        "session_timeout_minutes": 30
                    }
                },
                response_only=True
            )
        ]
    )
    def patch(self, request, pk):
        self.check_org_admin(pk)
        serializer = OrganizationSettingsUpdateSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors, message="Request validation failed.")

        validated = serializer.validated_data
        updated = SettingsService.update_settings(
            pk,
            timezone_str=validated.get("timezone"),
            country=validated.get("country"),
            branding_name=validated.get("branding_name"),
            logo=validated.get("logo"),
            session_timeout_minutes=validated.get("session_timeout_minutes")
        )
        return success_response(data=OrganizationSettingsDetailSerializer(updated).data, message="Settings updated successfully.")


# ==============================================================================
# Membership Controllers
# ==============================================================================

class MembershipListCreateAPIView(BaseOrgAPIView):
    """
    Handles member rosters and direct additions.
    """
    required_permission_map = {
        "GET": PermissionCodes.ORGANIZATION_READ,
        "POST": PermissionCodes.ORGANIZATION_MANAGE,
    }

    @extend_schema(
        summary="List Members",
        description="Lists all membership records for an organization. Filters by status (ACTIVE, SUSPENDED, PENDING) can be passed.",
        tags=["Organization Memberships"],
        parameters=[
            OpenApiParameter(name="status", description="Filter memberships by state", required=False, type=str),
        ],
        responses={
            200: OrganizationMembershipDetailSerializer(many=True),
            403: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Listing",
                value={
                    "success": True,
                    "message": "Members retrieved successfully.",
                    "data": [
                        {
                            "id": "33333333-3333-3333-3333-333333333333",
                            "organization": "11111111-1111-1111-1111-111111111111",
                            "user": {"id": "22222222-2222-2222-2222-222222222222", "email": "employee@alpha.com"},
                            "role": {"name": "Employee", "slug": "employee"},
                            "status": "ACTIVE",
                            "joined_at": "2026-07-17T12:00:00Z"
                        }
                    ]
                },
                response_only=True
            )
        ]
    )
    def get(self, request, pk):
        self.check_org_member(pk)
        status_filter = request.query_params.get("status")
        queryset = MembershipSelector.list_organization_memberships(pk, status=status_filter)

        paginator = LimitOffsetPagination()
        page = paginator.paginate_queryset(queryset, request, view=self)
        serializer = OrganizationMembershipDetailSerializer(page, many=True)
        paginated_data = {
            "count": queryset.count(),
            "next": paginator.get_next_link(),
            "previous": paginator.get_previous_link(),
            "results": serializer.data
        }
        return success_response(data=paginated_data, message="Members retrieved successfully.")

    @extend_schema(
        summary="Add Member Directly",
        description="Creates an active organization membership directly, bypassing invitations. Requires administrative access.",
        tags=["Organization Memberships"],
        request=MembershipAddSerializer,
        responses={
            201: OrganizationMembershipDetailSerializer,
            400: StandardErrorEnvelopeSerializer,
            403: StandardErrorEnvelopeSerializer,
            409: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Member Add",
                value={
                    "success": True,
                    "message": "Member mapped successfully.",
                    "data": {
                        "id": "33333333-3333-3333-3333-333333333333",
                        "organization": "11111111-1111-1111-1111-111111111111",
                        "user": {"id": "44444444-4444-4444-4444-444444444444", "email": "new@alpha.com"},
                        "role": {"slug": "employee"},
                        "status": "ACTIVE"
                    }
                },
                response_only=True
            ),
            OpenApiExample(
                "Membership Already Exists",
                value={
                    "success": False,
                    "message": "User is already an active member of organization.",
                    "errors": {}
                },
                response_only=True
            )
        ]
    )
    def post(self, request, pk):
        self.check_org_admin(pk)
        serializer = MembershipAddSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors, message="Request validation failed.")

        membership = MembershipService.add_member(
            organization_id=pk,
            user_id=serializer.validated_data["user_id"],
            role_slug=serializer.validated_data["role_slug"]
        )
        return success_response(
            data=OrganizationMembershipDetailSerializer(membership).data,
            message="Member added successfully.",
            status_code=status.HTTP_201_CREATED
        )


class MembershipRoleUpdateAPIView(BaseOrgAPIView):
    """
    Handles updates to a member's role slug assignment.
    """
    required_permission = PermissionCodes.ORGANIZATION_MANAGE

    @extend_schema(
        summary="Update Member Role",
        description="Updates a member's assigned workspace RBAC role. Blocks demotions of the primary owner membership.",
        tags=["Organization Memberships"],
        request=MembershipRoleUpdateSerializer,
        responses={
            200: OrganizationMembershipDetailSerializer,
            400: StandardErrorEnvelopeSerializer,
            403: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Role Change",
                value={
                    "success": True,
                    "message": "Member role updated successfully.",
                    "data": {
                        "id": "33333333-3333-3333-3333-333333333333",
                        "role": {"slug": "manager"}
                    }
                },
                response_only=True
            )
        ]
    )
    def patch(self, request, pk, membership_id):
        self.check_org_admin(pk)
        serializer = MembershipRoleUpdateSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors, message="Request validation failed.")

        membership = MembershipService.update_membership_role(
            membership_id=membership_id,
            role_slug=serializer.validated_data["role_slug"],
            actor=request.user
        )
        return success_response(data=OrganizationMembershipDetailSerializer(membership).data, message="Member role updated successfully.")


class MembershipStatusUpdateAPIView(BaseOrgAPIView):
    """
    Handles user suspensions, deactivations, or status resets.
    """
    required_permission = PermissionCodes.ORGANIZATION_MANAGE

    @extend_schema(
        summary="Update Member Status",
        description="Changes a member's status (e.g. SUSPENDED, ACTIVE). Suspensions targeting the primary owner are blocked.",
        tags=["Organization Memberships"],
        request=MembershipStatusUpdateSerializer,
        responses={
            200: OrganizationMembershipDetailSerializer,
            400: StandardErrorEnvelopeSerializer,
            403: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Status Update",
                value={
                    "success": True,
                    "message": "Member status updated successfully.",
                    "data": {
                        "id": "33333333-3333-3333-3333-333333333333",
                        "status": "SUSPENDED"
                    }
                },
                response_only=True
            )
        ]
    )
    def patch(self, request, pk, membership_id):
        self.check_org_admin(pk)
        serializer = MembershipStatusUpdateSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors, message="Request validation failed.")

        membership = MembershipService.update_membership_status(
            membership_id=membership_id,
            status=serializer.validated_data["status"],
            actor=request.user
        )
        return success_response(data=OrganizationMembershipDetailSerializer(membership).data, message="Member status updated successfully.")


class MembershipDetailAPIView(BaseOrgAPIView):
    """
    Handles membership cancellations (removing members from rosters).
    """
    required_permission = PermissionCodes.ORGANIZATION_MANAGE

    @extend_schema(
        summary="Remove Member",
        description="Removes a member from the workspace roster. Rejects if attempting to remove the primary tenant owner.",
        tags=["Organization Memberships"],
        responses={
            200: StandardErrorEnvelopeSerializer,
            400: StandardErrorEnvelopeSerializer,
            403: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Removal",
                value={
                    "success": True,
                    "message": "Member removed successfully.",
                    "data": {}
                },
                response_only=True
            )
        ]
    )
    def delete(self, request, pk, membership_id):
        self.check_org_admin(pk)
        MembershipService.remove_member(
            membership_id=membership_id,
            actor=request.user
        )
        return success_response(data={}, message="Member removed successfully.")


# ==============================================================================
# Invitation Controllers
# ==============================================================================

class InvitationListCreateAPIView(BaseOrgAPIView):
    """
    Handles sending invitations and listing active pending items.
    """
    required_permission_map = {
        "GET": PermissionCodes.ORGANIZATION_READ,
        "POST": PermissionCodes.ORGANIZATION_MANAGE,
    }

    @extend_schema(
        summary="List Pending Invitations",
        description="Lists all pending recruitment invitations for the organization. Requires read permissions.",
        tags=["Organization Invitations"],
        responses={
            200: OrganizationInvitationDetailSerializer(many=True),
            403: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Listing",
                value={
                    "success": True,
                    "message": "Invitations retrieved successfully.",
                    "data": [
                        {
                            "id": "55555555-5555-5555-5555-555555555555",
                            "email": "invitee@test.com",
                            "status": "PENDING",
                            "expires_at": "2026-07-24T12:00:00Z"
                        }
                    ]
                },
                response_only=True
            )
        ]
    )
    def get(self, request, pk):
        self.check_org_member(pk)
        queryset = InvitationSelector.list_pending_invitations(pk)
        serializer = OrganizationInvitationDetailSerializer(queryset, many=True)
        return success_response(data=serializer.data, message="Invitations retrieved successfully.")

    @extend_schema(
        summary="Invite Member",
        description="Creates an invitation record for a user email. If the user already has a system profile, maps a pending membership.",
        tags=["Organization Invitations"],
        request=InvitationCreateSerializer,
        responses={
            201: OrganizationInvitationDetailSerializer,
            400: StandardErrorEnvelopeSerializer,
            403: StandardErrorEnvelopeSerializer,
            409: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Invite",
                value={
                    "success": True,
                    "message": "Invitation sent successfully.",
                    "data": {
                        "id": "55555555-5555-5555-5555-555555555555",
                        "email": "invitee@test.com",
                        "status": "PENDING",
                        "expires_at": "2026-07-24T12:00:00Z"
                    }
                },
                response_only=True
            ),
            OpenApiExample(
                "Duplicate Invitation",
                value={
                    "success": False,
                    "message": "User is already an active member of organization 'alpha-org'.",
                    "errors": {}
                },
                response_only=True
            )
        ]
    )
    def post(self, request, pk):
        self.check_org_admin(pk)
        serializer = InvitationCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors, message="Request validation failed.")

        invitation = InvitationService.invite_member(
            organization_id=pk,
            email=serializer.validated_data["email"],
            invited_by=request.user,
            role_slug=serializer.validated_data.get("role_slug", RoleSlugs.EMPLOYEE),
            expires_in_days=serializer.validated_data.get("expires_in_days", 7)
        )
        return success_response(
            data=OrganizationInvitationDetailSerializer(invitation).data,
            message="Invitation sent successfully.",
            status_code=status.HTTP_201_CREATED
        )


class InvitationAcceptAPIView(BaseOrgAPIView):
    """
    Accepts a pending invitation token. Requires only standard authentication.
    """
    # Requires authentication, but no organization role check
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Accept Invitation",
        description="Accepts a pending workspace invitation token, activating the membership. Requires matching authenticated identity email.",
        tags=["Organization Invitations"],
        request=None,
        parameters=[
            OpenApiParameter(name="token", description="Unique UUID invitation token", required=True, type=OpenApiTypes.UUID, location=OpenApiParameter.PATH),
        ],
        responses={
            200: OrganizationMembershipDetailSerializer,
            400: StandardErrorEnvelopeSerializer,
            409: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Accept",
                value={
                    "success": True,
                    "message": "Invitation accepted successfully.",
                    "data": {
                        "id": "33333333-3333-3333-3333-333333333333",
                        "organization": "11111111-1111-1111-1111-111111111111",
                        "status": "ACTIVE"
                    }
                },
                response_only=True
            ),
            OpenApiExample(
                "Expired Invitation Token",
                value={
                    "success": False,
                    "message": "This invitation has expired.",
                    "errors": {}
                },
                response_only=True
            ),
            OpenApiExample(
                "Identity Mismatch Error",
                value={
                    "success": False,
                    "message": "Operation failed.",
                    "errors": {"email": ["This invitation was issued to a different email address."]}
                },
                response_only=True
            )
        ]
    )
    def post(self, request, token):
        membership = InvitationService.accept_invitation(token=token, user=request.user)
        return success_response(data=OrganizationMembershipDetailSerializer(membership).data, message="Invitation accepted successfully.")


class InvitationRejectAPIView(BaseOrgAPIView):
    """
    Rejects a pending invitation token. Requires only standard authentication.
    """
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Reject Invitation",
        description="Rejects a pending workspace invitation token, marking it permanently unusable.",
        tags=["Organization Invitations"],
        request=None,
        parameters=[
            OpenApiParameter(name="token", description="Unique UUID invitation token", required=True, type=OpenApiTypes.UUID, location=OpenApiParameter.PATH),
        ],
        responses={
            200: StandardErrorEnvelopeSerializer,
            400: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Rejection",
                value={
                    "success": True,
                    "message": "Invitation rejected successfully.",
                    "data": {}
                },
                response_only=True
            )
        ]
    )
    def post(self, request, token):
        InvitationService.reject_invitation(token=token)
        return success_response(data={}, message="Invitation rejected successfully.")


class InvitationCancelAPIView(BaseOrgAPIView):
    """
    Cancels an active invitation administratively.
    """
    required_permission = PermissionCodes.ORGANIZATION_MANAGE

    @extend_schema(
        summary="Cancel Invitation",
        description="Cancels a pending invitation administratively, preventing future acceptance. Requires admin access.",
        tags=["Organization Invitations"],
        request=None,
        responses={
            200: StandardErrorEnvelopeSerializer,
            400: StandardErrorEnvelopeSerializer,
            403: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Cancellation",
                value={
                    "success": True,
                    "message": "Invitation cancelled successfully.",
                    "data": {}
                },
                response_only=True
            )
        ]
    )
    def post(self, request, pk, invitation_id):
        self.check_org_admin(pk)
        InvitationService.cancel_invitation(invitation_id=invitation_id, actor=request.user)
        return success_response(data={}, message="Invitation cancelled successfully.")


# ==============================================================================
# Ownership Controllers
# ==============================================================================

class OwnershipTransferAPIView(BaseOrgAPIView):
    """
    Handles tenant ownership transfers.
    """
    required_permission = PermissionCodes.ORGANIZATION_MANAGE

    @extend_schema(
        summary="Transfer Ownership",
        description="Transfers primary ownership of the tenant to another active member. Outgoing owner retains administrative membership access.",
        tags=["Organization Ownership"],
        request=OwnershipTransferSerializer,
        responses={
            200: OrganizationDetailSerializer,
            400: StandardErrorEnvelopeSerializer,
            403: StandardErrorEnvelopeSerializer,
        },
        examples=[
            OpenApiExample(
                "Successful Transfer",
                value={
                    "success": True,
                    "message": "Ownership transferred successfully.",
                    "data": {
                        "id": "11111111-1111-1111-1111-111111111111",
                        "owner": {"id": "44444444-4444-4444-4444-444444444444", "email": "new_owner@alpha.com"}
                    }
                },
                response_only=True
            ),
            OpenApiExample(
                "Transfer Failure (e.g. self-transfer or suspended member)",
                value={
                    "success": False,
                    "message": "Cannot transfer ownership to yourself.",
                    "errors": {}
                },
                response_only=True
            )
        ]
    )
    def post(self, request, pk):
        org = self.check_org_owner(pk)
        serializer = OwnershipTransferSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors, message="Request validation failed.")

        new_owner_user = User.objects.get(id=serializer.validated_data["new_owner_id"])
        updated_org = OwnershipService.transfer_ownership(
            organization_id=org.id,
            current_owner=request.user,
            new_owner=new_owner_user
        )
        return success_response(data=OrganizationDetailSerializer(updated_org).data, message="Ownership transferred successfully.")

import logging
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import models
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import LimitOffsetPagination

from apps.authorization.constants import PermissionCodes
from apps.authorization.permissions import HasPermission
from apps.authorization.selectors import PermissionSelector, RoleSelector, AuthorizationSelector
from apps.authorization.services.permission_service import PermissionService
from apps.authorization.services.role_service import RoleService
from apps.authorization.services.user_role_service import UserRoleService
from apps.authorization.exceptions import AuthorizationException
from apps.authorization.api.serializers import (
    PermissionDetailSerializer,
    RoleDetailSerializer,
    PermissionCreateSerializer,
    PermissionUpdateSerializer,
    RoleCreateSerializer,
    RoleUpdateSerializer,
    RolePermissionDetailSerializer,
    RolePermissionAssignSerializer,
    RolePermissionRemoveSerializer,
    UserRoleDetailSerializer,
    UserRoleAssignSerializer,
    UserRoleRevokeSerializer,
    UserRoleExtendSerializer,
)

# Import doc decorators to centralized metadata mapping
from apps.authorization.api.docs import authorization_docs

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Generic API View Helpers
# --------------------------------------------------------------------------

def success_response(data, message="Operation successful.", status_code=status.HTTP_200_OK):
    """
    Standard Success Payload Formatter.
    """
    return Response({
        "success": True,
        "message": message,
        "data": data
    }, status=status_code)


def error_response(errors, message="Operation failed.", status_code=status.HTTP_400_BAD_REQUEST):
    """
    Standard Error Payload Formatter.
    """
    return Response({
        "success": False,
        "message": message,
        "errors": errors
    }, status=status_code)


class BaseAuthAPIView(APIView):
    """
    Base view configuring JWT authentication + catalog RBAC enforcement.

    Subclasses must declare ``required_permission``, ``required_permissions``,
    or ``required_permission_map`` so HasPermission can evaluate access.
    """
    permission_classes = [IsAuthenticated, HasPermission]

    def handle_exception(self, exc):
        """
        Custom exception interceptor translating core catalog exceptions
        to clean REST validation payloads.
        """
        if isinstance(exc, AuthorizationException):
            logger.warning("Auth Domain Exception handled: %s", str(exc))
            status_map = {
                "PermissionNotFoundException": status.HTTP_404_NOT_FOUND,
                "RoleNotFoundException": status.HTTP_404_NOT_FOUND,
                "RoleAlreadyExistsException": status.HTTP_409_CONFLICT,
                "PermissionAlreadyExistsException": status.HTTP_409_CONFLICT,
                "SystemRoleModificationException": status.HTTP_403_FORBIDDEN,
                "SystemPermissionModificationException": status.HTTP_403_FORBIDDEN,
                "PermissionAssignmentException": status.HTTP_422_UNPROCESSABLE_ENTITY,
                "RoleAssignmentException": status.HTTP_422_UNPROCESSABLE_ENTITY,
                "InvalidRoleException": status.HTTP_422_UNPROCESSABLE_ENTITY,
                "InvalidPermissionException": status.HTTP_422_UNPROCESSABLE_ENTITY,
            }
            exc_class = exc.__class__.__name__
            status_code = status_map.get(exc_class, status.HTTP_400_BAD_REQUEST)
            return error_response(errors={}, message=str(exc), status_code=status_code)

        if isinstance(exc, DjangoValidationError):
            logger.warning("Django ValidationError handled: %s", str(exc.message_dict))
            return error_response(errors=exc.message_dict, message="Semantic validation check failed.", status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)

        return super().handle_exception(exc)


# --------------------------------------------------------------------------
# Permissions Views
# --------------------------------------------------------------------------

class PermissionListCreateAPIView(BaseAuthAPIView):
    """
    API controller to retrieve the permission catalog or register new capabilities.
    """
    required_permission_map = {
        "GET": PermissionCodes.PERMISSION_READ,
        "POST": PermissionCodes.PERMISSION_CREATE,
    }

    @authorization_docs.permissions_list_docs
    def get(self, request):
        is_active_filter = request.query_params.get("is_active")
        is_active = None
        if is_active_filter is not None:
            is_active = is_active_filter.lower() in ["true", "1"]

        # Retrieve permissions via Selector layer only
        queryset = PermissionSelector.list_permissions(is_active=is_active)

        # Handle simple search parameter
        search = request.query_params.get("search")
        if search:
            queryset = queryset.filter(
                models.Q(name__icontains=search) | models.Q(code__icontains=search)
            )

        # Handroll pagination with standard DRF utilities to structure the output payload
        paginator = LimitOffsetPagination()
        page = paginator.paginate_queryset(queryset, request, view=self)
        
        serializer = PermissionDetailSerializer(page, many=True)
        paginated_data = {
            "count": queryset.count(),
            "next": paginator.get_next_link(),
            "previous": paginator.get_previous_link(),
            "results": serializer.data
        }
        return success_response(data=paginated_data, message="Permission catalog retrieved successfully.")

    @authorization_docs.permissions_create_docs
    def post(self, request):
        serializer = PermissionCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors, message="Invalid permission attributes.")
        
        permission = serializer.save()
        output_serializer = PermissionDetailSerializer(permission)
        return success_response(
            data=output_serializer.data, 
            message="Permission successfully created inside catalog.",
            status_code=status.HTTP_201_CREATED
        )


class PermissionDetailAPIView(BaseAuthAPIView):
    """
    API view to view details or update name/description on a catalog permission.
    """
    required_permission_map = {
        "GET": PermissionCodes.PERMISSION_READ,
        "PUT": PermissionCodes.PERMISSION_UPDATE,
    }

    @authorization_docs.permissions_detail_docs
    def get(self, request, permission_id):
        permission = PermissionSelector.get_permission_by_id(permission_id)
        serializer = PermissionDetailSerializer(permission)
        return success_response(data=serializer.data, message="Permission catalog item details retrieved.")

    @authorization_docs.permissions_update_docs
    def put(self, request, permission_id):
        permission = PermissionSelector.get_permission_by_id(permission_id)
        serializer = PermissionUpdateSerializer(instance=permission, data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors, message="Invalid update attributes.")
        
        updated_permission = serializer.save()
        output_serializer = PermissionDetailSerializer(updated_permission)
        return success_response(data=output_serializer.data, message="Permission catalog item updated.")


class PermissionActivateAPIView(BaseAuthAPIView):
    """
    POST API to enable a deactivated permission catalog capability.
    """
    required_permission = PermissionCodes.PERMISSION_UPDATE

    @authorization_docs.permissions_activate_docs
    def post(self, request, permission_id):
        PermissionSelector.get_permission_by_id(permission_id)  # Validate exists
        permission = PermissionService.activate_permission(permission_id)
        serializer = PermissionDetailSerializer(permission)
        return success_response(data=serializer.data, message="Catalog permission activated.")


class PermissionDeactivateAPIView(BaseAuthAPIView):
    """
    POST API to disable a permission catalog capability.
    """
    required_permission = PermissionCodes.PERMISSION_UPDATE

    @authorization_docs.permissions_deactivate_docs
    def post(self, request, permission_id):
        PermissionSelector.get_permission_by_id(permission_id)  # Validate exists
        permission = PermissionService.deactivate_permission(permission_id)
        serializer = PermissionDetailSerializer(permission)
        return success_response(data=serializer.data, message="Catalog permission deactivated.")


# --------------------------------------------------------------------------
# Roles Views
# --------------------------------------------------------------------------

class RoleListCreateAPIView(BaseAuthAPIView):
    """
    API controller to query available enterprise roles or create new roles.
    """
    required_permission_map = {
        "GET": PermissionCodes.ROLE_READ,
        "POST": PermissionCodes.ROLE_CREATE,
    }

    @authorization_docs.roles_list_docs
    def get(self, request):
        is_active_filter = request.query_params.get("is_active")
        is_active = None
        if is_active_filter is not None:
            is_active = is_active_filter.lower() in ["true", "1"]

        queryset = RoleSelector.list_roles(is_active=is_active)

        search = request.query_params.get("search")
        if search:
            queryset = queryset.filter(
                models.Q(name__icontains=search) | models.Q(slug__icontains=search)
            )

        paginator = LimitOffsetPagination()
        page = paginator.paginate_queryset(queryset, request, view=self)

        serializer = RoleDetailSerializer(page, many=True)
        paginated_data = {
            "count": queryset.count(),
            "next": paginator.get_next_link(),
            "previous": paginator.get_previous_link(),
            "results": serializer.data
        }
        return success_response(data=paginated_data, message="Enterprise roles list retrieved.")

    @authorization_docs.roles_create_docs
    def post(self, request):
        serializer = RoleCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors, message="Invalid role configuration.")

        role = serializer.save()
        output_serializer = RoleDetailSerializer(role)
        return success_response(
            data=output_serializer.data,
            message="Enterprise role created successfully.",
            status_code=status.HTTP_201_CREATED
        )


class RoleDetailAPIView(BaseAuthAPIView):
    """
    API view to view details or update enterprise roles.
    """
    required_permission_map = {
        "GET": PermissionCodes.ROLE_READ,
        "PUT": PermissionCodes.ROLE_UPDATE,
    }

    @authorization_docs.roles_detail_docs
    def get(self, request, role_id):
        role = RoleSelector.get_role_by_id(role_id)
        serializer = RoleDetailSerializer(role)
        return success_response(data=serializer.data, message="Role details retrieved.")

    @authorization_docs.roles_update_docs
    def put(self, request, role_id):
        role = RoleSelector.get_role_by_id(role_id)
        serializer = RoleUpdateSerializer(instance=role, data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors, message="Invalid update parameters.")

        updated_role = serializer.save()
        output_serializer = RoleDetailSerializer(updated_role)
        return success_response(data=output_serializer.data, message="Enterprise role updated.")


class RoleActivateAPIView(BaseAuthAPIView):
    """
    POST API to activate a deactivated role.
    """
    required_permission = PermissionCodes.ROLE_UPDATE

    @authorization_docs.roles_activate_docs
    def post(self, request, role_id):
        RoleSelector.get_role_by_id(role_id)
        role = RoleService.activate_role(role_id)
        serializer = RoleDetailSerializer(role)
        return success_response(data=serializer.data, message="Enterprise role activated.")


class RoleDeactivateAPIView(BaseAuthAPIView):
    """
    POST API to soft-deactivate an active role.
    """
    required_permission = PermissionCodes.ROLE_UPDATE

    @authorization_docs.roles_deactivate_docs
    def post(self, request, role_id):
        RoleSelector.get_role_by_id(role_id)
        role = RoleService.deactivate_role(role_id)
        serializer = RoleDetailSerializer(role)
        return success_response(data=serializer.data, message="Enterprise role deactivated.")


# --------------------------------------------------------------------------
# Role Permission Mapping Views
# --------------------------------------------------------------------------

class RolePermissionAssignAPIView(BaseAuthAPIView):
    """
    POST API to assign capability permissions to an enterprise role.
    """
    required_permission = PermissionCodes.ROLE_UPDATE

    @authorization_docs.role_permissions_assign_docs
    def post(self, request):
        serializer = RolePermissionAssignSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors, message="Invalid mapping parameters.")

        mapping = serializer.save(assigned_by_user=request.user)
        output_serializer = RolePermissionDetailSerializer(mapping)
        return success_response(
            data=output_serializer.data,
            message="Catalog capability mapped to role successfully.",
            status_code=status.HTTP_201_CREATED
        )


class RolePermissionRemoveAPIView(BaseAuthAPIView):
    """
    POST API to revoke a capability mapping from a target role.
    """
    required_permission = PermissionCodes.ROLE_UPDATE

    @authorization_docs.role_permissions_remove_docs
    def post(self, request):
        serializer = RolePermissionRemoveSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors, message="Invalid revocation request.")

        mapping = serializer.save()
        output_serializer = RolePermissionDetailSerializer(mapping)
        return success_response(data=output_serializer.data, message="Permission capability revoked from role.")


class RolePermissionListAPIView(BaseAuthAPIView):
    """
    GET API listing all active catalog capabilities mapped to a role.
    """
    required_permission = PermissionCodes.ROLE_READ

    @authorization_docs.role_permissions_list_docs
    def get(self, request, role_id):
        role = RoleSelector.get_role_by_id(role_id)
        permissions = AuthorizationSelector.get_active_role_permissions(role)
        serializer = PermissionDetailSerializer(permissions, many=True)
        return success_response(data=serializer.data, message="Role permission mappings retrieved.")


# --------------------------------------------------------------------------
# User Roles Assignment Views
# --------------------------------------------------------------------------

class UserRoleAssignAPIView(BaseAuthAPIView):
    """
    POST API to grant a user account role membership access.
    """
    required_permission = PermissionCodes.USER_UPDATE

    @authorization_docs.user_roles_assign_docs
    def post(self, request):
        serializer = UserRoleAssignSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors, message="Invalid role assignment parameters.")

        assignment = serializer.save(assigned_by_user=request.user)
        output_serializer = UserRoleDetailSerializer(assignment)
        return success_response(
            data=output_serializer.data,
            message="Role membership assigned to user account.",
            status_code=status.HTTP_201_CREATED
        )


class UserRoleRevokeAPIView(BaseAuthAPIView):
    """
    POST API to revoke a user account's role membership mapping.
    """
    required_permission = PermissionCodes.USER_UPDATE

    @authorization_docs.user_roles_revoke_docs
    def post(self, request):
        serializer = UserRoleRevokeSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors, message="Invalid revocation payload.")

        assignment = serializer.save()
        output_serializer = UserRoleDetailSerializer(assignment)
        return success_response(data=output_serializer.data, message="Role membership revoked from user account.")


class UserRoleExtendAPIView(BaseAuthAPIView):
    """
    POST API to extend a user's temporal JIT role assignment timeline.
    """
    required_permission = PermissionCodes.USER_UPDATE

    @authorization_docs.user_roles_extend_docs
    def post(self, request):
        serializer = UserRoleExtendSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(errors=serializer.errors, message="Invalid JIT extension configuration.")

        assignment = serializer.save()
        output_serializer = UserRoleDetailSerializer(assignment)
        return success_response(data=output_serializer.data, message="User role assignment expiration extended.")


class UserRoleListAPIView(BaseAuthAPIView):
    """
    GET API listing all active, unexpired role definitions assigned to a user.
    """
    required_permission = PermissionCodes.USER_READ

    @authorization_docs.user_roles_list_docs
    def get(self, request, user_id):
        # Using a dummy mock check or direct model resolver check for User validation is handled in Selector
        # Try finding user in active roles selector
        roles = AuthorizationSelector.get_active_user_roles(user=type('User', (object,), {"id": user_id, "is_authenticated": True}))
        serializer = RoleDetailSerializer(roles, many=True)
        return success_response(data=serializer.data, message="User role membership mappings retrieved.")

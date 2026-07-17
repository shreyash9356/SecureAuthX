from drf_spectacular.utils import extend_schema, OpenApiExample, OpenApiParameter, OpenApiResponse
from drf_spectacular.types import OpenApiTypes

from apps.authorization.constants import PermissionCodes, RoleSlugs
from apps.authorization.api.serializers import (
    PermissionCreateSerializer,
    PermissionUpdateSerializer,
    RoleCreateSerializer,
    RoleUpdateSerializer,
    RolePermissionAssignSerializer,
    RolePermissionRemoveSerializer,
    UserRoleAssignSerializer,
    UserRoleRevokeSerializer,
    UserRoleExtendSerializer,
)

# --------------------------------------------------------------------------
# Generic Error Response Schemas & Examples
# --------------------------------------------------------------------------

bad_request_response = OpenApiResponse(
    response=OpenApiTypes.OBJECT,
    description="Bad Request - Invalid payload, malformed format, or bad data.",
    examples=[
        OpenApiExample(
            name="Malformed Payload",
            value={
                "error": "Invalid request payload.",
                "details": {"slug": ["This field is required."]}
            }
        )
    ]
)

unauthorized_response = OpenApiResponse(
    response=OpenApiTypes.OBJECT,
    description="Unauthorized - Missing, expired, or invalid JWT access token.",
    examples=[
        OpenApiExample(
            name="Invalid JWT Access Token",
            value={
                "detail": "Given token not valid for any token type",
                "code": "token_not_valid",
                "messages": [
                    {
                        "token_class": "AccessToken",
                        "token_type": "access",
                        "message": "Token is invalid or expired"
                    }
                ]
            }
        )
    ]
)

forbidden_response = OpenApiResponse(
    response=OpenApiTypes.OBJECT,
    description="Forbidden - The user is authenticated but lacks required RBAC permission capabilities.",
    examples=[
        OpenApiExample(
            name="Insufficient Privilege",
            value={
                "detail": "You do not have permission to perform this action.",
                "required_permission": PermissionCodes.ROLE_CREATE,
            }
        )
    ]
)

not_found_response = OpenApiResponse(
    response=OpenApiTypes.OBJECT,
    description="Not Found - The requested resource does not exist in the database.",
    examples=[
        OpenApiExample(
            name="Resource Missing",
            value={
                "error": "Role with slug 'non-existent-role' not found."
            }
        )
    ]
)

conflict_response = OpenApiResponse(
    response=OpenApiTypes.OBJECT,
    description="Conflict - Uniqueness constraint violation or active duplicate relationship mapping.",
    examples=[
        OpenApiExample(
            name="Duplicate Assignment Mismatch",
            value={
                "error": (
                    f"Permission '{PermissionCodes.USER_CREATE}' is already actively "
                    f"assigned to role '{RoleSlugs.ADMIN}'."
                )
            }
        )
    ]
)

validation_error_response = OpenApiResponse(
    response=OpenApiTypes.OBJECT,
    description="Unprocessable Entity - Semantic validator failures.",
    examples=[
        OpenApiExample(
            name="Validation Rule Failure",
            value={
                "error": "Invalid role attributes: {'slug': ['Enter a valid value.']}"
            }
        )
    ]
)

# --------------------------------------------------------------------------
# Permissions Documentation Schemas
# --------------------------------------------------------------------------

permissions_list_docs = extend_schema(
    summary="List Permission Catalog",
    description=(
        "Retrieves a list of all registered capability permissions in the authorization catalog.\n\n"
        f"**Required Permission**: `{PermissionCodes.PERMISSION_READ}`  \n"
        "**Typical Roles**: `Super Administrator`, `Administrator`"
    ),
    tags=["Permissions"],
    parameters=[
        OpenApiParameter(
            name="is_active",
            type=OpenApiTypes.BOOL,
            location=OpenApiParameter.QUERY,
            required=False,
            description="Filter permissions by active/disabled status."
        )
    ],
    responses={
        200: OpenApiTypes.OBJECT,
        401: unauthorized_response,
        403: forbidden_response,
    }
)

permissions_detail_docs = extend_schema(
    summary="Get Permission Details",
    description=(
        "Retrieves a single permission definition from the catalog by its UUID identifier.\n\n"
        f"**Required Permission**: `{PermissionCodes.PERMISSION_READ}`  \n"
        "**Typical Roles**: `Super Administrator`, `Administrator`"
    ),
    tags=["Permissions"],
    responses={
        200: OpenApiTypes.OBJECT,
        401: unauthorized_response,
        403: forbidden_response,
        404: not_found_response,
    }
)

permissions_create_docs = extend_schema(
    request=PermissionCreateSerializer,
    summary="Create Catalog Permission",
    description=(
        "Registers a new capability definition in the global Permission Catalog.\n\n"
        f"**Required Permission**: `{PermissionCodes.PERMISSION_CREATE}`  \n"
        "**Typical Roles**: `Super Administrator`"
    ),
    tags=["Permissions"],
    responses={
        201: OpenApiTypes.OBJECT,
        400: bad_request_response,
        401: unauthorized_response,
        403: forbidden_response,
        409: conflict_response,
        422: validation_error_response,
    }
)

permissions_update_docs = extend_schema(
    request=PermissionUpdateSerializer,
    summary="Update Catalog Permission",
    description=(
        "Modifies the human-readable name or description of an existing permission definition.\n\n"
        f"**Required Permission**: `{PermissionCodes.PERMISSION_UPDATE}`  \n"
        "**Typical Roles**: `Super Administrator`"
    ),
    tags=["Permissions"],
    responses={
        200: OpenApiTypes.OBJECT,
        400: bad_request_response,
        401: unauthorized_response,
        403: forbidden_response,
        404: not_found_response,
        422: validation_error_response,
    }
)

permissions_activate_docs = extend_schema(
    summary="Activate Permission",
    description=(
        "Enables a deactivated permission catalog item.\n\n"
        f"**Required Permission**: `{PermissionCodes.PERMISSION_UPDATE}`  \n"
        "**Typical Roles**: `Super Administrator`"
    ),
    tags=["Permissions"],
    request=None,
    responses={
        200: OpenApiTypes.OBJECT,
        401: unauthorized_response,
        403: forbidden_response,
        404: not_found_response,
    }
)

permissions_deactivate_docs = extend_schema(
    summary="Deactivate Permission",
    description=(
        "Soft-disables a permission catalog item, temporarily disabling checking logic.\n\n"
        f"**Required Permission**: `{PermissionCodes.PERMISSION_UPDATE}`  \n"
        "**Typical Roles**: `Super Administrator`"
    ),
    tags=["Permissions"],
    request=None,
    responses={
        200: OpenApiTypes.OBJECT,
        401: unauthorized_response,
        403: forbidden_response,
        404: not_found_response,
    }
)

# --------------------------------------------------------------------------
# Roles Documentation Schemas
# --------------------------------------------------------------------------

roles_list_docs = extend_schema(
    summary="List Enterprise Roles",
    description=(
        "Retrieves all defined enterprise roles.\n\n"
        f"**Required Permission**: `{PermissionCodes.ROLE_READ}`  \n"
        "**Typical Roles**: `Super Administrator`, `Administrator`, `Manager`"
    ),
    tags=["Roles"],
    parameters=[
        OpenApiParameter(
            name="is_active",
            type=OpenApiTypes.BOOL,
            location=OpenApiParameter.QUERY,
            required=False,
            description="Filter roles by active/disabled status."
        )
    ],
    responses={
        200: OpenApiTypes.OBJECT,
        401: unauthorized_response,
        403: forbidden_response,
    }
)

roles_detail_docs = extend_schema(
    summary="Get Role Details",
    description=(
        "Retrieves details of a single enterprise role by its UUID.\n\n"
        f"**Required Permission**: `{PermissionCodes.ROLE_READ}`  \n"
        "**Typical Roles**: `Super Administrator`, `Administrator`, `Manager`"
    ),
    tags=["Roles"],
    responses={
        200: OpenApiTypes.OBJECT,
        401: unauthorized_response,
        403: forbidden_response,
        404: not_found_response,
    }
)

roles_create_docs = extend_schema(
    request=RoleCreateSerializer,
    summary="Create Enterprise Role",
    description=(
        "Registers a new operational enterprise role in the identity system.\n\n"
        f"**Required Permission**: `{PermissionCodes.ROLE_CREATE}`  \n"
        "**Typical Roles**: `Super Administrator`"
    ),
    tags=["Roles"],
    responses={
        201: OpenApiTypes.OBJECT,
        400: bad_request_response,
        401: unauthorized_response,
        403: forbidden_response,
        409: conflict_response,
        422: validation_error_response,
    }
)

roles_update_docs = extend_schema(
    request=RoleUpdateSerializer,
    summary="Update Enterprise Role",
    description=(
        "Modifies description, priority ranking, or details of a role.\n\n"
        f"**Required Permission**: `{PermissionCodes.ROLE_UPDATE}`  \n"
        "**Typical Roles**: `Super Administrator`"
    ),
    tags=["Roles"],
    responses={
        200: OpenApiTypes.OBJECT,
        400: bad_request_response,
        401: unauthorized_response,
        403: forbidden_response,
        404: not_found_response,
        422: validation_error_response,
    }
)

roles_activate_docs = extend_schema(
    summary="Activate Role",
    description=(
        "Enables a deactivated role definition.\n\n"
        f"**Required Permission**: `{PermissionCodes.ROLE_UPDATE}`  \n"
        "**Typical Roles**: `Super Administrator`"
    ),
    tags=["Roles"],
    request=None,
    responses={
        200: OpenApiTypes.OBJECT,
        401: unauthorized_response,
        403: forbidden_response,
        404: not_found_response,
    }
)

roles_deactivate_docs = extend_schema(
    summary="Deactivate Role",
    description=(
        "Soft-disables a role, preventing new assignments and disabling capabilities.\n\n"
        f"**Required Permission**: `{PermissionCodes.ROLE_UPDATE}`  \n"
        "**Typical Roles**: `Super Administrator`"
    ),
    tags=["Roles"],
    request=None,
    responses={
        200: OpenApiTypes.OBJECT,
        401: unauthorized_response,
        403: forbidden_response,
        404: not_found_response,
    }
)

# --------------------------------------------------------------------------
# Role Permissions Documentation Schemas
# --------------------------------------------------------------------------

role_permissions_assign_docs = extend_schema(
    request=RolePermissionAssignSerializer,
    summary="Map Permission to Role",
    description=(
        "Associates a capability permission from the catalog with a target role.\n\n"
        f"**Required Permission**: `{PermissionCodes.ROLE_UPDATE}`  \n"
        "**Typical Roles**: `Super Administrator`"
    ),
    tags=["Role Permissions"],
    responses={
        201: OpenApiTypes.OBJECT,
        400: bad_request_response,
        401: unauthorized_response,
        403: forbidden_response,
        404: not_found_response,
        409: conflict_response,
    }
)

role_permissions_remove_docs = extend_schema(
    request=RolePermissionRemoveSerializer,
    summary="Revoke Permission from Role",
    description=(
        "Revokes a capability permission association from a target role (soft clear).\n\n"
        f"**Required Permission**: `{PermissionCodes.ROLE_UPDATE}`  \n"
        "**Typical Roles**: `Super Administrator`"
    ),
    tags=["Role Permissions"],
    responses={
        200: OpenApiTypes.OBJECT,
        401: unauthorized_response,
        403: forbidden_response,
        404: not_found_response,
    }
)

role_permissions_list_docs = extend_schema(
    summary="List Role Permissions",
    description=(
        "Retrieves all permission catalog capabilities currently mapped to a target role.\n\n"
        f"**Required Permission**: `{PermissionCodes.ROLE_READ}`  \n"
        "**Typical Roles**: `Super Administrator`, `Administrator`, `Manager`"
    ),
    tags=["Role Permissions"],
    parameters=[
        OpenApiParameter(
            name="is_active",
            type=OpenApiTypes.BOOL,
            location=OpenApiParameter.QUERY,
            required=False,
            description="Filter active/revoked mappings."
        )
    ],
    responses={
        200: OpenApiTypes.OBJECT,
        401: unauthorized_response,
        403: forbidden_response,
        404: not_found_response,
    }
)

# --------------------------------------------------------------------------
# User Roles Documentation Schemas
# --------------------------------------------------------------------------

user_roles_assign_docs = extend_schema(
    request=UserRoleAssignSerializer,
    summary="Assign Role to User",
    description=(
        "Grants a security role membership to a user.\n\n"
        f"**Required Permission**: `{PermissionCodes.USER_UPDATE}`  \n"
        "**Typical Roles**: `Super Administrator`, `Administrator`"
    ),
    tags=["User Roles"],
    responses={
        201: OpenApiTypes.OBJECT,
        400: bad_request_response,
        401: unauthorized_response,
        403: forbidden_response,
        404: not_found_response,
        409: conflict_response,
    }
)

user_roles_revoke_docs = extend_schema(
    request=UserRoleRevokeSerializer,
    summary="Revoke Role from User",
    description=(
        "Soft-deactivates a user's role assignment mapping.\n\n"
        f"**Required Permission**: `{PermissionCodes.USER_UPDATE}`  \n"
        "**Typical Roles**: `Super Administrator`, `Administrator`"
    ),
    tags=["User Roles"],
    responses={
        200: OpenApiTypes.OBJECT,
        401: unauthorized_response,
        403: forbidden_response,
        404: not_found_response,
    }
)

user_roles_extend_docs = extend_schema(
    request=UserRoleExtendSerializer,
    summary="Extend JIT Role Expiration",
    description=(
        "Modifies the temporal expiration parameters of an active role assignment.\n\n"
        f"**Required Permission**: `{PermissionCodes.USER_UPDATE}`  \n"
        "**Typical Roles**: `Super Administrator`, `Administrator`"
    ),
    tags=["User Roles"],
    responses={
        200: OpenApiTypes.OBJECT,
        400: bad_request_response,
        401: unauthorized_response,
        403: forbidden_response,
        404: not_found_response,
    }
)

user_roles_list_docs = extend_schema(
    summary="List User Roles",
    description=(
        "Retrieves all roles currently mapped to a target user.\n\n"
        f"**Required Permission**: `{PermissionCodes.USER_READ}`  \n"
        "**Typical Roles**: `Super Administrator`, `Administrator`, `Manager`"
    ),
    tags=["User Roles"],
    parameters=[
        OpenApiParameter(
            name="is_active",
            type=OpenApiTypes.BOOL,
            location=OpenApiParameter.QUERY,
            required=False,
            description="Filter active/revoked mappings."
        )
    ],
    responses={
        200: OpenApiTypes.OBJECT,
        401: unauthorized_response,
        403: forbidden_response,
        404: not_found_response,
    }
)

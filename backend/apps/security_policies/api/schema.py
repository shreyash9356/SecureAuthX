from drf_spectacular.utils import extend_schema, OpenApiTypes
from apps.security_policies.api.serializers import (
    SecurityPolicySerializer,
    SecurityPolicyUpdateSerializer,
    PasswordPolicyCheckSerializer,
)

effective_policy_schema = extend_schema(
    summary="Get Effective Security Policy",
    description="Retrieve the active effective SecurityPolicy for the authenticated user context.",
    responses={200: SecurityPolicySerializer},
    tags=["Security Policies"],
)

global_policy_get_schema = extend_schema(
    summary="Get Global Security Policy",
    description="Retrieve the global default security policy (Admin only).",
    responses={200: SecurityPolicySerializer},
    tags=["Security Policies"],
)

global_policy_patch_schema = extend_schema(
    summary="Update Global Security Policy",
    description="Update rules on the global default security policy (Admin only).",
    request=SecurityPolicyUpdateSerializer,
    responses={200: SecurityPolicySerializer},
    tags=["Security Policies"],
)

policy_detail_get_schema = extend_schema(
    summary="Get Security Policy Detail",
    description="Retrieve details of a SecurityPolicy by UUID (Admin only).",
    responses={200: SecurityPolicySerializer},
    tags=["Security Policies"],
)

policy_detail_patch_schema = extend_schema(
    summary="Update Security Policy Detail",
    description="Update a specific SecurityPolicy record by UUID (Admin only).",
    request=SecurityPolicyUpdateSerializer,
    responses={200: SecurityPolicySerializer},
    tags=["Security Policies"],
)

policy_toggle_schema = extend_schema(
    summary="Toggle Security Policy Status",
    description="Enable or disable a SecurityPolicy (Admin only).",
    request=OpenApiTypes.OBJECT,
    responses={200: SecurityPolicySerializer},
    tags=["Security Policies"],
)

validate_password_schema = extend_schema(
    summary="Validate Password Against Policy",
    description="Tests a raw password against the user's active security policy.",
    request=PasswordPolicyCheckSerializer,
    responses={200: OpenApiTypes.OBJECT},
    tags=["Security Policies"],
)

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.core.exceptions import ValidationError

from apps.security_policies.selectors import (
    get_global_security_policy,
    get_user_effective_policy,
    get_policy_by_id,
)
from apps.security_policies.services.security_policy_service import SecurityPolicyService
from apps.security_policies.services.password_policy_service import PasswordPolicyService
from apps.security_policies.api.serializers import (
    SecurityPolicySerializer,
    SecurityPolicyUpdateSerializer,
    PasswordPolicyCheckSerializer,
)
from apps.security_policies.api.schema import (
    effective_policy_schema,
    global_policy_get_schema,
    global_policy_patch_schema,
    policy_detail_get_schema,
    policy_detail_patch_schema,
    policy_toggle_schema,
    validate_password_schema,
)


class EffectiveSecurityPolicyAPIView(APIView):
    """
    GET /api/v1/security-policies/effective/
    Retrieve the active effective SecurityPolicy for the authenticated user context.
    """
    permission_classes = [IsAuthenticated]

    @effective_policy_schema
    def get(self, request):
        policy = SecurityPolicyService.get_effective_policy(user=request.user)
        serializer = SecurityPolicySerializer(policy)
        return Response(
            {
                "success": True,
                "message": "Effective security policy retrieved.",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )


class GlobalSecurityPolicyAPIView(APIView):
    """
    GET /api/v1/security-policies/global/
    PATCH /api/v1/security-policies/global/
    View or update the global system security policy (Admin only).
    """
    permission_classes = [IsAuthenticated, IsAdminUser]

    @global_policy_get_schema
    def get(self, request):
        policy = get_global_security_policy()
        serializer = SecurityPolicySerializer(policy)
        return Response(
            {
                "success": True,
                "message": "Global security policy retrieved.",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )

    @global_policy_patch_schema
    def patch(self, request):
        policy = get_global_security_policy()
        serializer = SecurityPolicyUpdateSerializer(policy, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        
        updated_policy = SecurityPolicyService.create_or_update_policy(
            policy_id=str(policy.id),
            actor=request.user,
            **serializer.validated_data,
        )

        response_serializer = SecurityPolicySerializer(updated_policy)
        return Response(
            {
                "success": True,
                "message": "Global security policy updated successfully.",
                "data": response_serializer.data,
            },
            status=status.HTTP_200_OK,
        )


class SecurityPolicyDetailAPIView(APIView):
    """
    GET /api/v1/security-policies/{id}/
    PATCH /api/v1/security-policies/{id}/
    View or update a specific SecurityPolicy record by UUID (Admin only).
    """
    permission_classes = [IsAuthenticated, IsAdminUser]

    @policy_detail_get_schema
    def get(self, request, pk):
        policy = get_policy_by_id(pk)
        serializer = SecurityPolicySerializer(policy)
        return Response(
            {
                "success": True,
                "message": "Security policy details retrieved.",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )

    @policy_detail_patch_schema
    def patch(self, request, pk):
        policy = get_policy_by_id(pk)
        serializer = SecurityPolicyUpdateSerializer(policy, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        updated_policy = SecurityPolicyService.create_or_update_policy(
            policy_id=str(policy.id),
            actor=request.user,
            **serializer.validated_data,
        )

        response_serializer = SecurityPolicySerializer(updated_policy)
        return Response(
            {
                "success": True,
                "message": "Security policy updated successfully.",
                "data": response_serializer.data,
            },
            status=status.HTTP_200_OK,
        )


class SecurityPolicyToggleAPIView(APIView):
    """
    PATCH /api/v1/security-policies/{id}/toggle/
    Enable or disable a SecurityPolicy (Admin only).
    """
    permission_classes = [IsAuthenticated, IsAdminUser]

    @policy_toggle_schema
    def patch(self, request, pk):
        is_active = request.data.get("is_active", True)
        policy = SecurityPolicyService.toggle_policy_status(
            policy_id=pk,
            is_active=is_active,
            actor=request.user,
        )
        serializer = SecurityPolicySerializer(policy)
        return Response(
            {
                "success": True,
                "message": f"Security policy {'enabled' if is_active else 'disabled'} successfully.",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )


class ValidatePasswordPolicyAPIView(APIView):
    """
    POST /api/v1/security-policies/validate-password/
    Tests a candidate password against the user's effective security policy.
    """
    permission_classes = [IsAuthenticated]

    @validate_password_schema
    def post(self, request):
        serializer = PasswordPolicyCheckSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        password = serializer.validated_data["password"]
        try:
            PasswordPolicyService.validate_password_against_policy(
                password=password,
                user=request.user,
            )
        except ValidationError as e:
            errors = e.message_dict if hasattr(e, "message_dict") else {"password": e.messages}
            return Response(
                {
                    "success": False,
                    "message": "Password validation failed.",
                    "errors": errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {
                "success": True,
                "message": "Password satisfies all effective security policy rules.",
            },
            status=status.HTTP_200_OK,
        )

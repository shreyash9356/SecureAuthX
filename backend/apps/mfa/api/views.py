"""
API Views for the Multi-Factor Authentication (MFA) module.
"""

from drf_spectacular.utils import extend_schema, OpenApiParameter
from rest_framework import status
from rest_framework.exceptions import PermissionDenied, NotFound, ValidationError
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken, Token
from rest_framework_simplejwt.exceptions import TokenError
from datetime import timedelta

from apps.authorization.permissions import IsAdmin
from apps.common.responses import success_response, error_response
from apps.user_sessions.services.session_service import SessionService
from apps.user_sessions.utils import parse_user_agent
from apps.audit_logs.utils import get_client_ip, get_user_agent
from apps.mfa.api.serializers import (
    MFADeviceSerializer,
    MFASetupInitiateSerializer,
    MFAActivationSerializer,
    MFALoginVerificationSerializer,
    MFARecoveryCodeVerificationSerializer,
    MFADisableSerializer,
)
from apps.mfa.selectors.mfa_selector import MFASelector
from apps.mfa.services.setup import MFASetupService
from apps.mfa.services.verification import MFAVerificationService
from apps.mfa.services.recovery import MFARecoveryService
from apps.mfa.services.disable import MFADisableService
from apps.mfa.services.admin import MFAAdminService
from django.contrib.auth import get_user_model

User = get_user_model()


class MFAPendingToken(Token):
    """
    Short-lived, single-use token issued upon password verification
    when MFA is enabled. Valid for 5 minutes.
    """

    token_type = "mfa_pending"
    lifetime = timedelta(minutes=5)


class MFADeviceStatusAPIView(APIView):
    """
    API endpoint to retrieve the current user's MFA status.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Get MFA Status",
        description="Retrieve the multi-factor authentication status for the authenticated user.",
        tags=["Multi-Factor Authentication (MFA)"],
        responses={200: MFADeviceSerializer},
    )
    def get(self, request):
        device = MFASelector.get_device_by_user(request.user)

        if not device:
            return success_response(
                data={
                    "configured": False,
                    "enabled": False,
                    "locked": False,
                },
                message="MFA is not configured for this account.",
            )

        serializer = MFADeviceSerializer(device)

        return success_response(
            data={
                "configured": True,
                **serializer.data,
            },
            message="MFA configuration details retrieved.",
        )



class MFASetupInitiateAPIView(APIView):
    """
    API endpoint to initiate MFA setup. Generates a new TOTP secret.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Initiate MFA Setup",
        description="Generates a new TOTP secret and QR code provisioning URI. MFA remains unverified until activated.",
        tags=["Multi-Factor Authentication (MFA)"],
        responses={200: MFASetupInitiateSerializer},
    )
    def post(self, request):
        manual_key, provisioning_uri, qr_code = MFASetupService.initiate_mfa_setup(
            request.user
        )
        return success_response(
            data={
                "manual_key": manual_key,
                "provisioning_uri": provisioning_uri,
                "qr_code": qr_code,
            },
            message="MFA setup successfully initiated. Verify initial code to activate.",
        )


class MFAActivationAPIView(APIView):
    """
    API endpoint to verify the initial OTP and activate MFA.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Activate MFA",
        description="Verifies the initial OTP code from the authenticator app and activates MFA. Returns 10 one-time recovery codes.",
        tags=["Multi-Factor Authentication (MFA)"],
        request=MFAActivationSerializer,
        responses={200: MFAActivationSerializer},
    )
    def post(self, request):
        serializer = MFAActivationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        otp_code = serializer.validated_data["otp_code"]

        recovery_codes = MFASetupService.activate_mfa(request.user, otp_code)
        return success_response(
            data={"recovery_codes": recovery_codes},
            message="MFA has been successfully activated. Keep your recovery codes safe.",
        )


class MFADisableAPIView(APIView):
    """
    API endpoint to disable MFA. Requires password and OTP/Recovery confirmation.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Disable MFA",
        description="Disables multi-factor authentication and purges secrets. Requires password confirmation and either a valid OTP or recovery code.",
        tags=["Multi-Factor Authentication (MFA)"],
        request=MFADisableSerializer,
        responses={200: dict, 400: dict},
    )
    def post(self, request):
        serializer = MFADisableSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        password = serializer.validated_data["password"]
        otp_code = serializer.validated_data.get("otp_code")
        recovery_code = serializer.validated_data.get("recovery_code")

        MFADisableService.disable_mfa(
            request.user,
            password_confirmation=password,
            otp_code=otp_code,
            recovery_code=recovery_code,
        )

        return success_response(
            data={},
            message="MFA has been successfully disabled and credentials purged.",
        )


class MFARecoveryCodeRegenerateAPIView(APIView):
    """
    API endpoint to regenerate recovery codes. Invalidates previous codes.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Regenerate Recovery Codes",
        description="Generates a new batch of 10 one-time recovery codes and invalidates all previous ones.",
        tags=["Multi-Factor Authentication (MFA)"],
        responses={200: dict},
    )
    def post(self, request):
        new_codes = MFARecoveryService.regenerate_recovery_codes(request.user)
        return success_response(
            data={"recovery_codes": new_codes},
            message="MFA recovery codes successfully regenerated.",
        )


class MFALoginVerifyAPIView(APIView):
    """
    API endpoint to verify TOTP code or recovery code during login.
    """

    permission_classes = [AllowAny]

    @extend_schema(
        summary="Verify MFA Login",
        description="Validates the temporary `mfa_token` and the OTP code (or recovery code) to complete the login flow. Issues standard JWT tokens.",
        tags=["Multi-Factor Authentication (MFA)"],
        parameters=[
            OpenApiParameter(
                "mfa_token",
                description="The short-lived token returned by the initial password authentication.",
                required=True,
                type=str,
            )
        ],
        request=MFALoginVerificationSerializer,
        responses={200: dict, 400: dict, 401: dict},
    )
    def post(self, request):
        mfa_token_str = request.query_params.get("mfa_token")
        if not mfa_token_str:
            raise ValidationError({"mfa_token": ["MFA token is required."]})

        # 1. Decode and validate the temporary MFA token
        try:
            mfa_token = MFAPendingToken(mfa_token_str)
            user_id = mfa_token.payload.get("user_id")
            user = User.objects.get(id=user_id)
        except (TokenError, User.DoesNotExist) as exc:
            return error_response(
                errors={"detail": "MFA pending token is invalid or has expired."},
                message="MFA verification failed.",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        # 2. Check if the body contains a recovery code instead of OTP code
        otp_code = request.data.get("otp_code")
        recovery_code = request.data.get("recovery_code")

        if otp_code:
            MFAVerificationService.verify_otp_login(user, otp_code)
        elif recovery_code:
            MFARecoveryService.verify_and_use_recovery_code(user, recovery_code)
        else:
            raise ValidationError(
                {"detail": "Either otp_code or recovery_code must be provided."}
            )

        # 3. Successful verification path: Issue full JWTs and Session
        # Resolve organization context
        from apps.organizations.models import OrganizationMembership
        from apps.organizations.constants import MembershipStatus

        membership = OrganizationMembership.objects.filter(
            user=user, status=MembershipStatus.ACTIVE
        ).first()
        org = membership.organization if membership else None

        # Parse request metadata
        user_agent = get_user_agent(request)
        ip_address = get_client_ip(request) or "0.0.0.0"
        device_type, browser, operating_system = parse_user_agent(user_agent)

        session = SessionService.create_session(
            user=user,
            organization=org,
            ip_address=ip_address,
            user_agent=user_agent,
            device_type=device_type,
            browser=browser,
            operating_system=operating_system,
        )

        refresh = RefreshToken.for_user(user)
        refresh["session_id"] = str(session.pk)

        return success_response(
            data={
                "access": str(refresh.access_token),
                "refresh": str(refresh),
            },
            message="MFA login verification successful.",
        )


class MFAAdminActionAPIView(APIView):
    """
    API endpoint for administrators to forcibly unlock or disable MFA for a user.
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    @extend_schema(
        summary="Admin MFA Action",
        description="Forcibly clear MFA lockout or disable MFA for a target user. Restricted to administrators.",
        tags=["Multi-Factor Authentication (MFA)"],
        parameters=[
            OpenApiParameter(
                "action",
                description="Action to perform: 'disable' or 'unlock'.",
                required=True,
                type=str,
            ),
            OpenApiParameter(
                "user_id",
                description="UUID of the target user.",
                required=True,
                type=str,
            ),
        ],
        responses={200: dict, 400: dict, 404: dict},
    )
    def post(self, request):
        action = request.query_params.get("action")
        target_user_id = request.query_params.get("user_id")

        if not action or not target_user_id:
            raise ValidationError(
                {"detail": "Both 'action' and 'user_id' parameters are required."}
            )

        try:
            target_user = User.objects.get(id=target_user_id)
        except User.DoesNotExist:
            raise NotFound("Target user not found.")

        if action == "disable":
            MFAAdminService.admin_disable_mfa(request.user, target_user)
            message = "MFA configuration successfully disabled by administrator."
        elif action == "unlock":
            MFAAdminService.admin_unlock_mfa(request.user, target_user)
            message = "MFA lockout successfully cleared by administrator."
        else:
            raise ValidationError(
                {"action": ["Invalid action. Choose 'disable' or 'unlock'."]}
            )

        return success_response(data={}, message=message)

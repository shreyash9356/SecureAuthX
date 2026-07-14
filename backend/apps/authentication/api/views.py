"""
API views for the SecureAuthX authentication module.

Each view is intentionally thin:
- Deserialise the request (always injecting ``request`` into context)
- Call serializer.save() which delegates to the service
- Return a standardised response

Business logic and audit logging live exclusively in the service layer.
"""

from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.authentication.api.docs.schemas import (
    change_password_schema,
    forgot_password_schema,
    login_schema,
    logout_schema,
    me_schema,
    refresh_token_schema,
    registration_schema,
    resend_verification_schema,
    reset_password_schema,
    verify_email_schema,
)
from apps.authentication.api.serializers import (
    ChangePasswordSerializer,
    ForgotPasswordSerializer,
    LoginSerializer,
    LogoutSerializer,
    MeSerializer,
    RefreshTokenSerializer,
    RegistrationSerializer,
    ResendVerificationSerializer,
    ResetPasswordSerializer,
)
from apps.authentication.constants import (
    EMAIL_VERIFICATION_SUCCESS,
    LOGIN_SUCCESS,
    LOGOUT_SUCCESS,
    PASSWORD_CHANGED_SUCCESS,
    PASSWORD_RESET_EMAIL_SENT,
    PASSWORD_RESET_SUCCESS,
    PROFILE_RETRIEVED_SUCCESS,
    REGISTRATION_SUCCESS,
    RESEND_VERIFICATION_SUCCESS,
    TOKEN_REFRESH_SUCCESS,
)
from apps.authentication.services.email_verification import EmailVerificationService
from apps.authentication.services.profile import ProfileService
from apps.authentication.utils import success_response


# ==============================================================================
# Registration
# ==============================================================================


@registration_schema
class RegistrationAPIView(APIView):
    """API endpoint for user registration."""

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegistrationSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        result = serializer.save()

        return Response(
            success_response(
                message=REGISTRATION_SUCCESS,
                data={
                    "user_id": str(result["user"].id),
                    "email": result["user"].email,
                },
            ),
            status=status.HTTP_201_CREATED,
        )


# ==============================================================================
# Login
# ==============================================================================


@login_schema
class LoginAPIView(APIView):
    """API endpoint for user authentication."""

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        result = serializer.save()

        return Response(
            success_response(
                message=LOGIN_SUCCESS,
                data={
                    "access": result["access"],
                    "refresh": result["refresh"],
                    "user": {
                        "id": str(result["user"].id),
                        "email": result["user"].email,
                        "first_name": result["user"].first_name,
                        "last_name": result["user"].last_name,
                    },
                },
            ),
            status=status.HTTP_200_OK,
        )


# ==============================================================================
# Profile (Me)
# ==============================================================================


@me_schema
class MeAPIView(APIView):
    """API endpoint for retrieving the authenticated user's profile."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = ProfileService.get_profile(request.user)
        serializer = MeSerializer(user)

        return Response(
            success_response(
                message=PROFILE_RETRIEVED_SUCCESS,
                data=serializer.data,
            ),
            status=status.HTTP_200_OK,
        )


# ==============================================================================
# Token Refresh
# ==============================================================================


@refresh_token_schema
class RefreshTokenAPIView(APIView):
    """API endpoint for refreshing JWT access tokens."""

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RefreshTokenSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        result = serializer.save()

        return Response(
            success_response(message=TOKEN_REFRESH_SUCCESS, data=result),
            status=status.HTTP_200_OK,
        )


# ==============================================================================
# Logout
# ==============================================================================


@logout_schema
class LogoutAPIView(APIView):
    """API endpoint for logging out a user."""

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LogoutSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            success_response(message=LOGOUT_SUCCESS, data={}),
            status=status.HTTP_200_OK,
        )


# ==============================================================================
# Email Verification
# ==============================================================================


@verify_email_schema
class VerifyEmailAPIView(APIView):
    """API endpoint for verifying a user's email address."""

    permission_classes = [AllowAny]

    def get(self, request):
        token = request.query_params.get("token")

        if not token:
            return Response(
                {"success": False, "message": "Verification token is required.", "errors": {}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        EmailVerificationService.verify(token=token, request=request)

        return Response(
            success_response(message=EMAIL_VERIFICATION_SUCCESS, data={}),
            status=status.HTTP_200_OK,
        )


# ==============================================================================
# Resend Verification
# ==============================================================================


@resend_verification_schema
class ResendVerificationAPIView(APIView):
    """API endpoint for resending verification emails."""

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ResendVerificationSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            success_response(message=RESEND_VERIFICATION_SUCCESS, data={}),
            status=status.HTTP_200_OK,
        )


# ==============================================================================
# Forgot Password
# ==============================================================================


@forgot_password_schema
class ForgotPasswordAPIView(APIView):
    """API endpoint for requesting a password reset link."""

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ForgotPasswordSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            success_response(message=PASSWORD_RESET_EMAIL_SENT, data={}),
            status=status.HTTP_200_OK,
        )


# ==============================================================================
# Reset Password
# ==============================================================================


@reset_password_schema
class ResetPasswordAPIView(APIView):
    """API endpoint for resetting a password via a signed token."""

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ResetPasswordSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            success_response(message=PASSWORD_RESET_SUCCESS, data={}),
            status=status.HTTP_200_OK,
        )


# ==============================================================================
# Change Password
# ==============================================================================


@change_password_schema
class ChangePasswordAPIView(APIView):
    """API endpoint for changing the authenticated user's password."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            success_response(message=PASSWORD_CHANGED_SUCCESS, data={}),
            status=status.HTTP_200_OK,
        )

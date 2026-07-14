"""
Serializers for the SecureAuthX authentication module.

Each serializer's ``create()`` method pulls ``request`` from
``self.context`` (injected by the view) and passes it to the
service layer so audit logs capture accurate IP and User-Agent data.
"""

from rest_framework import serializers

from apps.accounts.models import User
from apps.authentication.services.login import LoginService
from apps.authentication.services.registration import RegistrationService


class RegistrationSerializer(serializers.Serializer):
    """
    Serializer for user registration.
    """

    email = serializers.EmailField(max_length=255)
    username = serializers.CharField(max_length=150, required=False, allow_blank=True)
    first_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    password = serializers.CharField(write_only=True, style={"input_type": "password"})
    confirm_password = serializers.CharField(write_only=True, style={"input_type": "password"})

    def validate(self, attrs):
        if attrs["password"] != attrs["confirm_password"]:
            raise serializers.ValidationError(
                {"confirm_password": ["Passwords do not match."]}
            )
        return attrs

    def create(self, validated_data):
        validated_data.pop("confirm_password")
        return RegistrationService.register(
            email=validated_data["email"],
            password=validated_data["password"],
            username=validated_data.get("username"),
            first_name=validated_data.get("first_name", ""),
            last_name=validated_data.get("last_name", ""),
            request=self.context.get("request"),
        )


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login.
    """

    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(write_only=True, style={"input_type": "password"})

    def create(self, validated_data):
        return LoginService.login(
            email=validated_data["email"],
            password=validated_data["password"],
            request=self.context.get("request"),
        )


class MeSerializer(serializers.ModelSerializer):
    """
    Serializer for the authenticated user's profile.
    """

    full_name = serializers.ReadOnlyField()

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "username",
            "first_name",
            "last_name",
            "full_name",
            "is_verified",
            "is_active",
            "created_at",
        )
        read_only_fields = fields


class RefreshTokenSerializer(serializers.Serializer):
    """
    Serializer for refreshing JWT access tokens.
    """

    refresh = serializers.CharField()

    def create(self, validated_data):
        from apps.authentication.services.token_refresh import RefreshTokenService

        request = self.context.get("request")
        user = request.user if request and request.user.is_authenticated else None

        return RefreshTokenService.refresh(
            refresh_token=validated_data["refresh"],
            user=user,
            request=request,
        )


class LogoutSerializer(serializers.Serializer):
    """
    Serializer for logging out a user.
    """

    refresh = serializers.CharField()

    def create(self, validated_data):
        from apps.authentication.services.logout import LogoutService

        request = self.context.get("request")
        user = request.user if request and request.user.is_authenticated else None

        LogoutService.logout(
            refresh_token=validated_data["refresh"],
            user=user,
            request=request,
        )
        return {}


class ResendVerificationSerializer(serializers.Serializer):
    """
    Serializer for resending email verification.
    """

    email = serializers.EmailField()

    def create(self, validated_data):
        from apps.authentication.services.resend_verification import (
            ResendVerificationService,
        )

        ResendVerificationService.resend(
            email=validated_data["email"],
            request=self.context.get("request"),
        )
        return {}


class ForgotPasswordSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset email.
    """

    email = serializers.EmailField()

    def create(self, validated_data):
        from apps.authentication.services.forgot_password import ForgotPasswordService

        ForgotPasswordService.send_reset_link(
            email=validated_data["email"],
            request=self.context.get("request"),
        )
        return {}


class ResetPasswordSerializer(serializers.Serializer):
    """
    Serializer for resetting a password via a signed token.
    """

    token = serializers.CharField()
    password = serializers.CharField(write_only=True, style={"input_type": "password"})
    confirm_password = serializers.CharField(write_only=True, style={"input_type": "password"})

    def create(self, validated_data):
        from apps.authentication.services.password_reset import PasswordResetService

        PasswordResetService.reset_password(
            token=validated_data["token"],
            password=validated_data["password"],
            confirm_password=validated_data["confirm_password"],
            request=self.context.get("request"),
        )
        return {}


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for changing the authenticated user's password.
    """

    current_password = serializers.CharField(write_only=True, style={"input_type": "password"})
    new_password = serializers.CharField(write_only=True, style={"input_type": "password"})
    confirm_password = serializers.CharField(write_only=True, style={"input_type": "password"})

    def create(self, validated_data):
        from apps.authentication.services.password_change import PasswordChangeService

        request = self.context["request"]

        PasswordChangeService.change_password(
            user=request.user,
            current_password=validated_data["current_password"],
            new_password=validated_data["new_password"],
            confirm_password=validated_data["confirm_password"],
            request=request,
        )
        return {}

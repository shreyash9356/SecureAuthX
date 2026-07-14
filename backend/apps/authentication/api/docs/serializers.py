"""
Documentation-only serializers for the SecureAuthX authentication module.

These serializers exist solely to produce accurate OpenAPI response schemas
in drf-spectacular. They are never used for input validation or business logic.
"""

from rest_framework import serializers


# ==============================================================================
# Shared / Primitive Serializers
# ==============================================================================


class ErrorDetailSerializer(serializers.Serializer):
    """
    Represents a map of field-level validation errors.

    Each key is a field name; each value is a list of error strings.
    Used as the ``errors`` field in error response bodies.
    """

    # Declared as a DictField so Swagger renders it as a free-form object,
    # which accurately reflects the dynamic nature of DRF validation errors.
    errors = serializers.DictField(
        child=serializers.ListField(
            child=serializers.CharField(),
        ),
        required=False,
        default={},
        help_text=(
            "Field-level validation errors keyed by field name. "
            "Empty when the error is not field-specific."
        ),
    )


# ==============================================================================
# Registration Serializers
# ==============================================================================


class RegistrationUserDataSerializer(serializers.Serializer):
    """
    The ``data`` payload returned on successful registration.
    """

    user_id = serializers.UUIDField(
        help_text="Unique identifier of the newly created user account.",
    )
    email = serializers.EmailField(
        help_text="Email address of the newly created user account.",
    )


class RegistrationSuccessResponseSerializer(serializers.Serializer):
    """
    Success response body for ``POST /api/v1/auth/register/``.
    """

    success = serializers.BooleanField(
        default=True,
        help_text="Indicates whether the request completed successfully.",
    )
    message = serializers.CharField(
        default="Registration successful. Please verify your email.",
        help_text="Human-readable status message.",
    )
    data = RegistrationUserDataSerializer(
        help_text="Payload containing the new user's identifier and email.",
    )


class RegistrationErrorResponseSerializer(serializers.Serializer):
    """
    Error response body for ``POST /api/v1/auth/register/``.

    Returned for validation failures (400), duplicate email (409),
    and unexpected server errors (500).
    """

    success = serializers.BooleanField(
        default=False,
        help_text="Always ``false`` for error responses.",
    )
    message = serializers.CharField(
        help_text="Human-readable description of the error.",
    )
    errors = serializers.DictField(
        child=serializers.ListField(
            child=serializers.CharField(),
        ),
        default={},
        help_text=(
            "Field-level validation errors. "
            "Empty for non-validation errors such as duplicate email."
        ),
    )


# ==============================================================================
# Login Serializers
# ==============================================================================


class LoginUserDataSerializer(serializers.Serializer):
    """
    The nested ``user`` object returned within a successful login response.
    """

    id = serializers.UUIDField(
        help_text="Unique identifier of the authenticated user.",
    )
    email = serializers.EmailField(
        help_text="Email address of the authenticated user.",
    )
    first_name = serializers.CharField(
        help_text="Given name of the authenticated user.",
    )
    last_name = serializers.CharField(
        help_text="Family name of the authenticated user.",
    )


class LoginDataSerializer(serializers.Serializer):
    """
    The ``data`` payload returned on successful authentication.
    """

    access = serializers.CharField(
        help_text=(
            "Short-lived JWT access token (15-minute expiry). "
            "Include in the ``Authorization: Bearer <token>`` header "
            "for all authenticated requests."
        ),
    )
    refresh = serializers.CharField(
        help_text=(
            "Long-lived JWT refresh token (7-day expiry). "
            "Use with ``POST /api/v1/auth/token/refresh/`` "
            "to obtain a new access token without re-authenticating."
        ),
    )
    user = LoginUserDataSerializer(
        help_text="Basic profile information for the authenticated user.",
    )


class LoginSuccessResponseSerializer(serializers.Serializer):
    """
    Success response body for ``POST /api/v1/auth/login/``.
    """

    success = serializers.BooleanField(
        default=True,
        help_text="Indicates whether the request completed successfully.",
    )
    message = serializers.CharField(
        default="Login successful.",
        help_text="Human-readable status message.",
    )
    data = LoginDataSerializer(
        help_text="Payload containing JWT tokens and authenticated user profile.",
    )


class LoginErrorResponseSerializer(serializers.Serializer):
    """
    Error response body for ``POST /api/v1/auth/login/``.

    Returned for invalid credentials (401), unverified email (403),
    inactive or locked account (403), and server errors (500).
    """

    success = serializers.BooleanField(
        default=False,
        help_text="Always ``false`` for error responses.",
    )
    message = serializers.CharField(
        help_text="Human-readable description of the authentication failure.",
    )
    errors = serializers.DictField(
        default={},
        help_text="Empty for authentication failures; reserved for future use.",
    )


# ==============================================================================
# Refresh Token Serializers
# ==============================================================================


class RefreshTokenRequestSerializer(serializers.Serializer):
    """
    Request body for refreshing a JWT access token.
    """

    refresh = serializers.CharField(help_text="Valid JWT refresh token.")


class RefreshTokenDataSerializer(serializers.Serializer):
    """
    Data returned after a successful refresh.
    """

    access = serializers.CharField(help_text="Newly issued JWT access token.")


class RefreshTokenSuccessResponseSerializer(serializers.Serializer):
    """
    Success response body for POST /api/v1/auth/token/refresh/
    """

    success = serializers.BooleanField(default=True)
    message = serializers.CharField(default="Access token refreshed successfully.")
    data = RefreshTokenDataSerializer()


class RefreshTokenErrorResponseSerializer(serializers.Serializer):
    """
    Error response body for POST /api/v1/auth/token/refresh/
    """

    success = serializers.BooleanField(default=False)
    message = serializers.CharField()
    errors = serializers.DictField(default={})


# ==============================================================================
# Logout Serializers
# ==============================================================================


class LogoutRequestSerializer(serializers.Serializer):
    """
    Request body for logging out a user.
    """

    refresh = serializers.CharField(
        help_text="Valid JWT refresh token to be blacklisted."
    )


class LogoutSuccessResponseSerializer(serializers.Serializer):
    """
    Success response body for POST /api/v1/auth/logout/
    """

    success = serializers.BooleanField(default=True)

    message = serializers.CharField(default="Logout successful.")

    data = serializers.DictField(default={}, help_text="Always an empty object.")


class LogoutErrorResponseSerializer(serializers.Serializer):
    """
    Error response body for POST /api/v1/auth/logout/
    """

    success = serializers.BooleanField(default=False)

    message = serializers.CharField()

    errors = serializers.DictField(default={})


# ==============================================================================
# Resendverification Serializers
# ==============================================================================


class ResendVerificationRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class ResendVerificationSuccessResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField(default=True)
    message = serializers.CharField()
    data = serializers.DictField(default={})


class ResendVerificationErrorResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField(default=False)
    message = serializers.CharField()
    errors = serializers.DictField(default={})


# ==============================================================================
# Forgot Password Serializers
# ==============================================================================


class ForgotPasswordRequestSerializer(serializers.Serializer):
    """
    Request body for ``POST /api/v1/auth/forgot-password/``.
    """

    email = serializers.EmailField(
        help_text="Email address associated with the account.",
    )


class ForgotPasswordSuccessResponseSerializer(serializers.Serializer):
    """
    Success response body for ``POST /api/v1/auth/forgot-password/``.

    Always returned regardless of whether the email exists in the database
    in order to prevent account enumeration.
    """

    success = serializers.BooleanField(
        default=True,
        help_text="Indicates whether the request completed successfully.",
    )
    message = serializers.CharField(
        default="If an account exists, a password reset link has been sent.",
        help_text="Generic human-readable status message.",
    )
    data = serializers.DictField(
        default={},
        help_text="Always an empty object for this endpoint.",
    )


class ForgotPasswordErrorResponseSerializer(serializers.Serializer):
    """
    Error response body for ``POST /api/v1/auth/forgot-password/``.

    Returned for field validation failures (400) and server errors (500).
    """

    success = serializers.BooleanField(
        default=False,
        help_text="Always ``false`` for error responses.",
    )
    message = serializers.CharField(
        help_text="Human-readable description of the error.",
    )
    errors = serializers.DictField(
        child=serializers.ListField(child=serializers.CharField()),
        default={},
        help_text="Field-level validation errors.",
    )


# ==============================================================================
# Reset Password Serializers
# ==============================================================================


class ResetPasswordRequestSerializer(serializers.Serializer):
    """
    Request body for ``POST /api/v1/auth/reset-password/``.
    """

    token = serializers.CharField(
        help_text="Signed password reset token received via email.",
    )
    password = serializers.CharField(
        help_text="New password satisfying the enterprise password policy.",
    )
    confirm_password = serializers.CharField(
        help_text="Must match ``password`` exactly.",
    )


class ResetPasswordSuccessResponseSerializer(serializers.Serializer):
    """
    Success response body for ``POST /api/v1/auth/reset-password/``.
    """

    success = serializers.BooleanField(
        default=True,
        help_text="Indicates whether the request completed successfully.",
    )
    message = serializers.CharField(
        default="Password reset successful.",
        help_text="Human-readable status message.",
    )
    data = serializers.DictField(
        default={},
        help_text="Always an empty object for this endpoint.",
    )


class ResetPasswordErrorResponseSerializer(serializers.Serializer):
    """
    Error response body for ``POST /api/v1/auth/reset-password/``.

    Returned for invalid/expired tokens (400), weak passwords (400),
    password mismatch (400), and server errors (500).
    """

    success = serializers.BooleanField(
        default=False,
        help_text="Always ``false`` for error responses.",
    )
    message = serializers.CharField(
        help_text="Human-readable description of the error.",
    )
    errors = serializers.DictField(
        child=serializers.ListField(child=serializers.CharField()),
        default={},
        help_text="Field-level validation errors.",
    )


# ==============================================================================
# Change Password Serializers
# ==============================================================================


class ChangePasswordRequestSerializer(serializers.Serializer):
    """
    Request body for ``POST /api/v1/auth/change-password/``.
    """

    current_password = serializers.CharField(
        help_text="The user's existing password.",
    )
    new_password = serializers.CharField(
        help_text="New password satisfying the enterprise password policy.",
    )
    confirm_password = serializers.CharField(
        help_text="Must match ``new_password`` exactly.",
    )


class ChangePasswordSuccessResponseSerializer(serializers.Serializer):
    """
    Success response body for ``POST /api/v1/auth/change-password/``.
    """

    success = serializers.BooleanField(
        default=True,
        help_text="Indicates whether the request completed successfully.",
    )
    message = serializers.CharField(
        default="Password changed successfully.",
        help_text="Human-readable status message.",
    )
    data = serializers.DictField(
        default={},
        help_text="Always an empty object for this endpoint.",
    )


class ChangePasswordErrorResponseSerializer(serializers.Serializer):
    """
    Error response body for ``POST /api/v1/auth/change-password/``.

    Returned for incorrect current password (401), mismatched passwords (400),
    weak new password (400), and server errors (500).
    """

    success = serializers.BooleanField(
        default=False,
        help_text="Always ``false`` for error responses.",
    )
    message = serializers.CharField(
        help_text="Human-readable description of the error.",
    )
    errors = serializers.DictField(
        child=serializers.ListField(child=serializers.CharField()),
        default={},
        help_text="Field-level validation errors.",
    )


# ==============================================================================
# Me (Profile) Serializers
# ==============================================================================


class MeUserDataSerializer(serializers.Serializer):
    """
    The ``data`` payload returned by ``GET /api/v1/auth/me/``.
    """

    id = serializers.UUIDField(
        help_text="Unique identifier of the user.",
    )
    email = serializers.EmailField(
        help_text="Email address of the user.",
    )
    username = serializers.CharField(
        allow_null=True,
        help_text="Optional username.",
    )
    first_name = serializers.CharField(
        help_text="Given name.",
    )
    last_name = serializers.CharField(
        help_text="Family name.",
    )
    full_name = serializers.CharField(
        help_text="Computed full name (first + last).",
    )
    is_verified = serializers.BooleanField(
        help_text="Whether the email address has been verified.",
    )
    is_active = serializers.BooleanField(
        help_text="Whether the account is active.",
    )
    created_at = serializers.DateTimeField(
        help_text="Account creation timestamp (ISO 8601).",
    )


class MeSuccessResponseSerializer(serializers.Serializer):
    """
    Success response body for ``GET /api/v1/auth/me/``.
    """

    success = serializers.BooleanField(
        default=True,
        help_text="Indicates whether the request completed successfully.",
    )
    message = serializers.CharField(
        default="Profile retrieved successfully.",
        help_text="Human-readable status message.",
    )
    data = MeUserDataSerializer(
        help_text="Authenticated user's profile data.",
    )


class MeErrorResponseSerializer(serializers.Serializer):
    """
    Error response body for ``GET /api/v1/auth/me/``.

    Returned when no valid JWT token is supplied (401).
    """

    success = serializers.BooleanField(
        default=False,
        help_text="Always ``false`` for error responses.",
    )
    message = serializers.CharField(
        help_text="Human-readable description of the error.",
    )
    errors = serializers.DictField(
        default={},
        help_text="Detail field from the authentication layer.",
    )


# ==============================================================================
# Verify Email Serializers
# ==============================================================================


class VerifyEmailSuccessResponseSerializer(serializers.Serializer):
    """
    Success response body for ``GET /api/v1/auth/verify-email/``.
    """

    success = serializers.BooleanField(
        default=True,
        help_text="Indicates whether the request completed successfully.",
    )
    message = serializers.CharField(
        default="Email verified successfully.",
        help_text="Human-readable status message.",
    )
    data = serializers.DictField(
        default={},
        help_text="Always an empty object for this endpoint.",
    )


class VerifyEmailErrorResponseSerializer(serializers.Serializer):
    """
    Error response body for ``GET /api/v1/auth/verify-email/``.

    Returned when the token is missing (400), invalid, or expired (400).
    """

    success = serializers.BooleanField(
        default=False,
        help_text="Always ``false`` for error responses.",
    )
    message = serializers.CharField(
        help_text="Human-readable description of the error.",
    )
    errors = serializers.DictField(
        default={},
        help_text="Empty for token errors; reserved for future use.",
    )

"""
``@extend_schema`` decorator factories for the SecureAuthX authentication views.

Keeping schema definitions in a dedicated module separates documentation
concerns from view logic. Views import and apply these decorators directly.
"""

from drf_spectacular.utils import OpenApiResponse, extend_schema
from drf_spectacular.utils import OpenApiParameter

from apps.authentication.api.docs.examples import (
    LOGIN_ACCOUNT_INACTIVE_EXAMPLE,
    LOGIN_ACCOUNT_LOCKED_EXAMPLE,
    LOGIN_EMAIL_NOT_VERIFIED_EXAMPLE,
    LOGIN_INVALID_CREDENTIALS_EXAMPLE,
    LOGIN_REQUEST_EXAMPLE,
    LOGIN_SERVER_ERROR_EXAMPLE,
    LOGIN_SUCCESS_EXAMPLE,
    LOGIN_VALIDATION_ERROR_EXAMPLE,
    REGISTRATION_DUPLICATE_EMAIL_EXAMPLE,
    REGISTRATION_MINIMAL_REQUEST_EXAMPLE,
    REGISTRATION_REQUEST_EXAMPLE,
    REGISTRATION_SERVER_ERROR_EXAMPLE,
    REGISTRATION_SUCCESS_EXAMPLE,
    REGISTRATION_VALIDATION_ERROR_EXAMPLE,
    REGISTRATION_WEAK_PASSWORD_EXAMPLE,
    REFRESH_TOKEN_REQUEST_EXAMPLE,
    REFRESH_TOKEN_SUCCESS_EXAMPLE,
    REFRESH_TOKEN_INVALID_EXAMPLE,
    LOGOUT_REQUEST_EXAMPLE,
    LOGOUT_SUCCESS_EXAMPLE,
    LOGOUT_INVALID_TOKEN_EXAMPLE,
    RESEND_VERIFICATION_REQUEST_EXAMPLE,
    RESEND_VERIFICATION_SUCCESS_EXAMPLE,
    
)
from apps.authentication.api.docs.serializers import (
    LoginErrorResponseSerializer,
    LoginSuccessResponseSerializer,
    RegistrationErrorResponseSerializer,
    RegistrationSuccessResponseSerializer,
    RefreshTokenSuccessResponseSerializer,
    RefreshTokenErrorResponseSerializer,
    RefreshTokenRequestSerializer,
    LogoutRequestSerializer,
    LogoutSuccessResponseSerializer,
    LogoutErrorResponseSerializer,
    RefreshTokenDataSerializer,
    ResendVerificationRequestSerializer,
    ResendVerificationSuccessResponseSerializer,
    ResendVerificationErrorResponseSerializer,
)

from apps.authentication.api.serializers import (
    LoginSerializer,
    RegistrationSerializer,
)

# ==============================================================================
# Registration Schema
# ==============================================================================

registration_schema = extend_schema(
    # ── Identity ───────────────────────────────────────────────────────────────
    summary="Register a new user account",
    description=(
        "Creates a new user account and sends an email verification link "
        "to the supplied address.\n\n"
        "**The account cannot be used to log in until the email address is "
        "verified.**\n\n"
        "### Password Policy\n\n"
        "Passwords must satisfy all of the following requirements:\n\n"
        "- Minimum length: **12 characters**\n"
        "- At least one **uppercase** letter (A–Z)\n"
        "- At least one **lowercase** letter (a–z)\n"
        "- At least one **digit** (0–9)\n"
        "- At least one **special character** (!@#$%^&* etc.)\n"
        "- Must not be a commonly used password\n"
        "- Must not be too similar to the email address\n\n"
        "### Duplicate Email Handling\n\n"
        "If the email is already registered, a `409 Conflict` is returned. "
        "No information about the existing account is disclosed.\n\n"
        "### Security Notes\n\n"
        "- Passwords are hashed with **Argon2id** before storage.\n"
        "- The verification token is single-use and expires after **24 hours**.\n"
        "- This endpoint does not require authentication."
    ),
    tags=["Authentication"],

    # ── Request ────────────────────────────────────────────────────────────────
    request=RegistrationSerializer,

    # ── Responses ─────────────────────────────────────────────────────────────
    responses={
        201: OpenApiResponse(
            response=RegistrationSuccessResponseSerializer,
            description=(
                "Account created successfully. "
                "A verification email has been dispatched."
            ),
        ),
        400: OpenApiResponse(
            response=RegistrationErrorResponseSerializer,
            description=(
                "Request validation failed. "
                "Inspect the ``errors`` object for field-level details."
            ),
        ),
        409: OpenApiResponse(
            response=RegistrationErrorResponseSerializer,
            description=(
                "An account with the supplied email address already exists."
            ),
        ),
        500: OpenApiResponse(
            response=RegistrationErrorResponseSerializer,
            description="Unexpected internal server error.",
        ),
    },

    # ── Examples ──────────────────────────────────────────────────────────────
    examples=[
        REGISTRATION_REQUEST_EXAMPLE,
        REGISTRATION_MINIMAL_REQUEST_EXAMPLE,
        REGISTRATION_SUCCESS_EXAMPLE,
        REGISTRATION_VALIDATION_ERROR_EXAMPLE,
        REGISTRATION_WEAK_PASSWORD_EXAMPLE,
        REGISTRATION_DUPLICATE_EMAIL_EXAMPLE,
        REGISTRATION_SERVER_ERROR_EXAMPLE,
    ],
)

# ==============================================================================
# Login Schema
# ==============================================================================

login_schema = extend_schema(
    # ── Identity ───────────────────────────────────────────────────────────────
    summary="Authenticate and obtain JWT tokens",
    description=(
        "Validates the supplied credentials and, on success, issues a "
        "short-lived **JWT access token** and a long-lived **JWT refresh token**.\n\n"
        "### Token Usage\n\n"
        "| Token | Lifetime | Usage |\n"
        "|---|---|---|\n"
        "| Access token | 15 minutes | `Authorization: Bearer <token>` header |\n"
        "| Refresh token | 7 days | `POST /api/v1/auth/token/refresh/` |\n\n"
        "### Token Storage Recommendations\n\n"
        "- Store the **access token** in memory only (not in `localStorage` "
        "or `sessionStorage`) to mitigate XSS risks.\n"
        "- Store the **refresh token** in an `HttpOnly`, `Secure`, `SameSite=Strict` "
        "cookie to prevent JavaScript access.\n\n"
        "### Authentication Checks (in order)\n\n"
        "1. Credentials must match a registered account.\n"
        "2. The email address must be verified.\n"
        "3. The account must be active.\n"
        "4. The account must not be locked.\n\n"
        "A deliberate **generic error message** (`Invalid email or password.`) "
        "is returned for credential failures to prevent user enumeration.\n\n"
        "### Security Notes\n\n"
        "- Email lookup is case-insensitive.\n"
        "- Refresh tokens are automatically rotated on each use "
        "(`ROTATE_REFRESH_TOKENS = True`).\n"
        "- Rotated refresh tokens are blacklisted immediately "
        "(`BLACKLIST_AFTER_ROTATION = True`).\n"
        "- This endpoint does not require authentication."
    ),
    tags=["Authentication"],

    # ── Request ────────────────────────────────────────────────────────────────
    request=LoginSerializer,

    # ── Responses ─────────────────────────────────────────────────────────────
    responses={
        200: OpenApiResponse(
            response=LoginSuccessResponseSerializer,
            description=(
                "Authentication successful. "
                "JWT access and refresh tokens are included in the response body."
            ),
        ),
        400: OpenApiResponse(
            response=LoginErrorResponseSerializer,
            description=(
                "Request body failed validation. "
                "Inspect the ``errors`` object for field-level details."
            ),
        ),
        401: OpenApiResponse(
            response=LoginErrorResponseSerializer,
            description=(
                "Authentication failed. "
                "The email or password is incorrect."
            ),
        ),
        403: OpenApiResponse(
            response=LoginErrorResponseSerializer,
            description=(
                "Access denied. "
                "The account email is unverified, the account is inactive, "
                "or the account is locked."
            ),
        ),
        500: OpenApiResponse(
            response=LoginErrorResponseSerializer,
            description="Unexpected internal server error.",
        ),
    },

    # ── Examples ──────────────────────────────────────────────────────────────
    examples=[
        LOGIN_REQUEST_EXAMPLE,
        LOGIN_SUCCESS_EXAMPLE,
        LOGIN_VALIDATION_ERROR_EXAMPLE,
        LOGIN_INVALID_CREDENTIALS_EXAMPLE,
        LOGIN_EMAIL_NOT_VERIFIED_EXAMPLE,
        LOGIN_ACCOUNT_LOCKED_EXAMPLE,
        LOGIN_ACCOUNT_INACTIVE_EXAMPLE,
        LOGIN_SERVER_ERROR_EXAMPLE,
    ],
)


# ==============================================================================
# REFRESH Schema
# ==============================================================================


refresh_token_schema = extend_schema(
    summary="Refresh JWT access token",
    description=(
        "Accepts a valid refresh token and returns a newly generated "
        "JWT access token.\n\n"
        "The refresh token itself is not replaced by this endpoint. "
        "Use this endpoint whenever the access token expires."
    ),
    tags=["Authentication"],
    # ── Request ──────────────────────────────────────────────────────────────
    request=RefreshTokenRequestSerializer,
    # ── Response ──────────────────────────────────────────────────────────────
    responses={
        200: OpenApiResponse(
            response=RefreshTokenSuccessResponseSerializer,
            description="Access token refreshed successfully.",
        ),
        401: OpenApiResponse(
            response=RefreshTokenErrorResponseSerializer,
            description="Refresh token is invalid or expired.",
        ),
    },
 # ── Examples ──────────────────────────────────────────────────────────────
    examples=[
        REFRESH_TOKEN_REQUEST_EXAMPLE,
        REFRESH_TOKEN_SUCCESS_EXAMPLE,
        REFRESH_TOKEN_INVALID_EXAMPLE,
    ],
)

# ==============================================================================
# Logout Schema
# ==============================================================================



logout_schema = extend_schema(
    summary="Logout the authenticated user",
    description=(
        "Invalidates the supplied JWT refresh token by adding it to the "
        "Simple JWT blacklist.\n\n"
        "After logout, the same refresh token cannot be used again to "
        "obtain new access tokens.\n\n"
        "Clients should delete any locally stored access and refresh tokens "
        "after a successful logout."
    ),
    tags=["Authentication"],
    request=LogoutRequestSerializer,
    responses={
        200: OpenApiResponse(
            response=LogoutSuccessResponseSerializer,
            description="Logout successful.",
        ),
        401: OpenApiResponse(
            response=LogoutErrorResponseSerializer,
            description="Refresh token is invalid or expired.",
        ),
    },
    examples=[
        LOGOUT_REQUEST_EXAMPLE,
        LOGOUT_SUCCESS_EXAMPLE,
        LOGOUT_INVALID_TOKEN_EXAMPLE,
    ],
)



# ==============================================================================
# verify_email Schema
# ==============================================================================



verify_email_schema = extend_schema(
    summary="Verify email address",
    description=(
        "Verifies a user's email address using the verification token "
        "sent during registration."
    ),
    tags=["Authentication"],

    parameters=[
        OpenApiParameter(
            name="token",
            type=str,
            location=OpenApiParameter.QUERY,
            required=True,
            description="Email verification token.",
        ),
    ],

    responses={
        200: OpenApiResponse(
            description="Email verified successfully.",
        ),
        400: OpenApiResponse(
            description="Verification token is missing, invalid or expired.",
        ),
    },
)


# ==============================================================================
# Resend Schema
# ==============================================================================


resend_verification_schema = extend_schema(
    summary="Resend verification email",
    description="Generate and send a new email verification link.",
    tags=["Authentication"],
    request=ResendVerificationRequestSerializer,
    responses={
        200: OpenApiResponse(
            response=ResendVerificationSuccessResponseSerializer,
            description="Verification email sent.",
        ),
        400: OpenApiResponse(
            response=ResendVerificationErrorResponseSerializer,
            description="Validation error.",
        ),
    },
    examples=[
        RESEND_VERIFICATION_REQUEST_EXAMPLE,
        RESEND_VERIFICATION_SUCCESS_EXAMPLE,
    ],
)


# ==============================================================================
# Import new examples and serializers needed for the three new schemas
# ==============================================================================

from apps.authentication.api.docs.examples import (
    FORGOT_PASSWORD_REQUEST_EXAMPLE,
    FORGOT_PASSWORD_SUCCESS_EXAMPLE,
    FORGOT_PASSWORD_VALIDATION_ERROR_EXAMPLE,
    FORGOT_PASSWORD_SERVER_ERROR_EXAMPLE,
    RESET_PASSWORD_REQUEST_EXAMPLE,
    RESET_PASSWORD_SUCCESS_EXAMPLE,
    RESET_PASSWORD_INVALID_TOKEN_EXAMPLE,
    RESET_PASSWORD_MISMATCH_EXAMPLE,
    RESET_PASSWORD_WEAK_PASSWORD_EXAMPLE,
    RESET_PASSWORD_VALIDATION_ERROR_EXAMPLE,
    RESET_PASSWORD_SERVER_ERROR_EXAMPLE,
    CHANGE_PASSWORD_REQUEST_EXAMPLE,
    CHANGE_PASSWORD_SUCCESS_EXAMPLE,
    CHANGE_PASSWORD_WRONG_CURRENT_EXAMPLE,
    CHANGE_PASSWORD_MISMATCH_EXAMPLE,
    CHANGE_PASSWORD_WEAK_PASSWORD_EXAMPLE,
    CHANGE_PASSWORD_VALIDATION_ERROR_EXAMPLE,
    CHANGE_PASSWORD_UNAUTHENTICATED_EXAMPLE,
    CHANGE_PASSWORD_SERVER_ERROR_EXAMPLE,
)
from apps.authentication.api.docs.serializers import (
    ForgotPasswordRequestSerializer,
    ForgotPasswordSuccessResponseSerializer,
    ForgotPasswordErrorResponseSerializer,
    ResetPasswordRequestSerializer,
    ResetPasswordSuccessResponseSerializer,
    ResetPasswordErrorResponseSerializer,
    ChangePasswordRequestSerializer,
    ChangePasswordSuccessResponseSerializer,
    ChangePasswordErrorResponseSerializer,
)

# ==============================================================================
# Forgot Password Schema
# ==============================================================================

forgot_password_schema = extend_schema(
    summary="Request a password reset link",
    description=(
        "Accepts an email address and dispatches a password reset link "
        "if an active account is found.\n\n"
        "### Account Enumeration Prevention\n\n"
        "The same generic success response is returned regardless of whether "
        "the email address exists in the system. This prevents attackers from "
        "determining which email addresses are registered.\n\n"
        "### Reset Link\n\n"
        "The emailed link contains a **signed token** that expires after "
        "**30 minutes**. Pass this token to "
        "`POST /api/v1/auth/reset-password/` to set a new password.\n\n"
        "### Security Notes\n\n"
        "- Only active, non-locked accounts receive the reset email.\n"
        "- Token is signed with Django's ``TimestampSigner`` — tamper-proof.\n"
        "- This endpoint does not require authentication."
    ),
    tags=["Password Management"],

    # ── Request ────────────────────────────────────────────────────────────────
    request=ForgotPasswordRequestSerializer,

    # ── Responses ─────────────────────────────────────────────────────────────
    responses={
        200: OpenApiResponse(
            response=ForgotPasswordSuccessResponseSerializer,
            description=(
                "Request processed. If the email exists, a reset link has been sent."
            ),
        ),
        400: OpenApiResponse(
            response=ForgotPasswordErrorResponseSerializer,
            description="Request body failed field-level validation.",
        ),
        500: OpenApiResponse(
            response=ForgotPasswordErrorResponseSerializer,
            description="Unexpected internal server error.",
        ),
    },

    # ── Examples ──────────────────────────────────────────────────────────────
    examples=[
        FORGOT_PASSWORD_REQUEST_EXAMPLE,
        FORGOT_PASSWORD_SUCCESS_EXAMPLE,
        FORGOT_PASSWORD_VALIDATION_ERROR_EXAMPLE,
        FORGOT_PASSWORD_SERVER_ERROR_EXAMPLE,
    ],
)


# ==============================================================================
# Reset Password Schema
# ==============================================================================

reset_password_schema = extend_schema(
    summary="Reset password using a signed token",
    description=(
        "Consumes the signed token from the password reset email and sets "
        "a new password for the associated account.\n\n"
        "### Token Validity\n\n"
        "- Tokens expire after **30 minutes**.\n"
        "- Tokens are cryptographically signed — any tampering renders them invalid.\n\n"
        "### Password Policy\n\n"
        "The new password must satisfy all enterprise policy requirements:\n\n"
        "- Minimum length: **12 characters**\n"
        "- At least one **uppercase** letter (A–Z)\n"
        "- At least one **lowercase** letter (a–z)\n"
        "- At least one **digit** (0–9)\n"
        "- At least one **special character** (!@#$%^&* etc.)\n"
        "- Must not be the same as the current password\n"
        "- Must not be a commonly used password\n\n"
        "### Security Notes\n\n"
        "- The ``password_changed_at`` timestamp is updated on success.\n"
        "- This endpoint does not require authentication."
    ),
    tags=["Password Management"],

    # ── Request ────────────────────────────────────────────────────────────────
    request=ResetPasswordRequestSerializer,

    # ── Responses ─────────────────────────────────────────────────────────────
    responses={
        200: OpenApiResponse(
            response=ResetPasswordSuccessResponseSerializer,
            description="Password reset successfully.",
        ),
        400: OpenApiResponse(
            response=ResetPasswordErrorResponseSerializer,
            description=(
                "Token is invalid or expired, passwords do not match, "
                "or the new password fails policy checks."
            ),
        ),
        500: OpenApiResponse(
            response=ResetPasswordErrorResponseSerializer,
            description="Unexpected internal server error.",
        ),
    },

    # ── Examples ──────────────────────────────────────────────────────────────
    examples=[
        RESET_PASSWORD_REQUEST_EXAMPLE,
        RESET_PASSWORD_SUCCESS_EXAMPLE,
        RESET_PASSWORD_INVALID_TOKEN_EXAMPLE,
        RESET_PASSWORD_MISMATCH_EXAMPLE,
        RESET_PASSWORD_WEAK_PASSWORD_EXAMPLE,
        RESET_PASSWORD_VALIDATION_ERROR_EXAMPLE,
        RESET_PASSWORD_SERVER_ERROR_EXAMPLE,
    ],
)


# ==============================================================================
# Change Password Schema
# ==============================================================================

change_password_schema = extend_schema(
    summary="Change password (authenticated users only)",
    description=(
        "Allows an authenticated user to change their own password by "
        "providing the current password and a new password.\n\n"
        "### Authentication\n\n"
        "A valid **JWT Bearer token** must be supplied in the "
        "`Authorization` header:\n\n"
        "```\nAuthorization: Bearer <access_token>\n```\n\n"
        "### Password Policy\n\n"
        "The new password must satisfy all enterprise policy requirements:\n\n"
        "- Minimum length: **12 characters**\n"
        "- At least one **uppercase** letter (A–Z)\n"
        "- At least one **lowercase** letter (a–z)\n"
        "- At least one **digit** (0–9)\n"
        "- At least one **special character** (!@#$%^&* etc.)\n"
        "- Must not be the same as the current password\n"
        "- Must not be a commonly used password\n\n"
        "### Security Notes\n\n"
        "- The ``password_changed_at`` timestamp is updated on success.\n"
        "- A generic error is returned for an incorrect current password "
        "to prevent timing-based enumeration."
    ),
    tags=["Password Management"],

    # ── Request ────────────────────────────────────────────────────────────────
    request=ChangePasswordRequestSerializer,

    # ── Responses ─────────────────────────────────────────────────────────────
    responses={
        200: OpenApiResponse(
            response=ChangePasswordSuccessResponseSerializer,
            description="Password changed successfully.",
        ),
        400: OpenApiResponse(
            response=ChangePasswordErrorResponseSerializer,
            description=(
                "Passwords do not match or the new password fails policy checks."
            ),
        ),
        401: OpenApiResponse(
            response=ChangePasswordErrorResponseSerializer,
            description=(
                "No valid JWT token provided, or the current password is incorrect."
            ),
        ),
        500: OpenApiResponse(
            response=ChangePasswordErrorResponseSerializer,
            description="Unexpected internal server error.",
        ),
    },

    # ── Examples ──────────────────────────────────────────────────────────────
    examples=[
        CHANGE_PASSWORD_REQUEST_EXAMPLE,
        CHANGE_PASSWORD_SUCCESS_EXAMPLE,
        CHANGE_PASSWORD_WRONG_CURRENT_EXAMPLE,
        CHANGE_PASSWORD_MISMATCH_EXAMPLE,
        CHANGE_PASSWORD_WEAK_PASSWORD_EXAMPLE,
        CHANGE_PASSWORD_VALIDATION_ERROR_EXAMPLE,
        CHANGE_PASSWORD_UNAUTHENTICATED_EXAMPLE,
        CHANGE_PASSWORD_SERVER_ERROR_EXAMPLE,
    ],
)

"""
``@extend_schema`` decorator factories for the SecureAuthX authentication views.

Keeping schema definitions in a dedicated module separates documentation
concerns from view logic. Views import and apply these decorators directly.

Exported names consumed by views.py
------------------------------------
registration_schema, login_schema, refresh_token_schema, logout_schema,
verify_email_schema, resend_verification_schema, me_schema,
forgot_password_schema, reset_password_schema, change_password_schema,
extend_schema   ← re-exported so views only need one import source
"""

from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema

from apps.authentication.api.docs.examples import (
    # Registration
    REGISTRATION_DUPLICATE_EMAIL_EXAMPLE,
    REGISTRATION_MINIMAL_REQUEST_EXAMPLE,
    REGISTRATION_REQUEST_EXAMPLE,
    REGISTRATION_SERVER_ERROR_EXAMPLE,
    REGISTRATION_SUCCESS_EXAMPLE,
    REGISTRATION_VALIDATION_ERROR_EXAMPLE,
    REGISTRATION_WEAK_PASSWORD_EXAMPLE,
    # Login
    LOGIN_ACCOUNT_INACTIVE_EXAMPLE,
    LOGIN_ACCOUNT_LOCKED_EXAMPLE,
    LOGIN_EMAIL_NOT_VERIFIED_EXAMPLE,
    LOGIN_INVALID_CREDENTIALS_EXAMPLE,
    LOGIN_REQUEST_EXAMPLE,
    LOGIN_SERVER_ERROR_EXAMPLE,
    LOGIN_SUCCESS_EXAMPLE,
    LOGIN_VALIDATION_ERROR_EXAMPLE,
    # Token refresh
    REFRESH_TOKEN_INVALID_EXAMPLE,
    REFRESH_TOKEN_REQUEST_EXAMPLE,
    REFRESH_TOKEN_SUCCESS_EXAMPLE,
    # Logout
    LOGOUT_INVALID_TOKEN_EXAMPLE,
    LOGOUT_REQUEST_EXAMPLE,
    LOGOUT_SUCCESS_EXAMPLE,
    # Email verification
    VERIFY_EMAIL_SUCCESS_EXAMPLE,
    VERIFY_EMAIL_MISSING_TOKEN_EXAMPLE,
    VERIFY_EMAIL_INVALID_TOKEN_EXAMPLE,
    # Resend verification
    RESEND_VERIFICATION_REQUEST_EXAMPLE,
    RESEND_VERIFICATION_SUCCESS_EXAMPLE,
    RESEND_VERIFICATION_VALIDATION_ERROR_EXAMPLE,
    # Me (profile)
    ME_SUCCESS_EXAMPLE,
    ME_UNAUTHENTICATED_EXAMPLE,
    # Forgot password
    FORGOT_PASSWORD_REQUEST_EXAMPLE,
    FORGOT_PASSWORD_SERVER_ERROR_EXAMPLE,
    FORGOT_PASSWORD_SUCCESS_EXAMPLE,
    FORGOT_PASSWORD_VALIDATION_ERROR_EXAMPLE,
    # Reset password
    RESET_PASSWORD_INVALID_TOKEN_EXAMPLE,
    RESET_PASSWORD_MISMATCH_EXAMPLE,
    RESET_PASSWORD_REQUEST_EXAMPLE,
    RESET_PASSWORD_SERVER_ERROR_EXAMPLE,
    RESET_PASSWORD_SUCCESS_EXAMPLE,
    RESET_PASSWORD_VALIDATION_ERROR_EXAMPLE,
    RESET_PASSWORD_WEAK_PASSWORD_EXAMPLE,
    # Change password
    CHANGE_PASSWORD_MISMATCH_EXAMPLE,
    CHANGE_PASSWORD_REQUEST_EXAMPLE,
    CHANGE_PASSWORD_SERVER_ERROR_EXAMPLE,
    CHANGE_PASSWORD_SUCCESS_EXAMPLE,
    CHANGE_PASSWORD_UNAUTHENTICATED_EXAMPLE,
    CHANGE_PASSWORD_VALIDATION_ERROR_EXAMPLE,
    CHANGE_PASSWORD_WEAK_PASSWORD_EXAMPLE,
    CHANGE_PASSWORD_WRONG_CURRENT_EXAMPLE,
)
from apps.authentication.api.docs.serializers import (
    # Registration
    RegistrationErrorResponseSerializer,
    RegistrationSuccessResponseSerializer,
    # Login
    LoginErrorResponseSerializer,
    LoginSuccessResponseSerializer,
    # Token refresh
    RefreshTokenErrorResponseSerializer,
    RefreshTokenRequestSerializer,
    RefreshTokenSuccessResponseSerializer,
    # Logout
    LogoutErrorResponseSerializer,
    LogoutRequestSerializer,
    LogoutSuccessResponseSerializer,
    # Email verification
    VerifyEmailErrorResponseSerializer,
    VerifyEmailSuccessResponseSerializer,
    # Resend verification
    ResendVerificationErrorResponseSerializer,
    ResendVerificationRequestSerializer,
    ResendVerificationSuccessResponseSerializer,
    # Me (profile)
    MeErrorResponseSerializer,
    MeSuccessResponseSerializer,
    # Forgot password
    ForgotPasswordErrorResponseSerializer,
    ForgotPasswordRequestSerializer,
    ForgotPasswordSuccessResponseSerializer,
    # Reset password
    ResetPasswordErrorResponseSerializer,
    ResetPasswordRequestSerializer,
    ResetPasswordSuccessResponseSerializer,
    # Change password
    ChangePasswordErrorResponseSerializer,
    ChangePasswordRequestSerializer,
    ChangePasswordSuccessResponseSerializer,
)
from apps.authentication.api.serializers import (
    LoginSerializer,
    RegistrationSerializer,
)

# ==============================================================================
# Registration
# ==============================================================================

registration_schema = extend_schema(
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
    request=RegistrationSerializer,
    responses={
        201: OpenApiResponse(
            response=RegistrationSuccessResponseSerializer,
            description="Account created. Verification email dispatched.",
        ),
        400: OpenApiResponse(
            response=RegistrationErrorResponseSerializer,
            description="Request validation failed.",
        ),
        409: OpenApiResponse(
            response=RegistrationErrorResponseSerializer,
            description="An account with this email already exists.",
        ),
        500: OpenApiResponse(
            response=RegistrationErrorResponseSerializer,
            description="Unexpected internal server error.",
        ),
    },
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
# Login
# ==============================================================================

login_schema = extend_schema(
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
        "### Account Lockout Policy\n\n"
        "After **5 consecutive failed login attempts** the account is automatically "
        "locked for **30 minutes**. While locked, even a correct password will be "
        "rejected with a 403. The lock lifts automatically — no manual intervention "
        "is needed. The failed-attempt counter resets to zero on a successful login.\n\n"
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
    request=LoginSerializer,
    responses={
        200: OpenApiResponse(
            response=LoginSuccessResponseSerializer,
            description="Authentication successful. JWT tokens issued.",
        ),
        400: OpenApiResponse(
            response=LoginErrorResponseSerializer,
            description="Request body failed validation.",
        ),
        401: OpenApiResponse(
            response=LoginErrorResponseSerializer,
            description="Invalid email or password.",
        ),
        403: OpenApiResponse(
            response=LoginErrorResponseSerializer,
            description=(
                "Access denied — email unverified, account inactive, or account locked."
            ),
        ),
        500: OpenApiResponse(
            response=LoginErrorResponseSerializer,
            description="Unexpected internal server error.",
        ),
    },
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
# Me (Profile)
# ==============================================================================

me_schema = extend_schema(
    summary="Retrieve the authenticated user's profile",
    description=(
        "Returns the profile information for the currently authenticated user.\n\n"
        "### Authentication\n\n"
        "A valid **JWT Bearer token** must be supplied in the "
        "`Authorization` header:\n\n"
        "```\nAuthorization: Bearer <access_token>\n```"
    ),
    tags=["Authentication"],
    request=None,
    responses={
        200: OpenApiResponse(
            response=MeSuccessResponseSerializer,
            description="Profile retrieved successfully.",
        ),
        401: OpenApiResponse(
            response=MeErrorResponseSerializer,
            description="No valid JWT token provided.",
        ),
    },
    examples=[
        ME_SUCCESS_EXAMPLE,
        ME_UNAUTHENTICATED_EXAMPLE,
    ],
)

# ==============================================================================
# Token Refresh
# ==============================================================================

refresh_token_schema = extend_schema(
    summary="Refresh JWT access token",
    description=(
        "Accepts a valid refresh token and returns a newly issued "
        "JWT access token.\n\n"
        "### Token Rotation\n\n"
        "Refresh tokens are **rotated on every use** "
        "(`ROTATE_REFRESH_TOKENS = True`). The old refresh token is "
        "immediately blacklisted. Always store the new refresh token "
        "returned by `POST /api/v1/auth/login/` or this endpoint.\n\n"
        "Use this endpoint whenever the access token expires (15-minute lifetime)."
    ),
    tags=["Authentication"],
    request=RefreshTokenRequestSerializer,
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
    examples=[
        REFRESH_TOKEN_REQUEST_EXAMPLE,
        REFRESH_TOKEN_SUCCESS_EXAMPLE,
        REFRESH_TOKEN_INVALID_EXAMPLE,
    ],
)

# ==============================================================================
# Logout
# ==============================================================================

logout_schema = extend_schema(
    summary="Logout — blacklist the refresh token",
    description=(
        "Invalidates the supplied JWT refresh token by adding it to the "
        "Simple JWT blacklist.\n\n"
        "After logout the same refresh token cannot be used to obtain new "
        "access tokens. Clients should also discard any locally stored "
        "access token after calling this endpoint."
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
            description="Refresh token is invalid or already blacklisted.",
        ),
    },
    examples=[
        LOGOUT_REQUEST_EXAMPLE,
        LOGOUT_SUCCESS_EXAMPLE,
        LOGOUT_INVALID_TOKEN_EXAMPLE,
    ],
)

# ==============================================================================
# Verify Email
# ==============================================================================

verify_email_schema = extend_schema(
    summary="Verify email address",
    description=(
        "Verifies a user's email address using the signed verification token "
        "dispatched during registration.\n\n"
        "### Flow\n\n"
        "1. User registers → verification email is sent.\n"
        "2. User clicks the link → frontend extracts the `token` query parameter.\n"
        "3. Frontend calls `GET /api/v1/auth/verify-email/?token=<token>`.\n"
        "4. On success the account is activated and the user can log in.\n\n"
        "### Token Details\n\n"
        "- Signed with Django's `TimestampSigner` — tamper-proof.\n"
        "- Expires after **24 hours**.\n"
        "- This endpoint does not require authentication."
    ),
    tags=["Authentication"],
    parameters=[
        OpenApiParameter(
            name="token",
            type=str,
            location=OpenApiParameter.QUERY,
            required=True,
            description=(
                "Signed email verification token received in the registration email."
            ),
        ),
    ],
    responses={
        200: OpenApiResponse(
            response=VerifyEmailSuccessResponseSerializer,
            description="Email verified successfully. Account is now active.",
        ),
        400: OpenApiResponse(
            response=VerifyEmailErrorResponseSerializer,
            description="Token is missing, invalid, or expired.",
        ),
    },
    examples=[
        VERIFY_EMAIL_SUCCESS_EXAMPLE,
        VERIFY_EMAIL_MISSING_TOKEN_EXAMPLE,
        VERIFY_EMAIL_INVALID_TOKEN_EXAMPLE,
    ],
)

# ==============================================================================
# Resend Verification
# ==============================================================================

resend_verification_schema = extend_schema(
    summary="Resend email verification link",
    description=(
        "Generates and sends a new email verification link for an unverified account.\n\n"
        "### Account Enumeration Prevention\n\n"
        "The same generic success response is always returned regardless of "
        "whether the email is registered or already verified — preventing "
        "attackers from enumerating valid addresses.\n\n"
        "- This endpoint does not require authentication."
    ),
    tags=["Authentication"],
    request=ResendVerificationRequestSerializer,
    responses={
        200: OpenApiResponse(
            response=ResendVerificationSuccessResponseSerializer,
            description="Request processed. Verification email sent if eligible.",
        ),
        400: OpenApiResponse(
            response=ResendVerificationErrorResponseSerializer,
            description="Request body failed field-level validation.",
        ),
    },
    examples=[
        RESEND_VERIFICATION_REQUEST_EXAMPLE,
        RESEND_VERIFICATION_SUCCESS_EXAMPLE,
        RESEND_VERIFICATION_VALIDATION_ERROR_EXAMPLE,
    ],
)

# ==============================================================================
# Forgot Password
# ==============================================================================

forgot_password_schema = extend_schema(
    summary="Request a password reset link",
    description=(
        "Accepts an email address and dispatches a password reset link "
        "if an active, non-locked account is found.\n\n"
        "### Account Enumeration Prevention\n\n"
        "The same generic success response is returned regardless of whether "
        "the email exists — preventing attackers from enumerating accounts.\n\n"
        "### Reset Link\n\n"
        "The emailed link embeds a **signed token** that expires after "
        "**30 minutes**. Pass this token to "
        "`POST /api/v1/auth/reset-password/` to set a new password.\n\n"
        "### Security Notes\n\n"
        "- Only active, non-locked accounts receive the reset email.\n"
        "- Token is signed with Django's `TimestampSigner` — tamper-proof.\n"
        "- This endpoint does not require authentication."
    ),
    tags=["Password Management"],
    request=ForgotPasswordRequestSerializer,
    responses={
        200: OpenApiResponse(
            response=ForgotPasswordSuccessResponseSerializer,
            description="Request processed. Reset link sent if account exists.",
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
    examples=[
        FORGOT_PASSWORD_REQUEST_EXAMPLE,
        FORGOT_PASSWORD_SUCCESS_EXAMPLE,
        FORGOT_PASSWORD_VALIDATION_ERROR_EXAMPLE,
        FORGOT_PASSWORD_SERVER_ERROR_EXAMPLE,
    ],
)

# ==============================================================================
# Reset Password
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
        "- `password_changed_at` timestamp is updated on success.\n"
        "- This endpoint does not require authentication."
    ),
    tags=["Password Management"],
    request=ResetPasswordRequestSerializer,
    responses={
        200: OpenApiResponse(
            response=ResetPasswordSuccessResponseSerializer,
            description="Password reset successfully.",
        ),
        400: OpenApiResponse(
            response=ResetPasswordErrorResponseSerializer,
            description=(
                "Token invalid/expired, passwords do not match, "
                "or new password fails policy checks."
            ),
        ),
        500: OpenApiResponse(
            response=ResetPasswordErrorResponseSerializer,
            description="Unexpected internal server error.",
        ),
    },
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
# Change Password
# ==============================================================================

change_password_schema = extend_schema(
    summary="Change password (authenticated users only)",
    description=(
        "Allows an authenticated user to change their own password.\n\n"
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
        "- `password_changed_at` timestamp is updated on success.\n"
        "- A generic error is returned for an incorrect current password "
        "to prevent timing-based enumeration."
    ),
    tags=["Password Management"],
    request=ChangePasswordRequestSerializer,
    responses={
        200: OpenApiResponse(
            response=ChangePasswordSuccessResponseSerializer,
            description="Password changed successfully.",
        ),
        400: OpenApiResponse(
            response=ChangePasswordErrorResponseSerializer,
            description="Passwords do not match or new password fails policy checks.",
        ),
        401: OpenApiResponse(
            response=ChangePasswordErrorResponseSerializer,
            description="No valid JWT token provided, or current password is incorrect.",
        ),
        500: OpenApiResponse(
            response=ChangePasswordErrorResponseSerializer,
            description="Unexpected internal server error.",
        ),
    },
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

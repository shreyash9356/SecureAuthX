"""
OpenAPI request and response examples for the SecureAuthX authentication module.

All examples are imported by the ``@extend_schema`` decorators in views.py.
Keeping examples in a dedicated module avoids cluttering view code and makes
them easy to update without touching business logic.
"""

from drf_spectacular.utils import OpenApiExample

# ==============================================================================
# Registration Examples
# ==============================================================================

REGISTRATION_REQUEST_EXAMPLE = OpenApiExample(
    name="Registration Request",
    summary="Standard registration with all fields",
    description=(
        "A complete registration payload including optional profile fields. "
        "``email`` and ``password`` are the only required fields. "
        "Passwords must be at least 12 characters and meet the enterprise "
        "password policy (uppercase, lowercase, digit, special character)."
    ),
    value={
        "email": "john.doe@example.com",
        "username": "johndoe",
        "first_name": "John",
        "last_name": "Doe",
        "password": "Str0ng!Passw0rd#2025",
        "confirm_password": "Str0ng!Passw0rd#2025",
    },
    request_only=True,
)

REGISTRATION_MINIMAL_REQUEST_EXAMPLE = OpenApiExample(
    name="Minimal Registration Request",
    summary="Registration with required fields only",
    description=(
        "A minimal registration payload. "
        "``username``, ``first_name``, and ``last_name`` are optional."
    ),
    value={
        "email": "jane.doe@example.com",
        "password": "Str0ng!Passw0rd#2025",
        "confirm_password": "Str0ng!Passw0rd#2025",
    },
    request_only=True,
)

REGISTRATION_SUCCESS_EXAMPLE = OpenApiExample(
    name="Registration Successful",
    summary="Account created — email verification required",
    description=(
        "Returned when the account is created successfully. "
        "The user must verify their email address before they can log in."
    ),
    value={
        "success": True,
        "message": "Registration successful. Please verify your email.",
        "data": {
            "user_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "email": "john.doe@example.com",
        },
    },
    response_only=True,
    status_codes=["201"],
)

REGISTRATION_VALIDATION_ERROR_EXAMPLE = OpenApiExample(
    name="Validation Error",
    summary="Request body failed validation",
    description=(
        "Returned when one or more fields fail serializer validation, "
        "for example when passwords do not match or the email format is invalid."
    ),
    value={
        "success": False,
        "message": "Request validation failed.",
        "errors": {
            "confirm_password": ["Passwords do not match."],
            "email": ["Enter a valid email address."],
        },
    },
    response_only=True,
    status_codes=["400"],
)

REGISTRATION_WEAK_PASSWORD_EXAMPLE = OpenApiExample(
    name="Weak Password",
    summary="Password does not meet the enterprise password policy",
    description=(
        "Returned when the supplied password fails the enterprise password policy. "
        "Passwords must be at least 12 characters and include uppercase letters, "
        "lowercase letters, digits, and special characters."
    ),
    value={
        "success": False,
        "message": "Password does not meet security requirements.",
        "errors": {},
    },
    response_only=True,
    status_codes=["400"],
)

REGISTRATION_DUPLICATE_EMAIL_EXAMPLE = OpenApiExample(
    name="Duplicate Email",
    summary="An account with this email already exists",
    description=(
        "Returned when a registration request uses an email address "
        "that is already associated with an existing account. "
        "For security, no information about the existing account is disclosed."
    ),
    value={
        "success": False,
        "message": "An account with this email already exists.",
        "errors": {},
    },
    response_only=True,
    status_codes=["409"],
)

REGISTRATION_SERVER_ERROR_EXAMPLE = OpenApiExample(
    name="Internal Server Error",
    summary="Unexpected server-side failure",
    description=(
        "Returned when an unexpected error occurs during registration. "
        "Details are not exposed in production environments."
    ),
    value={
        "success": False,
        "message": "Internal server error.",
        "errors": {},
    },
    response_only=True,
    status_codes=["500"],
)

# ==============================================================================
# Login Examples
# ==============================================================================

LOGIN_REQUEST_EXAMPLE = OpenApiExample(
    name="Login Request",
    summary="Authenticate with email and password",
    description=(
        "Submit valid credentials to receive a JWT access token and "
        "refresh token. The email address is case-insensitive."
    ),
    value={
        "email": "john.doe@example.com",
        "password": "Str0ng!Passw0rd#2025",
    },
    request_only=True,
)

LOGIN_SUCCESS_EXAMPLE = OpenApiExample(
    name="Login Successful",
    summary="Authentication succeeded — JWT tokens issued",
    description=(
        "Returned when credentials are valid, the email is verified, "
        "and the account is active and unlocked. "
        "Store the ``access`` token securely (memory only, not localStorage). "
        "Store the ``refresh`` token in an HttpOnly cookie."
    ),
    value={
        "success": True,
        "message": "Login successful.",
        "data": {
            "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJ1c2VyX2lkIjoiYTFiMmMzZDQtZTVmNi03ODkwLWFiY2QtZWYxMjM0NTY3ODkwIiwiZXhwIjoxNzUyMDAwMDAwfQ"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJ1c2VyX2lkIjoiYTFiMmMzZDQtZTVmNi03ODkwLWFiY2QtZWYxMjM0NTY3ODkwIiwidG9rZW5fdHlwZSI6InJlZnJlc2gifQ"
            ".dGVzdC1yZWZyZXNoLXRva2Vu",
            "user": {
                "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "email": "john.doe@example.com",
                "first_name": "John",
                "last_name": "Doe",
            },
        },
    },
    response_only=True,
    status_codes=["200"],
)

LOGIN_INVALID_CREDENTIALS_EXAMPLE = OpenApiExample(
    name="Invalid Credentials",
    summary="Email or password is incorrect",
    description=(
        "Returned when the email and password combination does not match "
        "any account. A deliberately generic message is used to prevent "
        "user enumeration attacks."
    ),
    value={
        "success": False,
        "message": "Invalid email or password.",
        "errors": {},
    },
    response_only=True,
    status_codes=["401"],
)

LOGIN_EMAIL_NOT_VERIFIED_EXAMPLE = OpenApiExample(
    name="Email Not Verified",
    summary="Account email address has not been verified",
    description=(
        "Returned when the credentials are valid but the user has not "
        "yet verified their email address. "
        "Direct the user to check their inbox or request a new verification email."
    ),
    value={
        "success": False,
        "message": "Your email address has not been verified.",
        "errors": {},
    },
    response_only=True,
    status_codes=["403"],
)

LOGIN_ACCOUNT_LOCKED_EXAMPLE = OpenApiExample(
    name="Account Locked",
    summary="Account has been locked due to excessive failed attempts",
    description=(
        "Returned when the account is locked after exceeding the maximum "
        "number of consecutive failed login attempts. "
        "The user must contact support to unlock their account."
    ),
    value={
        "success": False,
        "message": "Your account has been locked.",
        "errors": {},
    },
    response_only=True,
    status_codes=["403"],
)

LOGIN_ACCOUNT_INACTIVE_EXAMPLE = OpenApiExample(
    name="Account Inactive",
    summary="Account has been deactivated",
    description=(
        "Returned when the account exists but has been deactivated "
        "by an administrator."
    ),
    value={
        "success": False,
        "message": "Your account is inactive. Please contact support.",
        "errors": {},
    },
    response_only=True,
    status_codes=["403"],
)

LOGIN_VALIDATION_ERROR_EXAMPLE = OpenApiExample(
    name="Validation Error",
    summary="Request body failed validation",
    description=(
        "Returned when the request body is malformed, "
        "for example a missing required field or an invalid email format."
    ),
    value={
        "success": False,
        "message": "Request validation failed.",
        "errors": {
            "email": ["This field is required."],
            "password": ["This field is required."],
        },
    },
    response_only=True,
    status_codes=["400"],
)

LOGIN_SERVER_ERROR_EXAMPLE = OpenApiExample(
    name="Internal Server Error",
    summary="Unexpected server-side failure",
    description=(
        "Returned when an unexpected error occurs during authentication. "
        "Details are not exposed in production environments."
    ),
    value={
        "success": False,
        "message": "Internal server error.",
        "errors": {},
    },
    response_only=True,
    status_codes=["500"],
)


# ==============================================================================
# REFRESH Examples
# ==============================================================================


REFRESH_TOKEN_REQUEST_EXAMPLE = OpenApiExample(
    "Refresh access token",
    value={"refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."},
    request_only=True,
)

REFRESH_TOKEN_SUCCESS_EXAMPLE = OpenApiExample(
    "Success",
    value={
        "success": True,
        "message": "Access token refreshed successfully.",
        "data": {"access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."},
    },
    response_only=True,
    status_codes=["200"],
)

REFRESH_TOKEN_INVALID_EXAMPLE = OpenApiExample(
    "Invalid refresh token",
    value={
        "success": False,
        "message": "Refresh token is invalid or expired.",
        "errors": {},
    },
    response_only=True,
    status_codes=["401"],
)

# ==============================================================================
# Logout Examples
# ==============================================================================


LOGOUT_REQUEST_EXAMPLE = OpenApiExample(
    "Logout request",
    value={"refresh": "eyJhbGciOiJIUzI1NiIs..."},
    request_only=True,
)

LOGOUT_SUCCESS_EXAMPLE = OpenApiExample(
    "Logout successful",
    value={"success": True, "message": "Logout successful.", "data": {}},
    response_only=True,
    status_codes=["200"],
)

LOGOUT_INVALID_TOKEN_EXAMPLE = OpenApiExample(
    "Invalid refresh token",
    value={
        "success": False,
        "message": "Refresh token is invalid or expired.",
        "errors": {},
    },
    response_only=True,
    status_codes=["401"],
)

# ==============================================================================
# Resend Examples
# ==============================================================================


RESEND_VERIFICATION_REQUEST_EXAMPLE = OpenApiExample(
    "Resend verification email",
    value={"email": "john@example.com"},
    request_only=True,
)

RESEND_VERIFICATION_SUCCESS_EXAMPLE = OpenApiExample(
    "Success",
    value={
        "success": True,
        "message": "If the email exists and is not verified, a verification email has been sent.",
        "data": {},
    },
    response_only=True,
    status_codes=["200"],
)


# ==============================================================================
# Forgot Password Examples
# ==============================================================================

FORGOT_PASSWORD_REQUEST_EXAMPLE = OpenApiExample(
    name="Forgot Password Request",
    summary="Submit email to receive a password reset link",
    description=(
        "Submit the email address associated with your account. "
        "A reset link will be sent if the account exists. "
        "The same generic response is returned whether or not the "
        "email is registered — this prevents account enumeration."
    ),
    value={
        "email": "john.doe@example.com",
    },
    request_only=True,
)

FORGOT_PASSWORD_SUCCESS_EXAMPLE = OpenApiExample(
    name="Forgot Password — Success",
    summary="Generic success — reset link dispatched (or silently skipped)",
    description=("Returned in all cases to prevent leaking whether the email exists."),
    value={
        "success": True,
        "message": "If an account exists, a password reset link has been sent.",
        "data": {},
    },
    response_only=True,
    status_codes=["200"],
)

FORGOT_PASSWORD_VALIDATION_ERROR_EXAMPLE = OpenApiExample(
    name="Forgot Password — Validation Error",
    summary="Invalid email format",
    description="Returned when the submitted email fails format validation.",
    value={
        "success": False,
        "message": "Request validation failed.",
        "errors": {
            "email": ["Enter a valid email address."],
        },
    },
    response_only=True,
    status_codes=["400"],
)

FORGOT_PASSWORD_SERVER_ERROR_EXAMPLE = OpenApiExample(
    name="Forgot Password — Internal Server Error",
    summary="Unexpected server-side failure",
    description="Details are not exposed in production environments.",
    value={
        "success": False,
        "message": "Internal server error.",
        "errors": {},
    },
    response_only=True,
    status_codes=["500"],
)


# ==============================================================================
# Reset Password Examples
# ==============================================================================

RESET_PASSWORD_REQUEST_EXAMPLE = OpenApiExample(
    name="Reset Password Request",
    summary="Submit token and new password",
    description=(
        "Submit the signed token received in the reset email together "
        "with the desired new password. The token expires after 30 minutes."
    ),
    value={
        "token": "john.doe%40example.com:1sXyZa:abc123...",
        "password": "NewStr0ng!Passw0rd#2025",
        "confirm_password": "NewStr0ng!Passw0rd#2025",
    },
    request_only=True,
)

RESET_PASSWORD_SUCCESS_EXAMPLE = OpenApiExample(
    name="Reset Password — Success",
    summary="Password reset successfully",
    description=(
        "Returned when the token is valid and the new password passes "
        "all policy checks."
    ),
    value={
        "success": True,
        "message": "Password reset successful.",
        "data": {},
    },
    response_only=True,
    status_codes=["200"],
)

RESET_PASSWORD_INVALID_TOKEN_EXAMPLE = OpenApiExample(
    name="Reset Password — Invalid or Expired Token",
    summary="Token is invalid, tampered with, or expired",
    description=(
        "Returned when the signed token cannot be verified or has "
        "exceeded the 30-minute validity window."
    ),
    value={
        "success": False,
        "message": "Password reset link is invalid or has expired.",
        "errors": {},
    },
    response_only=True,
    status_codes=["400"],
)

RESET_PASSWORD_MISMATCH_EXAMPLE = OpenApiExample(
    name="Reset Password — Password Mismatch",
    summary="New password and confirmation do not match",
    value={
        "success": False,
        "message": "Passwords do not match.",
        "errors": {},
    },
    response_only=True,
    status_codes=["400"],
)

RESET_PASSWORD_WEAK_PASSWORD_EXAMPLE = OpenApiExample(
    name="Reset Password — Weak Password",
    summary="New password does not satisfy the enterprise policy",
    value={
        "success": False,
        "message": "Password does not meet security requirements.",
        "errors": {},
    },
    response_only=True,
    status_codes=["400"],
)

RESET_PASSWORD_VALIDATION_ERROR_EXAMPLE = OpenApiExample(
    name="Reset Password — Validation Error",
    summary="Request body failed field-level validation",
    value={
        "success": False,
        "message": "Request validation failed.",
        "errors": {
            "token": ["This field is required."],
            "password": ["This field is required."],
        },
    },
    response_only=True,
    status_codes=["400"],
)

RESET_PASSWORD_SERVER_ERROR_EXAMPLE = OpenApiExample(
    name="Reset Password — Internal Server Error",
    summary="Unexpected server-side failure",
    value={
        "success": False,
        "message": "Internal server error.",
        "errors": {},
    },
    response_only=True,
    status_codes=["500"],
)


# ==============================================================================
# Change Password Examples
# ==============================================================================

CHANGE_PASSWORD_REQUEST_EXAMPLE = OpenApiExample(
    name="Change Password Request",
    summary="Submit current and new password",
    description=(
        "Requires a valid JWT Bearer token in the ``Authorization`` header. "
        "The current password is verified before the new password is applied."
    ),
    value={
        "current_password": "0ldStr0ng!Passw0rd#2024",
        "new_password": "NewStr0ng!Passw0rd#2025",
        "confirm_password": "NewStr0ng!Passw0rd#2025",
    },
    request_only=True,
)

CHANGE_PASSWORD_SUCCESS_EXAMPLE = OpenApiExample(
    name="Change Password — Success",
    summary="Password changed successfully",
    value={
        "success": True,
        "message": "Password changed successfully.",
        "data": {},
    },
    response_only=True,
    status_codes=["200"],
)

CHANGE_PASSWORD_WRONG_CURRENT_EXAMPLE = OpenApiExample(
    name="Change Password — Wrong Current Password",
    summary="The supplied current password is incorrect",
    value={
        "success": False,
        "message": "Current password is incorrect.",
        "errors": {},
    },
    response_only=True,
    status_codes=["401"],
)

CHANGE_PASSWORD_MISMATCH_EXAMPLE = OpenApiExample(
    name="Change Password — Password Mismatch",
    summary="New password and confirmation do not match",
    value={
        "success": False,
        "message": "Passwords do not match.",
        "errors": {},
    },
    response_only=True,
    status_codes=["400"],
)

CHANGE_PASSWORD_WEAK_PASSWORD_EXAMPLE = OpenApiExample(
    name="Change Password — Weak Password",
    summary="New password does not satisfy the enterprise policy",
    value={
        "success": False,
        "message": "Password does not meet security requirements.",
        "errors": {},
    },
    response_only=True,
    status_codes=["400"],
)

CHANGE_PASSWORD_VALIDATION_ERROR_EXAMPLE = OpenApiExample(
    name="Change Password — Validation Error",
    summary="Request body failed field-level validation",
    value={
        "success": False,
        "message": "Request validation failed.",
        "errors": {
            "current_password": ["This field is required."],
            "new_password": ["This field is required."],
        },
    },
    response_only=True,
    status_codes=["400"],
)

CHANGE_PASSWORD_UNAUTHENTICATED_EXAMPLE = OpenApiExample(
    name="Change Password — Unauthenticated",
    summary="No valid JWT token provided",
    value={
        "success": False,
        "message": "Authentication credentials were not provided.",
        "errors": {
            "detail": "Authentication credentials were not provided.",
        },
    },
    response_only=True,
    status_codes=["401"],
)

CHANGE_PASSWORD_SERVER_ERROR_EXAMPLE = OpenApiExample(
    name="Change Password — Internal Server Error",
    summary="Unexpected server-side failure",
    value={
        "success": False,
        "message": "Internal server error.",
        "errors": {},
    },
    response_only=True,
    status_codes=["500"],
)


# ==============================================================================
# Verify Email Examples
# ==============================================================================

VERIFY_EMAIL_SUCCESS_EXAMPLE = OpenApiExample(
    name="Verify Email — Success",
    summary="Email verified successfully",
    description=(
        "Returned when the signed verification token is valid and "
        "the account is now active."
    ),
    value={
        "success": True,
        "message": "Email verified successfully.",
        "data": {},
    },
    response_only=True,
    status_codes=["200"],
)

VERIFY_EMAIL_MISSING_TOKEN_EXAMPLE = OpenApiExample(
    name="Verify Email — Missing Token",
    summary="No token query parameter supplied",
    description=(
        "Returned when the ``token`` query parameter is absent from the request."
    ),
    value={
        "success": False,
        "message": "Verification token is required.",
        "errors": {},
    },
    response_only=True,
    status_codes=["400"],
)

VERIFY_EMAIL_INVALID_TOKEN_EXAMPLE = OpenApiExample(
    name="Verify Email — Invalid or Expired Token",
    summary="Token is tampered with or has exceeded the 24-hour validity window",
    description=(
        "Returned when the signed token cannot be verified or has expired. "
        "The user must request a new verification email."
    ),
    value={
        "success": False,
        "message": "Verification link is invalid or has expired.",
        "errors": {},
    },
    response_only=True,
    status_codes=["400"],
)


# ==============================================================================
# Resend Verification — Validation Error Example (previously missing)
# ==============================================================================

RESEND_VERIFICATION_VALIDATION_ERROR_EXAMPLE = OpenApiExample(
    name="Resend Verification — Validation Error",
    summary="Invalid email format",
    description="Returned when the submitted email fails format validation.",
    value={
        "success": False,
        "message": "Request validation failed.",
        "errors": {
            "email": ["Enter a valid email address."],
        },
    },
    response_only=True,
    status_codes=["400"],
)


# ==============================================================================
# Me (Profile) Examples
# ==============================================================================

ME_SUCCESS_EXAMPLE = OpenApiExample(
    name="Me — Success",
    summary="Authenticated user profile retrieved",
    description=(
        "Returned when a valid JWT access token is supplied. "
        "Contains the full profile of the authenticated user."
    ),
    value={
        "success": True,
        "message": "Profile retrieved successfully.",
        "data": {
            "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "email": "john.doe@example.com",
            "username": "johndoe",
            "first_name": "John",
            "last_name": "Doe",
            "full_name": "John Doe",
            "is_verified": True,
            "is_active": True,
            "created_at": "2025-01-15T10:30:00Z",
        },
    },
    response_only=True,
    status_codes=["200"],
)

ME_UNAUTHENTICATED_EXAMPLE = OpenApiExample(
    name="Me — Unauthenticated",
    summary="No valid JWT token provided",
    description=(
        "Returned when the ``Authorization`` header is missing or "
        "contains an invalid/expired access token."
    ),
    value={
        "success": False,
        "message": "Authentication credentials were not provided.",
        "errors": {
            "detail": "Authentication credentials were not provided.",
        },
    },
    response_only=True,
    status_codes=["401"],
)

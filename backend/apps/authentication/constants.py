"""
Authentication constants for the SecureAuthX authentication module.
"""

# ==============================================================================
# Password Policy
# ==============================================================================

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128

# ==============================================================================
# Token Expiration (Seconds)
# ==============================================================================

EMAIL_VERIFICATION_TOKEN_EXPIRY = 60 * 60 * 24  # 24 hours

PASSWORD_RESET_TOKEN_EXPIRY = 60 * 30  # 30 minutes

# ==============================================================================
# Token Salts
# ==============================================================================

EMAIL_VERIFICATION_SALT = "email-verification"

PASSWORD_RESET_SALT = "password-reset"

# ==============================================================================
# Authentication Messages
# ==============================================================================

REGISTRATION_SUCCESS = "Registration successful. Please verify your email."

EMAIL_VERIFICATION_SUCCESS = "Email verified successfully."

EMAIL_ALREADY_VERIFIED = "Email is already verified."

LOGIN_SUCCESS = "Login successful."

LOGOUT_SUCCESS = "Logout successful."

TOKEN_REFRESH_SUCCESS = "Access token refreshed successfully."

PROFILE_RETRIEVED_SUCCESS = "Profile retrieved successfully."

RESEND_VERIFICATION_SUCCESS = (
    "If the email exists and is not verified, a verification email has been sent."
)

PASSWORD_RESET_EMAIL_SENT = "If an account exists, a password reset link has been sent."

PASSWORD_RESET_SUCCESS = "Password reset successful."

PASSWORD_CHANGED_SUCCESS = "Password changed successfully."

# ==============================================================================
# Generic Error Messages
# ==============================================================================

INVALID_CREDENTIALS = "Invalid email or password."

ACCOUNT_INACTIVE = "Your account is inactive."

EMAIL_NOT_VERIFIED = "Please verify your email address."

INVALID_TOKEN = "The provided token is invalid or has expired."

WEAK_PASSWORD = "Password does not meet security requirements."

DUPLICATE_EMAIL = "An account with this email already exists."

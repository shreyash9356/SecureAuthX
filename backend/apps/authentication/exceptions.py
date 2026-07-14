"""
Custom exceptions for the SecureAuthX authentication module.

Business logic should raise these exceptions instead of generic
Python exceptions. A global DRF exception handler will convert
them into standardized API responses.
"""


class AuthenticationException(Exception):
    """
    Base exception for all authentication-related errors.
    """

    default_message = "Authentication failed."

    def __init__(self, message=None):
        self.message = message or self.default_message
        super().__init__(self.message)


class InvalidCredentialsException(AuthenticationException):
    """
    Raised when authentication credentials are invalid.
    """

    default_message = "Invalid email or password."


class EmailNotVerifiedException(AuthenticationException):
    """
    Raised when a user attempts to log in without verifying their email.
    """

    default_message = "Your email address has not been verified."


class AccountInactiveException(AuthenticationException):
    """
    Raised when an inactive account attempts authentication.
    """

    default_message = "Your account is inactive. Please contact support."


class DuplicateEmailException(AuthenticationException):
    """
    Raised when a registration request uses an email that already exists.
    """

    default_message = "An account with this email already exists."


class WeakPasswordException(AuthenticationException):
    """
    Raised when a password does not satisfy the enterprise password policy.
    """

    default_message = "Password does not meet security requirements."


class InvalidVerificationTokenException(AuthenticationException):
    """
    Raised when an email verification token is invalid or expired.
    """

    default_message = "Verification link is invalid or has expired."


class InvalidPasswordResetTokenException(AuthenticationException):
    """
    Raised when a password reset token is invalid or expired.
    """

    default_message = "Password reset link is invalid or has expired."


class PasswordMismatchException(AuthenticationException):
    """
    Raised when password and confirm password do not match.
    """

    default_message = "Passwords do not match."

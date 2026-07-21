"""
Custom exceptions for the Multi-Factor Authentication (MFA) module.
"""

from apps.authentication.exceptions import AuthenticationException


class MFALockoutException(AuthenticationException):
    """
    Raised when OTP verification is locked out due to excessive failed attempts.
    """

    default_message = "MFA is temporarily locked due to excessive failed attempts."


class InvalidOTPException(AuthenticationException):
    """
    Raised when the provided OTP code is invalid.
    """

    default_message = "Invalid multi-factor authentication code."


class MFAExpiredSetupException(AuthenticationException):
    """
    Raised when the MFA setup process expires or is invalid.
    """

    default_message = "The MFA setup session has expired or is invalid."


class MFANotEnabledException(AuthenticationException):
    """
    Raised when an operation requires MFA to be enabled, but it is not.
    """

    default_message = "MFA is not enabled for this account."


class MFAAlreadyEnabledException(AuthenticationException):
    """
    Raised when attempting to configure MFA on a user who has it enabled.
    """

    default_message = "MFA is already enabled for this account."


class InvalidRecoveryCodeException(AuthenticationException):
    """
    Raised when a recovery code is invalid, used, or not found.
    """

    default_message = "Invalid or already used recovery code."

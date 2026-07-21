"""
Global DRF exception handler for SecureAuthX.

Converts all DRF exceptions, custom domain exceptions, and user management
violations into a standardized response envelope.
"""

from django.conf import settings
from rest_framework import status
from rest_framework.exceptions import (
    AuthenticationFailed,
    MethodNotAllowed,
    NotAuthenticated,
    NotFound,
    ParseError,
    PermissionDenied,
    Throttled,
    UnsupportedMediaType,
    ValidationError,
)
from rest_framework.response import Response
from rest_framework.views import exception_handler

from apps.authentication.exceptions import AuthenticationException
from apps.audit_logs.exceptions import AuditLogException, AuditLogNotFoundException


# ==============================================================================
# Internal Helpers
# ==============================================================================


def _error_response(
    message: str,
    errors: dict | list,
    http_status: int,
) -> Response:
    """
    Build a standardized error ``Response``.
    """
    return Response(
        {
            "success": False,
            "message": message,
            "errors": errors,
        },
        status=http_status,
    )


def _normalize_errors(data) -> dict:
    """
    Ensure the ``errors`` payload is always a plain ``dict``.
    """
    if isinstance(data, dict):
        return dict(data)

    # Non-field errors arrive as a list — wrap them under a "detail" key.
    if isinstance(data, list):
        return {"detail": data}

    return {"detail": str(data)}


# ==============================================================================
# Per-Exception Handlers
# ==============================================================================


def _handle_drf_exception(exc, drf_response: Response) -> Response:
    """
    Map each DRF exception to a meaningful message and HTTP status.
    """
    errors = _normalize_errors(drf_response.data)

    # 400 — Validation Error
    if isinstance(exc, ValidationError):
        return _error_response(
            message="Request validation failed.",
            errors=errors,
            http_status=status.HTTP_400_BAD_REQUEST,
        )

    # 400 — Malformed request body
    if isinstance(exc, ParseError):
        return _error_response(
            message="Malformed JSON request.",
            errors=errors,
            http_status=status.HTTP_400_BAD_REQUEST,
        )

    # 401 — No credentials supplied
    if isinstance(exc, NotAuthenticated):
        return _error_response(
            message="Authentication credentials were not provided.",
            errors=errors,
            http_status=status.HTTP_401_UNAUTHORIZED,
        )

    # 401 — Invalid / expired credentials
    if isinstance(exc, AuthenticationFailed):
        return _error_response(
            message="Invalid or expired access token.",
            errors=errors,
            http_status=status.HTTP_401_UNAUTHORIZED,
        )

    # 403 — Authenticated but not authorised
    if isinstance(exc, PermissionDenied):
        return _error_response(
            message="You do not have permission to perform this action.",
            errors=errors,
            http_status=status.HTTP_403_FORBIDDEN,
        )

    # 404 — Resource not found
    if isinstance(exc, NotFound):
        return _error_response(
            message="Requested resource was not found.",
            errors=errors,
            http_status=status.HTTP_404_NOT_FOUND,
        )

    # 405 — HTTP method not allowed
    if isinstance(exc, MethodNotAllowed):
        return _error_response(
            message="Method not allowed.",
            errors=errors,
            http_status=status.HTTP_405_METHOD_NOT_ALLOWED,
        )

    # 415 — Content-Type not supported
    if isinstance(exc, UnsupportedMediaType):
        return _error_response(
            message="Unsupported media type.",
            errors=errors,
            http_status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        )

    # 429 — Rate limit exceeded
    if isinstance(exc, Throttled):
        wait = getattr(exc, "wait", None)
        return _error_response(
            message="Too many requests. Please try again later.",
            errors={"retry_after": wait} if wait is not None else {},
            http_status=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    # Fallback
    return _error_response(
        message="An unexpected error occurred.",
        errors=errors,
        http_status=drf_response.status_code,
    )


def _handle_auth_exception(exc: AuthenticationException) -> Response:
    """
    Map custom ``AuthenticationException`` subclasses to standardized responses.
    """
    from apps.authentication.exceptions import (
        AccountInactiveException,
        DuplicateEmailException,
        EmailNotVerifiedException,
        InvalidCredentialsException,
        InvalidPasswordResetTokenException,
        InvalidVerificationTokenException,
        PasswordMismatchException,
        WeakPasswordException,
    )

    if isinstance(exc, InvalidCredentialsException):
        http_status = status.HTTP_401_UNAUTHORIZED
    elif isinstance(exc, (EmailNotVerifiedException,)):
        http_status = status.HTTP_403_FORBIDDEN
    elif isinstance(exc, AccountInactiveException):
        http_status = status.HTTP_403_FORBIDDEN
    elif isinstance(exc, DuplicateEmailException):
        http_status = status.HTTP_409_CONFLICT
    elif isinstance(
        exc,
        (
            WeakPasswordException,
            PasswordMismatchException,
            InvalidVerificationTokenException,
            InvalidPasswordResetTokenException,
        ),
    ):
        http_status = status.HTTP_400_BAD_REQUEST
    else:
        http_status = status.HTTP_400_BAD_REQUEST

    return _error_response(
        message=exc.message,
        errors={},
        http_status=http_status,
    )


# ==============================================================================
# Public Entry Point
# ==============================================================================


def custom_exception_handler(exc, context) -> Response | None:
    """
    Global DRF exception handler.
    """
    drf_response = exception_handler(exc, context)

    # DRF exceptions
    if drf_response is not None:
        return _handle_drf_exception(exc, drf_response)

    # Custom auth exceptions
    if isinstance(exc, AuthenticationException):
        return _handle_auth_exception(exc)

    # Audit log exceptions
    if isinstance(exc, AuditLogNotFoundException):
        return _error_response(
            message=exc.message,
            errors={},
            http_status=status.HTTP_404_NOT_FOUND,
        )

    if isinstance(exc, AuditLogException):
        return _error_response(
            message=exc.message,
            errors={},
            http_status=status.HTTP_400_BAD_REQUEST,
        )

    # Custom User Management exceptions (activate, deactivate, lock, etc.)
    try:
        from apps.users.exceptions import UserManagementException
        if isinstance(exc, UserManagementException):
            return _error_response(
                message=str(exc),
                errors={},
                http_status=status.HTTP_400_BAD_REQUEST,
            )
    except ImportError:
        pass

    # Custom Authorization exceptions (role assignments, etc.)
    try:
        from apps.authorization.exceptions import RoleAssignmentException, RoleNotFoundException
        if isinstance(exc, (RoleAssignmentException, RoleNotFoundException)):
            return _error_response(
                message=str(exc),
                errors={},
                http_status=status.HTTP_400_BAD_REQUEST,
            )
    except ImportError:
        pass

    # Unknown / unhandled exceptions
    if settings.DEBUG:
        raise exc

    return _error_response(
        message="Internal server error.",
        errors={},
        http_status=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )

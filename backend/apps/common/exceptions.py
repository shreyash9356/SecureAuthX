"""
Global DRF exception handler for SecureAuthX.

Converts all DRF exceptions and custom domain exceptions into a single
standardized response envelope:

    Success:
        {"success": true, "message": "...", "data": {}}

    Error:
        {"success": false, "message": "...", "errors": {}}

Adding support for a new exception type:
    1. Import the DRF exception class.
    2. Add an ``elif isinstance(exc, <ExcClass>):`` block inside
       ``_handle_drf_exception`` following the existing pattern.
    3. Return ``_error_response(message, errors, status_code)``.
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

    Args:
        message:     Human-readable description of the error.
        errors:      Field-level or detail-level error payload.
        http_status: HTTP status code to send.

    Returns:
        A DRF ``Response`` with the standardized error envelope.
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

    DRF sometimes returns a ``ReturnDict``, a plain ``dict``,
    or a ``list`` (e.g. non-field errors). This helper normalises
    all three so callers always receive a ``dict``.

    Args:
        data: Raw ``response.data`` from the default DRF handler.

    Returns:
        A plain ``dict`` suitable for the ``errors`` field.
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

    The ``drf_response`` is the response already produced by DRF's
    default handler and is used to extract structured error details.

    Args:
        exc:          The original exception instance.
        drf_response: The ``Response`` returned by ``exception_handler``.

    Returns:
        A standardized error ``Response``.
    """

    errors = _normalize_errors(drf_response.data)

    # ------------------------------------------------------------------
    # 400 — Validation Error
    # ------------------------------------------------------------------
    if isinstance(exc, ValidationError):
        return _error_response(
            message="Request validation failed.",
            errors=errors,
            http_status=status.HTTP_400_BAD_REQUEST,
        )

    # ------------------------------------------------------------------
    # 400 — Malformed / unparseable request body
    # ------------------------------------------------------------------
    if isinstance(exc, ParseError):
        return _error_response(
            message="Malformed JSON request.",
            errors=errors,
            http_status=status.HTTP_400_BAD_REQUEST,
        )

    # ------------------------------------------------------------------
    # 401 — No credentials supplied
    # ------------------------------------------------------------------
    if isinstance(exc, NotAuthenticated):
        return _error_response(
            message="Authentication credentials were not provided.",
            errors=errors,
            http_status=status.HTTP_401_UNAUTHORIZED,
        )

    # ------------------------------------------------------------------
    # 401 — Invalid / expired credentials (covers Simple JWT errors)
    # ------------------------------------------------------------------
    if isinstance(exc, AuthenticationFailed):
        return _error_response(
            message="Invalid or expired access token.",
            errors=errors,
            http_status=status.HTTP_401_UNAUTHORIZED,
        )

    # ------------------------------------------------------------------
    # 403 — Authenticated but not authorised
    # ------------------------------------------------------------------
    if isinstance(exc, PermissionDenied):
        return _error_response(
            message="You do not have permission to perform this action.",
            errors=errors,
            http_status=status.HTTP_403_FORBIDDEN,
        )

    # ------------------------------------------------------------------
    # 404 — Resource not found
    # ------------------------------------------------------------------
    if isinstance(exc, NotFound):
        return _error_response(
            message="Requested resource was not found.",
            errors=errors,
            http_status=status.HTTP_404_NOT_FOUND,
        )

    # ------------------------------------------------------------------
    # 405 — HTTP method not allowed on this endpoint
    # ------------------------------------------------------------------
    if isinstance(exc, MethodNotAllowed):
        return _error_response(
            message="Method not allowed.",
            errors=errors,
            http_status=status.HTTP_405_METHOD_NOT_ALLOWED,
        )

    # ------------------------------------------------------------------
    # 415 — Content-Type not supported
    # ------------------------------------------------------------------
    if isinstance(exc, UnsupportedMediaType):
        return _error_response(
            message="Unsupported media type.",
            errors=errors,
            http_status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        )

    # ------------------------------------------------------------------
    # 429 — Rate limit exceeded
    # ------------------------------------------------------------------
    if isinstance(exc, Throttled):
        return _error_response(
            message="Too many requests. Please try again later.",
            errors=errors,
            http_status=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    # ------------------------------------------------------------------
    # Fallback — unknown DRF exception; preserve original status code
    # ------------------------------------------------------------------
    return _error_response(
        message="An unexpected error occurred.",
        errors=errors,
        http_status=drf_response.status_code,
    )


def _handle_auth_exception(exc: AuthenticationException) -> Response:
    """
    Map custom ``AuthenticationException`` subclasses to standardized responses.

    All subclasses carry a ``message`` attribute set either by the caller
    or by the ``default_message`` class variable.  The HTTP status is
    derived from the exception type so each subclass can be mapped
    individually without changing the view layer.

    Args:
        exc: An ``AuthenticationException`` subclass instance.

    Returns:
        A standardized error ``Response``.
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

    # Credentials are wrong — 401
    if isinstance(exc, InvalidCredentialsException):
        http_status = status.HTTP_401_UNAUTHORIZED

    # Email not yet confirmed or token problems — 403
    elif isinstance(exc, (EmailNotVerifiedException,)):
        http_status = status.HTTP_403_FORBIDDEN

    # Account state issues — 403
    elif isinstance(exc, AccountInactiveException):
        http_status = status.HTTP_403_FORBIDDEN

    # Duplicate registration — 409
    elif isinstance(exc, DuplicateEmailException):
        http_status = status.HTTP_409_CONFLICT

    # Input/policy failures — 400
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

    # Base class / any future subclass not explicitly mapped
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
    Global DRF exception handler for SecureAuthX.

    Resolution order
    ----------------
    1. DRF exceptions       → ``_handle_drf_exception``
    2. Domain exceptions    → ``_handle_auth_exception``
    3. Unknown exceptions   → raise in DEBUG; 500 in production

    This function is registered via ``REST_FRAMEWORK["EXCEPTION_HANDLER"]``
    in ``settings/base.py``.

    Args:
        exc:     The raised exception.
        context: DRF context dict containing the ``request`` and ``view``.

    Returns:
        A standardized ``Response``, or ``None`` if DRF should use its
        default handling (this implementation always returns a ``Response``
        for known exception types).
    """

    # Let DRF's default handler attempt to handle it first.
    # This populates response.data with structured error details.
    drf_response = exception_handler(exc, context)

    # ── DRF exceptions ────────────────────────────────────────────────────────
    if drf_response is not None:
        return _handle_drf_exception(exc, drf_response)

    # ── Custom domain exceptions ──────────────────────────────────────────────
    if isinstance(exc, AuthenticationException):
        return _handle_auth_exception(exc)

    # ── Audit log domain exceptions ───────────────────────────────────────────
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

    # ── Unknown / unhandled exceptions ────────────────────────────────────────
    if settings.DEBUG:
        raise exc

    return _error_response(
        message="Internal server error.",
        errors={},
        http_status=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )

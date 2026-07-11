"""
Utility functions for the SecureAuthX authentication module.
"""

from typing import Any


def success_response(message: str, data: Any = None) -> dict:
    """
    Create a standardized success response.

    Args:
        message: Success message.
        data: Optional response payload.

    Returns:
        Standardized success response dictionary.
    """
    return {
        "success": True,
        "message": message,
        "data": data or {},
    }


def error_response(message: str, errors: Any = None) -> dict:
    """
    Create a standardized error response.

    Args:
        message: Error message.
        errors: Optional validation or business errors.

    Returns:
        Standardized error response dictionary.
    """
    return {
        "success": False,
        "message": message,
        "errors": errors or {},
    }

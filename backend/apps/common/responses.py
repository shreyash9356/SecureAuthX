from typing import Any
from rest_framework import status
from rest_framework.response import Response


def success_response(
    data: Any,
    message: str = "Operation successful.",
    status_code: int = status.HTTP_200_OK,
) -> Response:
    """
    Standard Success JSON response wrapper.
    """
    return Response(
        {
            "success": True,
            "message": message,
            "data": data,
        },
        status=status_code,
    )


def error_response(
    errors: Any,
    message: str = "Operation failed.",
    status_code: int = status.HTTP_400_BAD_REQUEST,
) -> Response:
    """
    Standard Error JSON response wrapper.
    """
    return Response(
        {
            "success": False,
            "message": message,
            "errors": errors,
        },
        status=status_code,
    )

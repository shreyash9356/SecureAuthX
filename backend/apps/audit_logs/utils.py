"""
Utility helpers for the audit_logs module.

Kept small and dependency-free so they can be imported safely from anywhere,
including service layers and signal handlers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rest_framework.request import Request


def get_client_ip(request: "Request | None") -> str | None:
    """
    Extract the real client IP address from an HTTP request.

    Checks ``HTTP_X_FORWARDED_FOR`` first (set by load balancers and
    reverse proxies) and falls back to ``REMOTE_ADDR``.

    Args:
        request: The DRF/Django request object.  May be ``None`` when
                 logging is triggered outside a request context.

    Returns:
        A string IP address, or ``None`` if unavailable.
    """
    if request is None:
        return None

    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        # The leftmost address is the originating client.
        return x_forwarded_for.split(",")[0].strip()

    return request.META.get("REMOTE_ADDR") or None


def get_user_agent(request: "Request | None") -> str:
    """
    Extract the User-Agent header from an HTTP request.

    Args:
        request: The DRF/Django request object.  May be ``None``.

    Returns:
        The User-Agent string, or an empty string if unavailable.
    """
    if request is None:
        return ""

    return request.META.get("HTTP_USER_AGENT", "") or ""

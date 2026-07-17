"""
Rate limiting throttles for the SecureAuthX authentication module.
"""

import re
from rest_framework.throttling import SimpleRateThrottle


class LoginRateThrottle(SimpleRateThrottle):
    """
    Throttle for the login endpoint.
    Limits requests by IP.
    5 requests / minute.
    """
    scope = "login"

    def get_cache_key(self, request, view):
        ident = self.get_ident(request)
        return self.cache_format % {
            "scope": self.scope,
            "ident": ident,
        }


class ForgotPasswordRateThrottle(SimpleRateThrottle):
    """
    Throttle for the forgot password endpoint.
    Limits requests by IP.
    Enforces a custom 15-minute rolling window (3 requests / 15 minutes).
    """
    scope = "forgot_password"

    def parse_rate(self, rate):
        """
        Custom rate parsing to support multi-minute intervals (e.g. '15min', '15m').
        """
        if rate is None:
            return (None, None)

        try:
            num, period = rate.split("/")
            num_requests = int(num)
        except ValueError:
            return (None, None)

        # Parse duration period (e.g., '15min', '15m')
        match = re.match(r"^(\d+)?([a-zA-Z]+)$", period)
        if not match:
            return (None, None)

        multiplier_str, unit = match.groups()
        multiplier = int(multiplier_str) if multiplier_str else 1

        unit = unit.lower()
        if unit in ("s", "sec", "second", "seconds"):
            duration = multiplier
        elif unit in ("m", "min", "minute", "minutes"):
            duration = multiplier * 60
        elif unit in ("h", "hr", "hour", "hours"):
            duration = multiplier * 3600
        elif unit in ("d", "day", "days"):
            duration = multiplier * 86400
        else:
            return (None, None)

        return (num_requests, duration)

    def get_cache_key(self, request, view):
        ident = self.get_ident(request)
        return self.cache_format % {
            "scope": self.scope,
            "ident": ident,
        }


class ResendVerificationRateThrottle(SimpleRateThrottle):
    """
    Throttle for the resend verification endpoint.
    Limits requests by IP.
    3 requests / hour.
    """
    scope = "resend_verification"

    def get_cache_key(self, request, view):
        ident = self.get_ident(request)
        return self.cache_format % {
            "scope": self.scope,
            "ident": ident,
        }
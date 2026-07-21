"""
OpenAPI Schema extensions for user_sessions.
"""

from drf_spectacular.extensions import OpenApiAuthenticationExtension


class SessionJWTAuthenticationScheme(OpenApiAuthenticationExtension):
    """
    OpenAPI extension to register SessionJWTAuthentication in drf-spectacular schema.
    """

    target_class = "apps.user_sessions.authentication.SessionJWTAuthentication"
    name = "BearerAuth"

    def get_security_definition(self, auto_schema):
        return {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": (
                "JWT Bearer token authentication. "
                "Obtain a token via POST /api/v1/auth/login/ "
                "and prefix the value with 'Bearer '."
            ),
        }

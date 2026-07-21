from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes


def user_list_swagger_decorator(tags=None):
    """
    Decorator to document search, filter, and pagination parameters for UserListAPIView in Swagger/OpenAPI.
    """
    if tags is None:
        tags = ["Users"]
    return extend_schema(
        summary="List Users",
        description="Retrieve a paginated list of users with filtering, searching, and ordering.",
        tags=tags,
        parameters=[
            OpenApiParameter(
                "is_active",
                OpenApiTypes.BOOL,
                OpenApiParameter.QUERY,
                description="Filter by active status",
            ),
            OpenApiParameter(
                "is_verified",
                OpenApiTypes.BOOL,
                OpenApiParameter.QUERY,
                description="Filter by email verification status",
            ),
            OpenApiParameter(
                "is_locked",
                OpenApiTypes.BOOL,
                OpenApiParameter.QUERY,
                description="Filter by account lock status",
            ),
            OpenApiParameter(
                "search",
                OpenApiTypes.STR,
                OpenApiParameter.QUERY,
                description="Search query for email, username, or name fields",
            ),
            OpenApiParameter(
                "ordering",
                OpenApiTypes.STR,
                OpenApiParameter.QUERY,
                description="Sort order (e.g. email, -created_at)",
            ),
            OpenApiParameter(
                "page",
                OpenApiTypes.INT,
                OpenApiParameter.QUERY,
                description="Page number",
            ),
            OpenApiParameter(
                "page_size",
                OpenApiTypes.INT,
                OpenApiParameter.QUERY,
                description="Number of items per page",
            ),
        ],
    )


def base_swagger_decorator(default_tag, summary=None, description=None, tags=None, **kwargs):
    """
    Base helper function to generate standard openapi schema documentation.
    """
    if tags is None:
        tags = [default_tag]
    return extend_schema(
        summary=summary,
        description=description,
        tags=tags,
        **kwargs
    )


def user_action_swagger_decorator(summary=None, description=None, tags=None, **kwargs):
    """
    Generic decorator to apply the "Users" tag (by default) and custom details on User endpoints.
    """
    return base_swagger_decorator("Users", summary, description, tags, **kwargs)


def audit_log_swagger_decorator(summary=None, description=None, tags=None, **kwargs):
    """
    Generic decorator to apply the "Audit Logs" tag (by default) and custom details on Audit Log endpoints.
    """
    return base_swagger_decorator("Audit Logs", summary, description, tags, **kwargs)

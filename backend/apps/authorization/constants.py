"""
Centralized authorization constants for SecureAuthX.

Permission codes must match the seeded catalog and Swagger documentation.
Do not hardcode these strings in views or permission helpers.
"""


class RoleSlugs:
    """System role slug identifiers."""

    SUPER_ADMIN = "super-admin"
    ADMIN = "admin"
    MANAGER = "manager"
    EMPLOYEE = "employee"
    AUDITOR = "auditor"
    SUPPORT = "support"


class PermissionCodes:
    """
    Catalog permission capability codes.

    Format: ``{domain}:{resource}:{action}``
    """

    # identity:user
    USER_CREATE = "identity:user:create"
    USER_READ = "identity:user:read"
    USER_UPDATE = "identity:user:update"
    USER_DELETE = "identity:user:delete"
    USER_MANAGE = "identity:user:manage"

    # identity:role
    ROLE_CREATE = "identity:role:create"
    ROLE_READ = "identity:role:read"
    ROLE_UPDATE = "identity:role:update"
    ROLE_DELETE = "identity:role:delete"
    ROLE_MANAGE = "identity:role:manage"

    # identity:permission
    PERMISSION_CREATE = "identity:permission:create"
    PERMISSION_READ = "identity:permission:read"
    PERMISSION_UPDATE = "identity:permission:update"
    PERMISSION_DELETE = "identity:permission:delete"
    PERMISSION_MANAGE = "identity:permission:manage"

    # identity:session
    SESSION_CREATE = "identity:session:create"
    SESSION_READ = "identity:session:read"
    SESSION_UPDATE = "identity:session:update"
    SESSION_DELETE = "identity:session:delete"
    SESSION_MANAGE = "identity:session:manage"

    # identity:mfa
    MFA_CREATE = "identity:mfa:create"
    MFA_READ = "identity:mfa:read"
    MFA_UPDATE = "identity:mfa:update"
    MFA_DELETE = "identity:mfa:delete"
    MFA_MANAGE = "identity:mfa:manage"

    # organization:organization
    ORGANIZATION_CREATE = "organization:organization:create"
    ORGANIZATION_READ = "organization:organization:read"
    ORGANIZATION_UPDATE = "organization:organization:update"
    ORGANIZATION_DELETE = "organization:organization:delete"
    ORGANIZATION_MANAGE = "organization:organization:manage"

    # audit:log
    AUDIT_LOG_READ = "audit:log:read"
    AUDIT_LOG_MANAGE = "audit:log:manage"
    AUDIT_LOG_EXPORT = "audit:log:export"

    # notification:notification
    NOTIFICATION_CREATE = "notification:notification:create"
    NOTIFICATION_READ = "notification:notification:read"
    NOTIFICATION_UPDATE = "notification:notification:update"
    NOTIFICATION_DELETE = "notification:notification:delete"
    NOTIFICATION_MANAGE = "notification:notification:manage"
    NOTIFICATION_EXECUTE = "notification:notification:execute"

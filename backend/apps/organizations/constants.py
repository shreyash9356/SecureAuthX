from django.db import models


class OrganizationStatus(models.TextChoices):
    """
    Represents the lifecycle state of an organization.
    """

    ACTIVE = "ACTIVE", "Active"
    INACTIVE = "INACTIVE", "Inactive"
    SUSPENDED = "SUSPENDED", "Suspended"
    DELETED = "DELETED", "Deleted"


class MembershipStatus(models.TextChoices):
    """
    Represents the status of a user's membership
    within an organization.
    """

    PENDING = "PENDING", "Pending"
    ACTIVE = "ACTIVE", "Active"
    SUSPENDED = "SUSPENDED", "Suspended"
    REMOVED = "REMOVED", "Removed"


class InvitationStatus(models.TextChoices):
    """
    Represents the lifecycle of an organization invitation.
    """

    PENDING = "PENDING", "Pending"
    ACCEPTED = "ACCEPTED", "Accepted"
    REJECTED = "REJECTED", "Rejected"
    EXPIRED = "EXPIRED", "Expired"
    CANCELLED = "CANCELLED", "Cancelled"


class OrganizationRoleType(models.TextChoices):
    """
    Defines special organization-level ownership roles.

    RBAC roles are still managed by the Authorization module.
    This enum is only for ownership semantics.
    """

    OWNER = "OWNER", "Owner"
    MEMBER = "MEMBER", "Member"


# ==============================================================================
# Configuration Defaults
# ==============================================================================

DEFAULT_INVITATION_EXPIRY_DAYS = 7
DEFAULT_TIMEZONE = "UTC"
DEFAULT_SESSION_TIMEOUT_MINUTES = 60
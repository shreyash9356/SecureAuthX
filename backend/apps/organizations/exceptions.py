class OrganizationException(Exception):
    """Base exception for all organization-related business logic and rule violations."""
    pass


class OrganizationNotFoundException(OrganizationException):
    """Raised when a queried organization cannot be found in the database."""
    pass


class OrganizationAlreadyExistsException(OrganizationException):
    """Raised when attempting to create an organization with a duplicate name or slug."""
    pass


class MembershipNotFoundException(OrganizationException):
    """Raised when an organization membership is queried but does not exist."""
    pass


class MembershipAlreadyExistsException(OrganizationException):
    """Raised when trying to add a user who is already a member of the organization."""
    pass


class InvitationNotFoundException(OrganizationException):
    """Raised when an invitation token or ID is missing or invalid."""
    pass


class InvitationExpiredException(OrganizationException):
    """Raised when a user attempts to accept an invitation that has passed its expiration date."""
    pass


class InvitationAlreadyAcceptedException(OrganizationException):
    """Raised when a user attempts to accept a token that has already been used."""
    pass


class InvalidInvitationStateException(OrganizationException):
    """Raised when an invitation is in a non-pending state (e.g. cancelled, rejected)."""
    pass


class InvalidMembershipException(OrganizationException):
    """Raised when membership business rules or constraints (e.g. owner demotion/removal) are violated."""
    pass


class OwnershipTransferException(OrganizationException):
    """Raised when validation fails during an organization ownership transfer request."""
    pass

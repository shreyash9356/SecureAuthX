"""
Domain exceptions for the audit_logs module.
"""


class AuditLogException(Exception):
    """
    Base exception for all audit log domain errors.
    """

    default_message = "An audit log error occurred."

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.default_message
        super().__init__(self.message)


class AuditLogNotFoundException(AuditLogException):
    """
    Raised when an audit log record cannot be found.
    """

    default_message = "Audit log record not found."

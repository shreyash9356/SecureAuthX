"""
Registration service for the SecureAuthX authentication module.
"""

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction

from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService
from apps.authentication.emails.verification import VerificationEmailService
from apps.authentication.exceptions import (
    DuplicateEmailException,
    WeakPasswordException,
)
from apps.authentication.tokens import TokenService
from apps.authentication.validators.password_validator import (
    EnterprisePasswordValidator,
)

User = get_user_model()


class RegistrationService:
    """
    Service responsible for user registration.
    """

    @staticmethod
    @transaction.atomic
    def register(
        *,
        email: str,
        password: str,
        username: str | None = None,
        first_name: str = "",
        last_name: str = "",
        request=None,
    ) -> dict:
        """
        Register a new user.

        Args:
            email:      User's email address.
            password:   Plaintext password.
            username:   Optional username.
            first_name: Optional given name.
            last_name:  Optional family name.
            request:    HTTP request for IP/UA extraction.

        Raises:
            DuplicateEmailException
            WeakPasswordException
        """

        email = email.lower().strip()

        # Prevent duplicate accounts
        if User.objects.filter(email=email).exists():
            raise DuplicateEmailException()

        # Validate enterprise password policy
        try:
            EnterprisePasswordValidator().validate(password)
        except ValidationError as exc:
            raise WeakPasswordException(message=" ".join(exc.messages)) from exc

        # Create user
        user = User.objects.create_user(
            email=email,
            password=password,
            username=username,
            first_name=first_name,
            last_name=last_name,
            is_verified=False,
            is_active=True,
            is_locked=False,
        )

        # Generate verification token and send email
        token = TokenService.generate_email_verification_token(user.id)
        VerificationEmailService.send(user=user, token=token)

        AuditLogService.log(
            event_type=AuditLog.EventType.REGISTER,
            status=AuditLog.Status.SUCCESS,
            description=f"New user registered: {user.email}.",
            user=user,
            request=request,
            resource="User",
            resource_id=str(user.id),
        )

        AuditLogService.log(
            event_type=AuditLog.EventType.EMAIL_VERIFICATION_SENT,
            status=AuditLog.Status.INFO,
            description=f"Verification email sent to {user.email}.",
            user=user,
            request=request,
            resource="User",
            resource_id=str(user.id),
        )

        return {"user": user}

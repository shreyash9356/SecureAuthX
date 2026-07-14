"""
Login service for the SecureAuthX authentication module.
"""

from datetime import timedelta

from django.contrib.auth import authenticate, get_user_model
from django.db import transaction
from django.utils import timezone

from rest_framework_simplejwt.tokens import RefreshToken

from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService
from apps.authentication.exceptions import (
    AccountInactiveException,
    EmailNotVerifiedException,
    InvalidCredentialsException,
)

User = get_user_model()


class LoginService:
    """
    Service responsible for authenticating users.
    """

    MAX_FAILED_ATTEMPTS = 5
    LOCK_DURATION_MINUTES = 30

    @classmethod
    def login(
        cls,
        *,
        email: str,
        password: str,
        request=None,
    ) -> dict:
        """
        Authenticate a user and generate JWT tokens.

        Note on transactions
        --------------------
        This method is intentionally NOT wrapped in ``@transaction.atomic``
        at the top level.  The failed-attempt counter and lock fields must
        be committed to the database *before* ``InvalidCredentialsException``
        is raised.  If the whole method were atomic, the exception would
        cause Django to roll back the ``user.save()`` call, leaving
        ``failed_login_attempts`` permanently at 0.

        Only the successful-login path (counter reset + JWT generation)
        is wrapped in its own atomic block so that those two writes are
        always consistent with each other.

        Args:
            email:   User's email address.
            password: Plaintext password.
            request: HTTP request object for IP/UA extraction.
        """

        email = email.lower().strip()

        # ---------------------------------------------------------
        # Get user first
        # ---------------------------------------------------------
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            AuditLogService.log(
                event_type=AuditLog.EventType.LOGIN_FAILED,
                status=AuditLog.Status.FAILURE,
                description=f"Login attempt for unknown email: {email}",
                request=request,
                metadata={"email": email},
            )
            raise InvalidCredentialsException()

        # ---------------------------------------------------------
        # Auto unlock if lock period expired
        # ---------------------------------------------------------
        if user.is_locked and user.locked_until and timezone.now() >= user.locked_until:
            user.is_locked = False
            user.locked_until = None
            user.failed_login_attempts = 0
            user.save(
                update_fields=[
                    "is_locked",
                    "locked_until",
                    "failed_login_attempts",
                ]
            )
            AuditLogService.log(
                event_type=AuditLog.EventType.ACCOUNT_UNLOCKED,
                status=AuditLog.Status.INFO,
                description="Account automatically unlocked after lock expiry.",
                user=user,
                request=request,
                resource="User",
                resource_id=str(user.id),
            )

        # ---------------------------------------------------------
        # Reject locked users
        # ---------------------------------------------------------
        if user.is_locked:
            AuditLogService.log(
                event_type=AuditLog.EventType.LOGIN_FAILED,
                status=AuditLog.Status.FAILURE,
                description="Login attempt on locked account.",
                user=user,
                request=request,
                resource="User",
                resource_id=str(user.id),
            )
            raise AccountInactiveException(
                "Your account has been temporarily locked due to multiple failed login attempts."
            )

        # ---------------------------------------------------------
        # Authenticate credentials
        # ---------------------------------------------------------
        authenticated_user = authenticate(
            username=email,
            password=password,
        )

        if authenticated_user is None:
            user.failed_login_attempts += 1
            just_locked = False

            if user.failed_login_attempts >= cls.MAX_FAILED_ATTEMPTS:
                user.is_locked = True
                user.locked_until = timezone.now() + timedelta(
                    minutes=cls.LOCK_DURATION_MINUTES
                )
                just_locked = True

            user.save(
                update_fields=[
                    "failed_login_attempts",
                    "is_locked",
                    "locked_until",
                ]
            )

            AuditLogService.log(
                event_type=AuditLog.EventType.LOGIN_FAILED,
                status=AuditLog.Status.FAILURE,
                description=(
                    f"Invalid credentials. "
                    f"Failed attempts: {user.failed_login_attempts}."
                ),
                user=user,
                request=request,
                metadata={"failed_login_attempts": user.failed_login_attempts},
                resource="User",
                resource_id=str(user.id),
            )

            if just_locked:
                AuditLogService.log(
                    event_type=AuditLog.EventType.ACCOUNT_LOCKED,
                    status=AuditLog.Status.WARNING,
                    description=(
                        f"Account locked after {cls.MAX_FAILED_ATTEMPTS} "
                        f"consecutive failed login attempts."
                    ),
                    user=user,
                    request=request,
                    metadata={
                        "locked_until": user.locked_until.isoformat(),
                        "max_attempts": cls.MAX_FAILED_ATTEMPTS,
                    },
                    resource="User",
                    resource_id=str(user.id),
                )

            raise InvalidCredentialsException()

        # ---------------------------------------------------------
        # Business validations (before touching counters)
        # ---------------------------------------------------------
        if not authenticated_user.is_active:
            AuditLogService.log(
                event_type=AuditLog.EventType.LOGIN_FAILED,
                status=AuditLog.Status.FAILURE,
                description="Login attempt on inactive account.",
                user=authenticated_user,
                request=request,
                resource="User",
                resource_id=str(authenticated_user.id),
            )
            raise AccountInactiveException()

        if not authenticated_user.is_verified:
            AuditLogService.log(
                event_type=AuditLog.EventType.LOGIN_FAILED,
                status=AuditLog.Status.FAILURE,
                description="Login attempt with unverified email.",
                user=authenticated_user,
                request=request,
                resource="User",
                resource_id=str(authenticated_user.id),
            )
            raise EmailNotVerifiedException()

        # ---------------------------------------------------------
        # Reset security counters + generate JWT atomically
        # A single atomic block here ensures the counter reset and
        # the token issuance are always consistent.
        # ---------------------------------------------------------
        with transaction.atomic():
            if (
                authenticated_user.failed_login_attempts > 0
                or authenticated_user.is_locked
            ):
                authenticated_user.failed_login_attempts = 0
                authenticated_user.is_locked = False
                authenticated_user.locked_until = None

                authenticated_user.save(
                    update_fields=[
                        "failed_login_attempts",
                        "is_locked",
                        "locked_until",
                    ]
                )

            refresh = RefreshToken.for_user(authenticated_user)

        AuditLogService.log(
            event_type=AuditLog.EventType.LOGIN_SUCCESS,
            status=AuditLog.Status.SUCCESS,
            description="User logged in successfully.",
            user=authenticated_user,
            request=request,
            resource="User",
            resource_id=str(authenticated_user.id),
        )

        return {
            "user": authenticated_user,
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        }

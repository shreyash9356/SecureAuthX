"""
SecureAuthX – User Sessions Service Layer
==========================================
Handles all business logic related to UserSession lifecycle management.

Architecture:
    APIView → Serializer → Service → Selector → Model
"""

import logging
from datetime import datetime

from django.contrib.auth.models import AbstractBaseUser
from django.db import transaction
from django.utils import timezone
from rest_framework_simplejwt.settings import api_settings

from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService
from apps.authentication.exceptions import AuthenticationException
from apps.organizations.models import Organization
from apps.user_sessions.models import UserSession

logger = logging.getLogger(__name__)


class SessionService:
    """
    Service class encapsulating all UserSession business logic.

    Responsibilities:
        - Session creation with full metadata
        - Activity tracking
        - Secure session termination and revocation
    """

    @staticmethod
    def _get_session_expiry() -> datetime:
        """
        Calculate session expiry from the project's JWT refresh token lifetime.

        Reads SIMPLE_JWT settings via Simple JWT's api_settings wrapper.

        Returns:
            datetime: Server-generated expiry timestamp (timezone-aware).
        """
        return timezone.now() + api_settings.REFRESH_TOKEN_LIFETIME

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def create_session(
        *,
        user: AbstractBaseUser,
        organization: Organization | None = None,
        ip_address: str,
        user_agent: str = "",
        device_type: str = "",
        browser: str = "",
        operating_system: str = "",
    ) -> UserSession:
        """
        Create and persist a new active UserSession.

        All timestamps are generated server-side; no client-supplied values
        are trusted. JWT and refresh tokens are intentionally never stored.

        Args:
            user:             Authenticated User instance.
            organization:     Optional Organization instance the user belongs to.
            ip_address:       Client IP address (resolved by the view layer).
            user_agent:       Raw User-Agent header string.
            device_type:      Parsed device category (e.g. "mobile", "desktop").
            browser:          Parsed browser name (e.g. "Chrome").
            operating_system: Parsed OS name (e.g. "Windows 11").

        Returns:
            UserSession: The newly created, active session record.
        """
        now = timezone.now()
        expires_at = SessionService._get_session_expiry()

        session = UserSession.objects.create(
            user=user,
            organization=organization,
            ip_address=ip_address,
            user_agent=user_agent,
            device_type=device_type,
            browser=browser,
            operating_system=operating_system,
            login_time=now,
            last_activity=now,
            expires_at=expires_at,
            status=UserSession.Status.ACTIVE,
        )

        logger.info(
            "Session created | user_id=%s org_id=%s session_id=%s ip=%s",
            user.pk,
            getattr(organization, "pk", None),
            session.pk,
            ip_address,
        )

        # Audit log integration
        AuditLogService.log(
            event_type=AuditLog.EventType.SESSION_CREATED,
            status=AuditLog.Status.SUCCESS,
            description="User session established.",
            user=user,
            resource="UserSession",
            resource_id=str(session.pk),
            metadata={
                "ip_address": ip_address,
                "browser": browser,
                "operating_system": operating_system,
                "device_type": device_type,
            },
        )

        return session

    @staticmethod
    def update_last_activity(session: UserSession) -> UserSession:
        """
        Refresh the last_activity timestamp on an existing active session.

        Uses update_fields to issue a minimal UPDATE statement and avoid
        overwriting concurrent writes to other columns.

        Args:
            session: The UserSession instance to update.

        Returns:
            UserSession: The updated session instance.

        Raises:
            AuthenticationException: If the session is inactive or expired.
        """
        now = timezone.now()

        # Check logical expiration (sliding / hard TTL check)
        if now >= session.expires_at:
            if session.status == UserSession.Status.ACTIVE:
                session.status = UserSession.Status.EXPIRED
                session.save(update_fields=["status", "updated_at"])
            raise AuthenticationException("Session has expired.")

        # Ensure session is active
        if session.status != UserSession.Status.ACTIVE:
            raise AuthenticationException("Session is not active.")

        session.last_activity = now
        session.save(update_fields=["last_activity", "updated_at"])

        logger.debug(
            "Session activity updated | session_id=%s user_id=%s",
            session.pk,
            session.user_id,
        )

        return session

    @staticmethod
    @transaction.atomic
    def logout_session(session: UserSession) -> UserSession:
        """
        Terminate an active session by transitioning its status to LOGGED_OUT.

        The record is retained for audit and forensic purposes; it is never
        deleted. Only the status and logout_time fields are written.

        Args:
            session: The active UserSession instance to terminate.

        Returns:
            UserSession: The updated session with LOGGED_OUT status.

        Raises:
            AuthenticationException: If the session is inactive or expired.
        """
        now = timezone.now()

        # Check logical expiration
        if now >= session.expires_at:
            if session.status == UserSession.Status.ACTIVE:
                session.status = UserSession.Status.EXPIRED
                session.save(update_fields=["status", "updated_at"])
            raise AuthenticationException("Cannot logout an expired session.")

        # Ensure session is active before allowing transition to LOGGED_OUT
        if session.status != UserSession.Status.ACTIVE:
            raise AuthenticationException(
                f"Cannot logout session with status: {session.status}"
            )

        session.status = UserSession.Status.LOGGED_OUT
        session.logout_time = now
        session.save(update_fields=["status", "logout_time", "updated_at"])

        logger.info(
            "Session logged out | session_id=%s user_id=%s",
            session.pk,
            session.user_id,
        )

        # Audit log integration
        AuditLogService.log(
            event_type=AuditLog.EventType.LOGOUT,
            status=AuditLog.Status.SUCCESS,
            description="User logged out successfully.",
            user=session.user,
            resource="UserSession",
            resource_id=str(session.pk),
        )

        return session

    @staticmethod
    @transaction.atomic
    def logout_all_sessions(
        user: AbstractBaseUser,
        exclude_session: UserSession | None = None,
    ) -> int:
        """
        Log out all active, non-expired sessions for a user, optionally excluding one.

        Args:
            user:            The authenticated User instance.
            exclude_session: Optional UserSession instance to preserve.

        Returns:
            int: Number of sessions terminated.
        """
        from apps.user_sessions.selectors.session_selector import SessionSelector

        now = timezone.now()
        active_sessions = SessionSelector.list_active_sessions_for_user(user)

        if exclude_session:
            active_sessions = active_sessions.exclude(id=exclude_session.id)

        count = 0
        for session in active_sessions:
            session.status = UserSession.Status.LOGGED_OUT
            session.logout_time = now
            session.save(update_fields=["status", "logout_time", "updated_at"])

            logger.info(
                "Session logged out via bulk logout | session_id=%s user_id=%s",
                session.pk,
                session.user_id,
            )

            # Audit log integration
            AuditLogService.log(
                event_type=AuditLog.EventType.LOGOUT,
                status=AuditLog.Status.SUCCESS,
                description="Session logged out via bulk logout.",
                user=user,
                resource="UserSession",
                resource_id=str(session.pk),
            )
            count += 1

        return count

    @staticmethod
    @transaction.atomic
    def revoke_session(
        session: UserSession,
        revoked_by: AbstractBaseUser,
        revocation_reason: str = "",
    ) -> UserSession:
        """
        Forcibly revoke an active session by an administrator.

        Args:
            session:           The UserSession instance to revoke.
            revoked_by:        The User model instance performing the revocation (must be admin).
            revocation_reason: The reason for the revocation.

        Returns:
            UserSession: The updated session instance.

        Raises:
            AuthenticationException: If the session is inactive or expired.
        """
        now = timezone.now()

        # Check logical expiration
        if now >= session.expires_at:
            if session.status == UserSession.Status.ACTIVE:
                session.status = UserSession.Status.EXPIRED
                session.save(update_fields=["status", "updated_at"])
            raise AuthenticationException("Cannot revoke an expired session.")

        # Ensure session is active
        if session.status != UserSession.Status.ACTIVE:
            raise AuthenticationException(
                f"Cannot revoke session with status: {session.status}"
            )

        session.status = UserSession.Status.REVOKED
        session.revoked_at = now
        session.revoked_by = revoked_by
        session.revocation_reason = revocation_reason
        session.save(
            update_fields=[
                "status",
                "revoked_at",
                "revoked_by",
                "revocation_reason",
                "updated_at",
            ]
        )

        logger.info(
            "Session revoked by admin | session_id=%s revoked_by=%s reason=%s",
            session.pk,
            revoked_by.pk,
            revocation_reason,
        )

        # Audit log integration
        AuditLogService.log(
            event_type=AuditLog.EventType.SESSION_REVOKED,
            status=AuditLog.Status.SUCCESS,
            description=f"Session revoked by admin. Reason: {revocation_reason}",
            user=revoked_by,
            resource="UserSession",
            resource_id=str(session.pk),
            metadata={
                "revocation_reason": revocation_reason,
                "affected_user_id": str(session.user_id),
            },
        )

        return session



import logging
from typing import Any, Optional
from django.utils import timezone
from django.core.exceptions import ValidationError

from apps.security_policies.models import SecurityPolicy
from apps.security_policies.selectors import get_user_effective_policy
from apps.user_sessions.selectors.session_selector import SessionSelector
from apps.user_sessions.services.session_service import SessionService

logger = logging.getLogger(__name__)


class SessionPolicyService:
    """
    Enterprise Session Policy Enforcement Service.
    
    Evaluates concurrent user session caps, absolute session timeouts,
    idle inactivity timeouts, and forced logouts on security events.
    """

    @classmethod
    def enforce_concurrent_session_limit(cls, user: Any, organization: Any = None) -> int:
        """
        Revokes oldest active sessions if user session count exceeds max_concurrent_sessions limit.
        
        Returns:
            Count of revoked sessions.
        """
        effective_policy = get_user_effective_policy(user, organization)
        max_sessions = effective_policy.max_concurrent_sessions

        if max_sessions <= 0:
            return 0

        active_sessions = SessionSelector.list_active_sessions_for_user(user)
        current_count = active_sessions.count()

        if current_count >= max_sessions:
            excess = (current_count - max_sessions) + 1
            oldest_sessions = active_sessions.order_by("created_at")[:excess]
            
            revoked_count = 0
            for session in oldest_sessions:
                try:
                    SessionService.revoke_session(session=session, revoked_by=user, revocation_reason="Concurrent session limit exceeded.")
                except Exception:
                    session.status = "REVOKED"
                    session.save()
                revoked_count += 1

            logger.info("Revoked %d excess session(s) for user %s to enforce concurrent session cap of %d.", revoked_count, user.email, max_sessions)
            return revoked_count

        return 0

    @classmethod
    def validate_session_timeouts(cls, session: Any, organization: Any = None) -> bool:
        """
        Validates session age against policy absolute and idle timeouts.
        
        Returns:
            True if valid, False if session has expired per policy.
        """
        effective_policy = get_user_effective_policy(session.user, organization)
        now = timezone.now()

        # Absolute Timeout Check
        abs_limit = effective_policy.session_absolute_timeout_minutes
        if abs_limit > 0:
            abs_exp = session.created_at + timezone.timedelta(minutes=abs_limit)
            if now > abs_exp:
                logger.warning("Session %s expired due to absolute timeout policy (%d mins).", session.id, abs_limit)
                try:
                    SessionService.revoke_session(session=session, revoked_by=session.user, revocation_reason="Absolute timeout expired.")
                except Exception:
                    session.status = "EXPIRED"
                    session.save()
                return False

        # Idle Timeout Check
        idle_limit = effective_policy.session_idle_timeout_minutes
        if idle_limit > 0:
            last_activity = getattr(session, "last_activity", None) or session.created_at
            idle_exp = last_activity + timezone.timedelta(minutes=idle_limit)
            if now > idle_exp:
                logger.warning("Session %s expired due to idle inactivity policy (%d mins).", session.id, idle_limit)
                try:
                    SessionService.revoke_session(session=session, revoked_by=session.user, revocation_reason="Idle timeout expired.")
                except Exception:
                    session.status = "EXPIRED"
                    session.save()
                return False

        return True

    @classmethod
    def handle_force_logout_on_password_change(cls, user: Any, organization: Any = None) -> int:
        """
        Revokes all active user sessions if force_logout_on_password_change is enabled in policy.
        
        Returns:
            Count of revoked sessions.
        """
        effective_policy = get_user_effective_policy(user, organization)

        if effective_policy.force_logout_on_password_change:
            revoked_count = SessionService.logout_all_sessions(user=user)
            logger.info("Revoked all %d sessions for user %s following password change.", revoked_count, user.email)
            return revoked_count

        return 0

"""
Authentication backend for user_sessions validation.
"""

from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.utils import timezone

from apps.user_sessions.selectors.session_selector import SessionSelector
from apps.user_sessions.services.session_service import SessionService
from apps.user_sessions.models import UserSession


class SessionJWTAuthentication(JWTAuthentication):
    """
    Session-aware JWT Authentication.

    Extends Simple JWT's JWTAuthentication to:
    1. Verify that the request's JWT contains a valid, ACTIVE session ID.
    2. Enforce administrative revocation and hard TTL expiry at request time.
    3. Update the session's last_activity timestamp on every request.
    """

    def authenticate(self, request):
        # Delegate basic JWT validation to Simple JWT
        auth_result = super().authenticate(request)
        if auth_result is None:
            return None

        user, validated_token = auth_result

        # Extract session_id claim
        session_id = validated_token.get("session_id")
        if not session_id:
            raise AuthenticationFailed("Session ID not found in token.")

        # Retrieve the session
        try:
            session = SessionSelector.get_session_by_id(session_id)
        except UserSession.DoesNotExist:
            raise AuthenticationFailed("Associated session does not exist.")

        # Verify ownership
        if session.user_id != user.id:
            raise AuthenticationFailed(
                "Associated session does not belong to the authenticated user."
            )

        # Verify hard expiry
        now = timezone.now()
        if now >= session.expires_at:
            if session.status == UserSession.Status.ACTIVE:
                session.status = UserSession.Status.EXPIRED
                session.save(update_fields=["status", "updated_at"])
            raise AuthenticationFailed("Session has expired.")

        # Verify ACTIVE status (not revoked, not logged out)
        if session.status != UserSession.Status.ACTIVE:
            raise AuthenticationFailed(
                f"Session is no longer active (status: {session.status.lower()})."
            )

        # Update last_activity timestamp
        try:
            SessionService.update_last_activity(session)
        except Exception as exc:
            raise AuthenticationFailed(
                "Unable to update last activity."
            ) from exc

        # Attach the session context to the request
        request.user_session = session

        return user, validated_token


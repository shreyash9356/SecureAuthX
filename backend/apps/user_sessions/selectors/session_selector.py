"""
SecureAuthX – User Sessions Selector Layer
==========================================
Handles all read-only database query operations for the UserSession model.

Architecture:
    APIView → Serializer → Service → Selector → Model
"""

import logging
import uuid
from django.contrib.auth.models import AbstractBaseUser
from django.db.models import QuerySet
from django.utils import timezone

from apps.user_sessions.models import UserSession

logger = logging.getLogger(__name__)


class SessionSelector:
    """
    Selector class encapsulating read-only queries for UserSession.
    """

    @staticmethod
    def get_session_by_id(session_id: uuid.UUID | str) -> UserSession:
        """
        Retrieve a single UserSession by its UUID.

        Args:
            session_id: The UUID of the session.

        Returns:
            UserSession instance.

        Raises:
            UserSession.DoesNotExist: If session is not found.
        """
        return UserSession.objects.get(id=session_id)

    @staticmethod
    def get_active_session_by_id(session_id: uuid.UUID | str) -> UserSession:
        """
        Retrieve a single active, logically non-expired UserSession by UUID.

        Args:
            session_id: The UUID of the session.

        Returns:
            UserSession: The matching active session.

        Raises:
            UserSession.DoesNotExist: If session is not found or is inactive/expired.
        """
        now = timezone.now()
        return UserSession.objects.get(
            id=session_id,
            status=UserSession.Status.ACTIVE,
            expires_at__gt=now,
        )

    @staticmethod
    def list_active_sessions_for_user(user: AbstractBaseUser) -> QuerySet[UserSession]:
        """
        List all ACTIVE and logically non-expired sessions for a user.

        Args:
            user: The user instance.

        Returns:
            QuerySet of UserSession instances.
        """
        now = timezone.now()
        return UserSession.objects.filter(
            user=user,
            status=UserSession.Status.ACTIVE,
            expires_at__gt=now,
        )

    @staticmethod
    def list_active_sessions_for_organization(
        organization_id: uuid.UUID | str,
    ) -> QuerySet[UserSession]:
        """
        List all ACTIVE and logically non-expired sessions within an organization context.

        Args:
            organization_id: The organization UUID.

        Returns:
            QuerySet of UserSession instances.
        """
        now = timezone.now()
        return UserSession.objects.filter(
            organization_id=organization_id,
            status=UserSession.Status.ACTIVE,
            expires_at__gt=now,
        )

    @staticmethod
    def get_active_session_by_id_and_user(
        session_id: uuid.UUID | str, user: AbstractBaseUser
    ) -> UserSession:
        """
        Retrieve an active, non-expired session by ID and user to prevent IDOR/BOLA.

        Args:
            session_id: The UUID of the session.
            user: The user who owns the session.

        Returns:
            UserSession instance.

        Raises:
            UserSession.DoesNotExist: If the session doesn't exist, belongs to another
                                      user, or is inactive/expired.
        """
        now = timezone.now()
        return UserSession.objects.get(
            id=session_id,
            user=user,
            status=UserSession.Status.ACTIVE,
            expires_at__gt=now,
        )

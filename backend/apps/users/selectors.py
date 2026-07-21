from typing import Optional

from apps.accounts.models import User


class UserSelector:
    """
    Read-only database queries for User Management.

    This selector is responsible only for retrieving user data.
    No business logic should be implemented here.
    """

    @staticmethod
    def get_user_by_id(user_id) -> Optional[User]:
        """
        Retrieve a user by UUID.
        """
        return (
            User.objects.filter(id=user_id)
            .first()
        )

    @staticmethod
    def get_user_by_email(email: str) -> Optional[User]:
        """
        Retrieve a user by email.
        """
        return (
            User.objects.filter(email=email)
            .first()
        )

    @staticmethod
    def get_users():
        """
        Return the base User queryset.
        """
        return User.objects.all()

    @staticmethod
    def list_users():
        """
        Return all users.

        Default ordering is applied from the User model.
        """
        return (
            User.objects
            .all()
        )

    @staticmethod
    def search_users(qs, term: str):
        """
        Filter user queryset by search term.
        """
        from django.db.models import Q
        return qs.filter(
            Q(email__icontains=term) |
            Q(username__icontains=term) |
            Q(first_name__icontains=term) |
            Q(last_name__icontains=term)
        )

    @staticmethod
    def filter_active_users(qs, is_active: bool):
        """
        Filter user queryset by active status.
        """
        return qs.filter(is_active=is_active)

    @staticmethod
    def filter_locked_users(qs, is_locked: bool):
        """
        Filter user queryset by locked status.
        """
        return qs.filter(is_locked=is_locked)
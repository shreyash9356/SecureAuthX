"""
Profile service for the SecureAuthX authentication module.
"""

from django.contrib.auth import get_user_model

User = get_user_model()


class ProfileService:
    """
    Service responsible for retrieving
    the authenticated user's profile.
    """

    @staticmethod
    def get_profile(user):
        """
        Return the authenticated user.
        """

        return user
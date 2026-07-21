from apps.users.selectors import UserSelector


class UserListingService:
    """
    Business logic for user listing operations.
    """

    @staticmethod
    def list_users():
        return UserSelector.get_users()

    @staticmethod
    def get_user_detail(user_id):
        user = UserSelector.get_user_by_id(user_id)
        if not user:
            from rest_framework.exceptions import NotFound
            raise NotFound("User not found.")
        return user
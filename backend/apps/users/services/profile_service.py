from django.db import transaction
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError

from apps.authorization.permissions import can_edit_user
from apps.users.selectors import UserSelector


class UserProfileService:
    """
    Business logic for user profile operations.
    """

    @staticmethod
    def update_user_profile(user_id, data, actor):
        """
        Updates the profile of a user.

        Fields updated: first_name, last_name, username.
        Checks BOLA permission: caller must be target user or have user:update permission.
        """
        user = UserSelector.get_user_by_id(user_id)
        if not user:
            raise NotFound("User not found.")

        # BOLA Security Policy Check
        if not can_edit_user(actor, user):
            raise PermissionDenied("You do not have permission to update this user's profile.")

        try:
            with transaction.atomic():
                # Perform updates
                if "first_name" in data:
                    user.first_name = data["first_name"].strip()
                if "last_name" in data:
                    user.last_name = data["last_name"].strip()
                if "username" in data:
                    user.username = data["username"].strip() if data["username"] else None

                user.full_clean()
                user.save()

                # Audit Log Extension Point:
                # AuditLogService.log_user_updated(
                #     actor_id=actor.id,
                #     target_id=user.id,
                #     changes=data
                # )

                return user
        except DjangoValidationError as e:
            raise ValidationError(e.message_dict)
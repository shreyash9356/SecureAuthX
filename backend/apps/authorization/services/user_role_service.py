import logging
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction, models
from django.core.exceptions import ValidationError
from django.utils import timezone

from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService
from apps.authorization.models import Role, UserRole
from apps.authorization.exceptions import (
    RoleNotFoundException,
    RoleAssignmentException,
)

logger = logging.getLogger(__name__)


class UserRoleService:
    """
    Enterprise User Role Provisioning and Assignment Service.
    
    Orchestrates user-to-role mappings, temporal validation (expirations),
    Just-in-Time (JIT) access extensions, and soft-deactivation controls.
    """

    @classmethod
    def assign_role(
        cls,
        *,
        user_id: str,
        role_id: str,
        assigned_by_user,
        expires_at=None,
        assignment_reason: str = None
    ) -> UserRole:
        """
        Assigns a security Role to a User.
        """
        User = get_user_model()
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise RoleAssignmentException(f"User with ID '{user_id}' does not exist.")

        try:
            role = Role.objects.get(id=role_id)
        except Role.DoesNotExist:
            raise RoleNotFoundException(f"Role with ID '{role_id}' not found.")

        if not role.is_active:
            raise RoleAssignmentException(f"Cannot assign role '{role.slug}' because it is deactivated.")

        now = timezone.now()

        try:
            with transaction.atomic():
                existing = UserRole.objects.filter(
                    user=user,
                    role=role,
                    is_active=True
                ).first()

                if existing:
                    if existing.expires_at and existing.expires_at <= now:
                        existing.is_active = False
                        existing.save()
                    else:
                        raise RoleAssignmentException(
                            f"Role '{role.slug}' is already actively assigned to user '{user.email}'."
                        )

                assignment = UserRole(
                    user=user,
                    role=role,
                    assigned_by=assigned_by_user,
                    expires_at=expires_at,
                    assignment_reason=assignment_reason,
                    is_active=True
                )
                
                assignment.full_clean()
                assignment.save()

                logger.info("Successfully assigned role %s to User %s", role.slug, user.email)

                AuditLogService.log(
                    event_type=AuditLog.EventType.ROLE_ASSIGNED,
                    status=AuditLog.Status.SUCCESS,
                    description=f"Role {role.slug} assigned to user {user.email}.",
                    user=assigned_by_user,
                    resource="UserRole",
                    resource_id=str(assignment.id),
                    metadata={"target_user_id": str(user.id), "role_slug": role.slug, "expires_at": str(expires_at) if expires_at else None},
                )

                return assignment

        except ValidationError as e:
            logger.error("Validation failed during role assignment: %s", e.message_dict)
            raise RoleAssignmentException(f"Invalid assignment attributes: {e.message_dict}")

    @classmethod
    def revoke_role(cls, *, user_id: str, role_id: str, actor=None) -> UserRole:
        """
        Revokes a user's role assignment by soft-deactivating it.
        """
        try:
            assignment = UserRole.objects.select_related("role", "user").get(
                user_id=user_id,
                role_id=role_id,
                is_active=True
            )
        except UserRole.DoesNotExist:
            raise RoleAssignmentException(
                f"No active role assignment mapping found for User ID '{user_id}' and Role ID '{role_id}'."
            )

        try:
            with transaction.atomic():
                assignment.is_active = False
                assignment.save()

                logger.warning("Revoked role %s from User %s", assignment.role.slug, assignment.user.email)

                AuditLogService.log(
                    event_type=AuditLog.EventType.ROLE_REMOVED,
                    status=AuditLog.Status.SUCCESS,
                    description=f"Role {assignment.role.slug} revoked from user {assignment.user.email}.",
                    user=actor,
                    resource="UserRole",
                    resource_id=str(assignment.id),
                    metadata={"target_user_id": str(user_id), "role_slug": assignment.role.slug},
                )

                return assignment
        except ValidationError as e:
            raise RoleAssignmentException(f"Validation failed during revocation: {e.message_dict}")

    @classmethod
    def activate_assignment(cls, assignment_id: str) -> UserRole:
        """
        Re-activates a soft-disabled user role assignment.
        """
        try:
            assignment = UserRole.objects.select_related("role").get(id=assignment_id)
        except UserRole.DoesNotExist:
            raise RoleAssignmentException(f"UserRole assignment with ID '{assignment_id}' not found.")

        if not assignment.role.is_active:
            raise RoleAssignmentException(
                f"Cannot activate assignment because the associated role '{assignment.role.slug}' is deactivated."
            )

        try:
            with transaction.atomic():
                assignment.is_active = True
                assignment.save()

                logger.info("Activated assignment ID %s", assignment_id)

                # TODO: Trigger AuditLogService call in a later phase.
                # AuditLogService.log_assignment_activated(assignment_id=assignment_id)

                return assignment
        except ValidationError as e:
            raise RoleAssignmentException(f"Validation failed: {e.message_dict}")

    @classmethod
    def deactivate_assignment(cls, assignment_id: str) -> UserRole:
        """
        Soft-deactivates an active user role assignment.
        """
        try:
            assignment = UserRole.objects.get(id=assignment_id)
        except UserRole.DoesNotExist:
            raise RoleAssignmentException(f"UserRole assignment with ID '{assignment_id}' not found.")

        try:
            with transaction.atomic():
                assignment.is_active = False
                assignment.save()

                logger.warning("Deactivated assignment ID %s", assignment_id)

                # TODO: Trigger AuditLogService call in a later phase.
                # AuditLogService.log_assignment_deactivated(assignment_id=assignment_id)

                return assignment
        except ValidationError as e:
            raise RoleAssignmentException(f"Validation failed: {e.message_dict}")

    @classmethod
    def extend_assignment(cls, assignment_id: str, *, expires_at) -> UserRole:
        """
        Extends or updates the expiration timestamp of an active user role assignment.
        """
        try:
            assignment = UserRole.objects.get(id=assignment_id)
        except UserRole.DoesNotExist:
            raise RoleAssignmentException(f"UserRole assignment with ID '{assignment_id}' not found.")

        if not assignment.is_active:
            raise RoleAssignmentException("Cannot extend a deactivated role assignment.")

        if expires_at and expires_at <= timezone.now():
            raise RoleAssignmentException("New expiration date and time must be in the future.")

        try:
            with transaction.atomic():
                assignment.expires_at = expires_at
                assignment.save()

                logger.info("Extended assignment ID %s to %s", assignment_id, expires_at)

                # TODO: Trigger AuditLogService call in a later phase.
                # AuditLogService.log_assignment_extended(assignment_id=assignment_id, expires_at=expires_at)

                return assignment
        except ValidationError as e:
            raise RoleAssignmentException(f"Validation failed: {e.message_dict}")

    @classmethod
    def expire_assignment(cls, assignment_id: str) -> UserRole:
        """
        Expires an active user role assignment immediately, soft-deactivating access.
        """
        try:
            assignment = UserRole.objects.get(id=assignment_id)
        except UserRole.DoesNotExist:
            raise RoleAssignmentException(f"UserRole assignment with ID '{assignment_id}' not found.")

        try:
            with transaction.atomic():
                assignment.expires_at = timezone.now()
                assignment.is_active = False
                assignment.save()

                logger.warning("Expired assignment ID %s immediately", assignment_id)

                # TODO: Trigger AuditLogService call in a later phase.
                # AuditLogService.log_assignment_expired(assignment_id=assignment_id)

                return assignment
        except ValidationError as e:
            raise RoleAssignmentException(f"Validation failed: {e.message_dict}")

    @classmethod
    def get_user_roles(cls, user_id: str) -> models.QuerySet:
        """
        Retrieves all Roles (active and inactive) historically linked to a User.
        
        Optimized to join role definitions in a single database fetch.
        """
        assignments = UserRole.objects.filter(user_id=user_id).select_related("role")
        role_ids = assignments.values_list("role_id", flat=True)
        return Role.objects.filter(id__in=role_ids)

    @classmethod
    def get_active_roles(cls, user_id: str) -> models.QuerySet:
        """
        Retrieves only the active, unexpired Roles assigned to a User.
        """
        now = timezone.now()
        
        # Optimize query: filter and fetch mapping records with role joins
        assignments = UserRole.objects.filter(
            user_id=user_id,
            is_active=True
        ).filter(
            models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now)
        ).select_related("role")

        role_ids = assignments.values_list("role_id", flat=True)
        return Role.objects.filter(id__in=role_ids)

    @classmethod
    def user_has_role(cls, user_id: str, role_slug: str) -> bool:
        """
        Verifies if a user currently holds an active, unexpired role.
        """
        now = timezone.now()
        
        return UserRole.objects.filter(
            user_id=user_id,
            role__slug=role_slug,
            is_active=True
        ).filter(
            models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now)
        ).exists()

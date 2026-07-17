import logging
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

from apps.authorization.models import Permission, Role, RolePermission, UserRole

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------------------
# Permission Catalog Signals
# ------------------------------------------------------------------------------

@receiver(post_save, sender=Permission)
def permission_post_save(sender, instance, created, **kwargs):
    """
    Signal handler triggered after a Permission catalog capability is saved.
    """
    if created:
        logger.info("Signal: Permission created - %s", instance.code)
        # TODO: Trigger AuditLogService for permission creation
        # AuditLogService.log(
        #     event="permission.created",
        #     actor=None,
        #     target=instance.code,
        #     details={"name": instance.name, "resource": instance.resource, "action": instance.action}
        # )
    else:
        logger.info("Signal: Permission updated - %s (Active: %s)", instance.code, instance.is_active)
        # TODO: Trigger AuditLogService for permission modifications
        # AuditLogService.log(
        #     event="permission.updated",
        #     actor=None,
        #     target=instance.code,
        #     details={"is_active": instance.is_active}
        # )

    # TODO: Trigger CacheService to invalidate active authorization caches referencing this code
    # CacheService.invalidate(f"permission_catalog:{instance.code}")


# ------------------------------------------------------------------------------
# Role Definition Signals
# ------------------------------------------------------------------------------

@receiver(post_save, sender=Role)
def role_post_save(sender, instance, created, **kwargs):
    """
    Signal handler triggered after a Role definition is saved.
    """
    if created:
        logger.info("Signal: Role created - %s", instance.slug)
        # TODO: Trigger AuditLogService for role creation
        # AuditLogService.log(
        #     event="role.created",
        #     actor=None,
        #     target=instance.slug,
        #     details={"name": instance.name, "priority": instance.priority}
        # )
    else:
        logger.info("Signal: Role updated - %s (Active: %s)", instance.slug, instance.is_active)
        # TODO: Trigger AuditLogService for role modifications
        # AuditLogService.log(
        #     event="role.updated",
        #     actor=None,
        #     target=instance.slug,
        #     details={"is_active": instance.is_active}
        # )

    # TODO: Trigger CacheService to invalidate cached details of this role
    # CacheService.invalidate(f"role_definition:{instance.slug}")


# ------------------------------------------------------------------------------
# RolePermission Mapping Signals
# ------------------------------------------------------------------------------

@receiver(post_save, sender=RolePermission)
def role_permission_post_save(sender, instance, created, **kwargs):
    """
    Signal handler triggered after a Permission is assigned/updated on a Role.
    """
    if created:
        logger.info(
            "Signal: Permission %s assigned to Role %s",
            instance.permission.code,
            instance.role.slug
        )
        # TODO: Trigger AuditLogService to log privilege mapping
        # AuditLogService.log(
        #     event="role.permission_assigned",
        #     actor=instance.assigned_by,
        #     target=instance.role.slug,
        #     details={
        #         "permission_code": instance.permission.code,
        #         "reason": instance.assignment_reason
        #     }
        # )
        
        # TODO: Trigger NotificationService if high-priority permission is assigned
        # if instance.permission.code.startswith("admin:"):
        #     NotificationService.notify_security_ops(...)

    # TODO: Trigger CacheService to invalidate cached role permission trees
    # CacheService.invalidate(f"role_permissions:{instance.role.slug}")


@receiver(post_delete, sender=RolePermission)
def role_permission_post_delete(sender, instance, **kwargs):
    """
    Signal handler triggered after a Permission assignment is revoked from a Role.
    """
    logger.info(
        "Signal: Permission %s removed from Role %s",
        instance.permission.code,
        instance.role.slug
    )
    # TODO: Trigger AuditLogService to log privilege revocation
    # AuditLogService.log(
    #     event="role.permission_removed",
    #     actor=None,
    #     target=instance.role.slug,
    #     details={"permission_code": instance.permission.code}
    # )

    # TODO: Trigger CacheService to invalidate cached role permission trees
    # CacheService.invalidate(f"role_permissions:{instance.role.slug}")


# ------------------------------------------------------------------------------
# UserRole Assignment Signals
# ------------------------------------------------------------------------------

@receiver(post_save, sender=UserRole)
def user_role_post_save(sender, instance, created, **kwargs):
    """
    Signal handler triggered after a Role is assigned/updated for a User.
    """
    if created:
        logger.info("Signal: Role %s assigned to User %s", instance.role.slug, instance.user)
        # TODO: Trigger AuditLogService to log membership mapping
        # AuditLogService.log(
        #     event="user.role_assigned",
        #     actor=instance.assigned_by,
        #     target=str(instance.user.id),
        #     details={
        #         "role_slug": instance.role.slug,
        #         "expires_at": str(instance.expires_at) if instance.expires_at else None,
        #         "reason": instance.assignment_reason
        #     }
        # )

        # TODO: Trigger NotificationService to alert user of assignment change
        # NotificationService.notify(
        #     recipient=instance.user,
        #     template="role_assigned",
        #     context={"role_name": instance.role.name, "expires_at": instance.expires_at}
        # )

    # TODO: Trigger CacheService to invalidate access tokens and compiled permission lists for this user
    # CacheService.invalidate(f"user_permissions:{instance.user.id}")


@receiver(post_delete, sender=UserRole)
def user_role_post_delete(sender, instance, **kwargs):
    """
    Signal handler triggered after a Role assignment is revoked from a User.
    """
    logger.info("Signal: Role %s revoked from User %s", instance.role.slug, instance.user)
    # TODO: Trigger AuditLogService to log membership revocation
    # AuditLogService.log(
    #     event="user.role_revoked",
    #     actor=None,
    #     target=str(instance.user.id),
    #     details={"role_slug": instance.role.slug}
    # )

    # TODO: Trigger NotificationService to alert user of revocation
    # NotificationService.notify(
    #     recipient=instance.user,
    #     template="role_revoked",
    #     context={"role_name": instance.role.name}
    # )

    # TODO: Trigger CacheService to invalidate access tokens and compiled permission lists for this user
    # CacheService.invalidate(f"user_permissions:{instance.user.id}")

import logging
from django.core.management.base import BaseCommand
from django.db import transaction

from apps.authorization.constants import PermissionCodes
from apps.authorization.models import Permission

logger = logging.getLogger(__name__)


# Display names keyed by PermissionCodes (canonical codes live only in constants).
PERMISSION_DISPLAY_NAMES = {
    PermissionCodes.USER_CREATE: "Create User",
    PermissionCodes.USER_READ: "Read User",
    PermissionCodes.USER_UPDATE: "Update User",
    PermissionCodes.USER_DELETE: "Delete User",
    PermissionCodes.USER_MANAGE: "Manage Users",
    PermissionCodes.ROLE_CREATE: "Create Role",
    PermissionCodes.ROLE_READ: "Read Role",
    PermissionCodes.ROLE_UPDATE: "Update Role",
    PermissionCodes.ROLE_DELETE: "Delete Role",
    PermissionCodes.ROLE_MANAGE: "Manage Roles",
    PermissionCodes.PERMISSION_CREATE: "Create Permission",
    PermissionCodes.PERMISSION_READ: "Read Permission",
    PermissionCodes.PERMISSION_UPDATE: "Update Permission",
    PermissionCodes.PERMISSION_DELETE: "Delete Permission",
    PermissionCodes.PERMISSION_MANAGE: "Manage Permissions",
    PermissionCodes.SESSION_CREATE: "Create Session",
    PermissionCodes.SESSION_READ: "Read Session",
    PermissionCodes.SESSION_UPDATE: "Update Session",
    PermissionCodes.SESSION_DELETE: "Delete Session",
    PermissionCodes.SESSION_MANAGE: "Manage Sessions",
    PermissionCodes.MFA_CREATE: "Configure MFA",
    PermissionCodes.MFA_READ: "Read MFA Status",
    PermissionCodes.MFA_UPDATE: "Update MFA Configuration",
    PermissionCodes.MFA_DELETE: "Disable MFA",
    PermissionCodes.MFA_MANAGE: "Manage MFA Settings",
    PermissionCodes.ORGANIZATION_CREATE: "Create Organization",
    PermissionCodes.ORGANIZATION_READ: "Read Organization",
    PermissionCodes.ORGANIZATION_UPDATE: "Update Organization",
    PermissionCodes.ORGANIZATION_DELETE: "Delete Organization",
    PermissionCodes.ORGANIZATION_MANAGE: "Manage Organization",
    PermissionCodes.AUDIT_LOG_READ: "Read Audit Logs",
    PermissionCodes.AUDIT_LOG_MANAGE: "Manage Audit Logs",
    PermissionCodes.AUDIT_LOG_EXPORT: "Export Audit Logs",
    PermissionCodes.NOTIFICATION_CREATE: "Create Notification Template",
    PermissionCodes.NOTIFICATION_READ: "Read Notifications",
    PermissionCodes.NOTIFICATION_UPDATE: "Update Notification Template",
    PermissionCodes.NOTIFICATION_DELETE: "Delete Notification Template",
    PermissionCodes.NOTIFICATION_MANAGE: "Manage Notifications System",
    PermissionCodes.NOTIFICATION_EXECUTE: "Send Notifications",
}


def _catalog_permission_codes() -> list[str]:
    """Return every catalog code defined on PermissionCodes."""
    return sorted(
        value
        for key, value in vars(PermissionCodes).items()
        if key.isupper() and isinstance(value, str) and ":" in value
    )


def _parse_permission_code(code: str) -> tuple[str, str]:
    """
    Split a catalog code into (resource_namespace, action).

    Example: ``identity:user:create`` → (``identity:user``, ``create``)
    """
    resource, action = code.rsplit(":", 1)
    return resource, action


class Command(BaseCommand):
    """
    Django Management Command to Seed the Authorization Permission Catalog.

    Seeds exclusively from ``PermissionCodes`` (single source of truth).
    Idempotent, transactional, and safe to re-run in production.
    """

    help = "Idempotently seeds all default system permissions from PermissionCodes."

    def handle(self, *args, **options) -> None:
        self.stdout.write(self.style.WARNING("Bootstrapping Authorization Permission Catalog..."))

        catalog_codes = _catalog_permission_codes()
        missing_names = [code for code in catalog_codes if code not in PERMISSION_DISPLAY_NAMES]
        if missing_names:
            raise SystemExit(
                "PERMISSION_DISPLAY_NAMES is missing entries for: "
                + ", ".join(missing_names)
            )

        total_created = 0
        already_existed = 0
        skipped = 0

        try:
            with transaction.atomic():
                for code in catalog_codes:
                    resource, action = _parse_permission_code(code)
                    name = PERMISSION_DISPLAY_NAMES[code]
                    description = (
                        f"System capability allowing '{action}' operations "
                        f"on resource '{resource}'."
                    )

                    try:
                        permission, created = Permission.objects.get_or_create(
                            code=code,
                            defaults={
                                "name": name,
                                "resource": resource,
                                "action": action,
                                "description": description,
                                "is_system": True,
                                "is_active": True,
                            },
                        )

                        if created:
                            total_created += 1
                            self.stdout.write(self.style.SUCCESS(f"  [+] Created: {code}"))
                        else:
                            already_existed += 1
                            updated = False
                            if not permission.is_system:
                                permission.is_system = True
                                updated = True
                            if not permission.is_active:
                                permission.is_active = True
                                updated = True
                            if permission.name != name:
                                permission.name = name
                                updated = True
                            if permission.description != description:
                                permission.description = description
                                updated = True
                            if permission.resource != resource:
                                permission.resource = resource
                                updated = True
                            if permission.action != action:
                                permission.action = action
                                updated = True

                            if updated:
                                permission.save()
                                self.stdout.write(self.style.SUCCESS(f"  [*] Synchronized: {code}"))

                    except Exception as e:
                        skipped += 1
                        logger.error("Failed to seed permission %s: %s", code, str(e))
                        self.stdout.write(self.style.ERROR(f"  [-] Skipped: {code} (Error: {str(e)})"))

            self.stdout.write("\n" + "=" * 50)
            self.stdout.write(self.style.SUCCESS("Permission Catalog Seeding Complete!"))
            self.stdout.write(f"  Total Created:     {total_created}")
            self.stdout.write(f"  Already Existed:   {already_existed}")
            self.stdout.write(f"  Skipped/Failed:    {skipped}")
            self.stdout.write("=" * 50 + "\n")

        except Exception as transaction_err:
            logger.critical("Critical failure seeding permission catalog: %s", str(transaction_err))
            self.stdout.write(
                self.style.ERROR(f"Transaction rolled back. Seeding aborted: {str(transaction_err)}")
            )

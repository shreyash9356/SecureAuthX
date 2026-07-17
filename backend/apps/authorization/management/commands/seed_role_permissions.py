import logging
from django.core.management.base import BaseCommand
from django.db import transaction

from apps.authorization.constants import PermissionCodes, RoleSlugs
from apps.authorization.models import Role, Permission, RolePermission

logger = logging.getLogger(__name__)

ROLE_PERMISSIONS_MAPPING = {
    RoleSlugs.SUPER_ADMIN: {
        "all": True,
    },
    RoleSlugs.ADMIN: {
        "all": False,
        "permissions": [
            PermissionCodes.USER_CREATE,
            PermissionCodes.USER_READ,
            PermissionCodes.USER_UPDATE,
            PermissionCodes.USER_DELETE,
            PermissionCodes.USER_MANAGE,
            PermissionCodes.ROLE_CREATE,
            PermissionCodes.ROLE_READ,
            PermissionCodes.ROLE_UPDATE,
            PermissionCodes.ROLE_DELETE,
            PermissionCodes.ROLE_MANAGE,
            PermissionCodes.ORGANIZATION_CREATE,
            PermissionCodes.ORGANIZATION_READ,
            PermissionCodes.ORGANIZATION_UPDATE,
            PermissionCodes.ORGANIZATION_DELETE,
            PermissionCodes.ORGANIZATION_MANAGE,
            PermissionCodes.NOTIFICATION_CREATE,
            PermissionCodes.NOTIFICATION_READ,
            PermissionCodes.NOTIFICATION_UPDATE,
            PermissionCodes.NOTIFICATION_DELETE,
            PermissionCodes.NOTIFICATION_MANAGE,
            PermissionCodes.NOTIFICATION_EXECUTE,
            PermissionCodes.AUDIT_LOG_READ,
        ],
    },
    RoleSlugs.MANAGER: {
        "all": False,
        "permissions": [
            PermissionCodes.USER_READ,
            PermissionCodes.USER_UPDATE,
            PermissionCodes.SESSION_READ,
            PermissionCodes.ORGANIZATION_READ,
            PermissionCodes.NOTIFICATION_READ,
        ],
    },
    RoleSlugs.EMPLOYEE: {
        "all": False,
        "permissions": [
            PermissionCodes.USER_READ,
            PermissionCodes.SESSION_READ,
            PermissionCodes.NOTIFICATION_READ,
        ],
    },
}


class Command(BaseCommand):
    """
    Django Management Command to Seed Role-Permission Mappings.
    
    Establishes role privileges cleanly, transactionally, and idempotently
    following the Principle of Least Privilege.
    """
    help = "Idempotently maps permission catalog capabilities to seeded system roles."

    def handle(self, *args, **options) -> None:
        self.stdout.write(self.style.WARNING("Bootstrapping Role-Permission Mappings..."))

        total_mapped = 0
        already_mapped = 0
        skipped = 0

        try:
            with transaction.atomic():
                for role_slug, rules in ROLE_PERMISSIONS_MAPPING.items():
                    try:
                        role = Role.objects.get(slug=role_slug)
                    except Role.DoesNotExist:
                        self.stdout.write(
                            self.style.ERROR(f"  [-] Role '{role_slug}' not found. Run 'seed_roles' first.")
                        )
                        skipped += 1
                        continue

                    # Determine target permissions
                    if rules.get("all", False):
                        target_permissions = Permission.objects.all()
                    else:
                        perm_codes = rules.get("permissions", [])
                        target_permissions = Permission.objects.filter(code__in=perm_codes)

                        # Check for missing codes
                        found_codes = set(target_permissions.values_list("code", flat=True))
                        missing_codes = set(perm_codes) - found_codes
                        for missing in missing_codes:
                            self.stdout.write(
                                self.style.WARNING(
                                    f"  [!] Warning: Code '{missing}' is missing from catalog. Run 'seed_permissions' first."
                                )
                            )

                    self.stdout.write(f"  Mapping privileges for role: {role.name} ({role.slug})...")

                    for permission in target_permissions:
                        try:
                            # Use get_or_create to prevent duplicate capability associations
                            mapping, created = RolePermission.objects.get_or_create(
                                role=role,
                                permission=permission,
                                defaults={
                                    "is_active": True,
                                    "assignment_reason": f"System default bootstrap configuration mapping for role '{role_slug}'."
                                }
                            )

                            if created:
                                total_mapped += 1
                                self.stdout.write(
                                    self.style.SUCCESS(f"    [+] Mapped: {permission.code} to {role.slug}")
                                )
                            else:
                                already_mapped += 1
                                if not mapping.is_active:
                                    mapping.is_active = True
                                    mapping.save()
                                    self.stdout.write(
                                        self.style.SUCCESS(f"    [*] Activated: {permission.code} to {role.slug}")
                                    )

                        except Exception as e:
                            skipped += 1
                            logger.error(
                                "Failed to map permission %s to role %s: %s",
                                permission.code,
                                role_slug,
                                str(e)
                            )
                            self.stdout.write(
                                self.style.ERROR(
                                    f"    [-] Skipped mapping: {permission.code} to {role.slug} (Error: {str(e)})"
                                )
                            )

            # Report Summary
            self.stdout.write("\n" + "=" * 50)
            self.stdout.write(self.style.SUCCESS("Role-Permission Mappings Seeded Successfully!"))
            self.stdout.write(f"  Total Mappings Created:    {total_mapped}")
            self.stdout.write(f"  Already Mapped:            {already_mapped}")
            self.stdout.write(f"  Skipped/Failed Mappings:   {skipped}")
            self.stdout.write("=" * 50 + "\n")

        except Exception as transaction_err:
            logger.critical("Critical failure mapping role permissions: %s", str(transaction_err))
            self.stdout.write(self.style.ERROR(f"Transaction rolled back. Seeding aborted: {str(transaction_err)}"))

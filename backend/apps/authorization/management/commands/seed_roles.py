import logging
from django.core.management.base import BaseCommand
from django.db import transaction

from apps.authorization.constants import RoleSlugs
from apps.authorization.models import Role

logger = logging.getLogger(__name__)

ROLES_SCHEMA = [
    {
        "name": "Super Administrator",
        "slug": RoleSlugs.SUPER_ADMIN,
        "description": "System-defined root administrator with full unrestricted access to all domains.",
        "priority": 1000,
        "is_system": True,
        "is_active": True
    },
    {
        "name": "Administrator",
        "slug": RoleSlugs.ADMIN,
        "description": "System-defined administrator with operational capabilities across resources.",
        "priority": 800,
        "is_system": True,
        "is_active": True
    },
    {
        "name": "Manager",
        "slug": RoleSlugs.MANAGER,
        "description": "System-defined manager with standard operations and management read capabilities.",
        "priority": 500,
        "is_system": True,
        "is_active": True
    },
    {
        "name": "Employee",
        "slug": RoleSlugs.EMPLOYEE,
        "description": "System-defined employee role with basic access to profiles and notifications.",
        "priority": 100,
        "is_system": True,
        "is_active": True
    }
]


class Command(BaseCommand):
    """
    Django Management Command to Seed the Enterprise Roles.
    
    Bootstraps Super Administrator, Administrator, Manager, and Employee
    roles cleanly and idempotently.
    """
    help = "Idempotently seeds all default system roles."

    def handle(self, *args, **options) -> None:
        self.stdout.write(self.style.WARNING("Bootstrapping Enterprise Roles..."))

        total_created = 0
        already_existed = 0
        skipped = 0

        try:
            with transaction.atomic():
                for role_data in ROLES_SCHEMA:
                    name = role_data["name"]
                    slug = role_data["slug"]
                    description = role_data["description"]
                    priority = role_data["priority"]

                    try:
                        # Use get_or_create to enforce complete idempotency
                        role, created = Role.objects.get_or_create(
                            slug=slug,
                            defaults={
                                "name": name,
                                "description": description,
                                "priority": priority,
                                "is_system": True,
                                "is_active": True
                            }
                        )

                        if created:
                            total_created += 1
                            self.stdout.write(self.style.SUCCESS(f"  [+] Created: {name} (slug: {slug})"))
                        else:
                            already_existed += 1
                            # Update system values if they are out of sync
                            updated = False
                            if not role.is_system:
                                role.is_system = True
                                updated = True
                            if not role.is_active:
                                role.is_active = True
                                updated = True
                            if role.name != name:
                                role.name = name
                                updated = True
                            if role.description != description:
                                role.description = description
                                updated = True
                            if role.priority != priority:
                                role.priority = priority
                                updated = True

                            if updated:
                                role.save()
                                self.stdout.write(self.style.SUCCESS(f"  [*] Synchronized: {name}"))

                    except Exception as e:
                        skipped += 1
                        logger.error("Failed to seed role %s: %s", slug, str(e))
                        self.stdout.write(self.style.ERROR(f"  [-] Skipped: {name} (Error: {str(e)})"))

            # Report summary
            self.stdout.write("\n" + "=" * 50)
            self.stdout.write(self.style.SUCCESS("Role Seeding Complete!"))
            self.stdout.write(f"  Total Created:     {total_created}")
            self.stdout.write(f"  Already Existed:   {already_existed}")
            self.stdout.write(f"  Skipped/Failed:    {skipped}")
            self.stdout.write("=" * 50 + "\n")

        except Exception as transaction_err:
            logger.critical("Critical failure seeding roles: %s", str(transaction_err))
            self.stdout.write(self.style.ERROR(f"Transaction rolled back. Seeding aborted: {str(transaction_err)}"))

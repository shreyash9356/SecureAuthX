from django.contrib import admin
from django.contrib.auth import get_user_model
from .models import Role, Permission, RolePermission, UserRole

User = get_user_model()


class RolePermissionInline(admin.TabularInline):
    """
    Inline admin representation for RolePermission mapping.
    Enables managing permission catalog assignments on the Role change view.
    """
    model = RolePermission
    extra = 1
    autocomplete_fields = ["permission", "assigned_by"]
    readonly_fields = ["assigned_by", "created_at", "updated_at"]
    fields = ("permission", "assignment_reason", "is_active", "assigned_by")
    verbose_name = "Assigned Permission"
    verbose_name_plural = "Assigned Permissions"


class UserRoleInline(admin.TabularInline):
    """
    Inline admin representation for UserRole assignments.
    Enables managing role allocations on the User change view.
    """
    model = UserRole
    fk_name = "user"
    extra = 1
    autocomplete_fields = ["role", "assigned_by"]
    readonly_fields = ["assigned_by", "assigned_at", "created_at", "updated_at"]
    fields = ("role", "assignment_reason", "expires_at", "is_active", "assigned_by")
    verbose_name = "Assigned Role"
    verbose_name_plural = "Assigned Roles"


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    """
    Admin configuration for the Role model.
    Exposes nested permission mapping using TabularInline.
    """
    list_display = (
        "name",
        "slug",
        "priority",
        "is_system",
        "is_active",
        "created_at",
    )
    search_fields = (
        "name",
        "slug",
    )
    list_filter = (
        "is_system",
        "is_active",
    )
    ordering = (
        "-priority",
        "name",
    )
    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
    )
    inlines = [RolePermissionInline]

    def save_formset(self, request, form, formset, change):
        """
        Audit hook to assign the logged-in administrator to RolePermission inline additions.
        """
        instances = formset.save(commit=False)
        for obj in formset.deleted_objects:
            obj.delete()
        for instance in instances:
            if isinstance(instance, RolePermission) and not instance.assigned_by_id:
                instance.assigned_by = request.user
            instance.save()
        formset.save_m2m()


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    """
    Admin configuration for the Permission catalog model.
    """
    list_display = (
        "name",
        "code",
        "resource",
        "action",
        "is_system",
        "is_active",
    )
    search_fields = (
        "name",
        "code",
        "resource",
        "action",
    )
    list_filter = (
        "is_system",
        "is_active",
        "resource",
    )
    ordering = (
        "resource",
        "action",
    )
    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
    )


@admin.register(RolePermission)
class RolePermissionAdmin(admin.ModelAdmin):
    """
    Admin configuration for explicit Role-Permission mappings.
    """
    list_display = (
        "role",
        "permission",
        "is_active",
        "assigned_by",
        "created_at",
    )
    search_fields = (
        "role__name",
        "role__slug",
        "permission__code",
        "permission__name",
        "assignment_reason",
    )
    list_filter = (
        "is_active",
        "role",
        "permission",
    )
    ordering = (
        "role",
        "permission",
    )
    autocomplete_fields = (
        "role",
        "permission",
        "assigned_by",
    )
    readonly_fields = (
        "id",
        "assigned_by",
        "created_at",
        "updated_at",
    )
    # Database optimization: use select_related to prevent N+1 queries in Django Admin list view
    list_select_related = (
        "role",
        "permission",
        "assigned_by",
    )

    def save_model(self, request, obj, form, change):
        """
        Audit hook to assign the logged-in administrator as the assigning user.
        """
        if not obj.assigned_by_id:
            obj.assigned_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    """
    Admin configuration for User-Role assignments.
    """
    list_display = (
        "user",
        "role",
        "is_active",
        "assigned_by",
        "assigned_at",
        "expires_at",
    )
    search_fields = (
        "user__email",
        "user__username",
        "role__name",
        "assignment_reason",
    )
    list_filter = (
        "is_active",
        "role",
        "assigned_at",
        "expires_at",
    )
    ordering = (
        "user",
        "role",
    )
    autocomplete_fields = (
        "user",
        "role",
        "assigned_by",
    )
    readonly_fields = (
        "id",
        "assigned_by",
        "assigned_at",
        "created_at",
        "updated_at",
    )
    # Database optimization: use select_related to prevent N+1 queries in Django Admin list view
    list_select_related = (
        "user",
        "role",
        "assigned_by",
    )

    def save_model(self, request, obj, form, change):
        """
        Audit hook to assign the logged-in administrator as the assigning user.
        """
        if not obj.assigned_by_id:
            obj.assigned_by = request.user
        super().save_model(request, obj, form, change)
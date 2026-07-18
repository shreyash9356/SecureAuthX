from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .forms import CustomUserCreationForm, CustomUserChangeForm
from apps.authorization.admin import UserRoleInline

from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """
    Admin configuration for the custom User model.
    """
    form = CustomUserChangeForm
    add_form = CustomUserCreationForm
    inlines = [UserRoleInline]

    list_display = (
        "email",
        "first_name",
        "last_name",
        "is_staff",
        "is_active",
        "is_verified",
        "is_locked",
        "created_at",
    )

    list_filter = (
        "is_staff",
        "is_active",
        "is_verified",
        "is_locked",
    )

    search_fields = (
        "email",
        "first_name",
        "last_name",
        "username",
    )

    ordering = ("email",)

    readonly_fields = (
        "created_at",
        "updated_at",
        "last_login",
        "password_changed_at",
    )

    fieldsets = (
        (
            "Login",
            {
                "fields": (
                    "email",
                    "password",
                ),
            },
        ),
        (
            "Personal Information",
            {
                "fields": (
                    "first_name",
                    "last_name",
                    "username",
                ),
            },
        ),
        (
            "Security",
            {
                "fields": (
                    "failed_login_attempts",
                    "password_changed_at",
                    "is_verified",
                    "is_locked",
                ),
            },
        ),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        (
            "Audit",
            {
                "fields": (
                    "last_login",
                    "created_at",
                    "updated_at",
                ),
            },
        ),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "password1",
                    "password2",
                    "is_staff",
                    "is_active",
                ),
            },
        ),
    )

    def save_formset(self, request, form, formset, change):
        """
        Audit hook to assign the logged-in administrator to UserRole inline additions.
        """
        instances = formset.save(commit=False)
        for obj in formset.deleted_objects:
            obj.delete()
        for instance in instances:
            if hasattr(instance, "assigned_by") and not instance.assigned_by_id:
                instance.assigned_by = request.user
            instance.save()
        formset.save_m2m()




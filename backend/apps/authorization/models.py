import uuid
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator, RegexValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class Permission(models.Model):
    """
    Authorization Permission Catalog Model.
    
    Serves as the registry of all security capabilities and operations across the system.
    Each capability is bound to a specific resource namespace and action verb, and uniquely
    identified by a formatted permission code.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text=_("Unique identifier for this permission capability."),
    )
    name = models.CharField(
        max_length=100,
        help_text=_("Human-readable label for administrators."),
    )
    code = models.CharField(
        max_length=100,
        unique=True,
        db_index=True,
        validators=[
            RegexValidator(
                regex=r"^[a-z0-9_:-]+$",
                message=_(
                    "Permission code must contain only lowercase letters, numbers, underscores, colons, or hyphens."
                ),
                code="invalid_permission_code",
            )
        ],
        help_text=_("Machine-readable capability identifier (e.g., identity:user:create)."),
    )
    resource = models.CharField(
        max_length=100,
        db_index=True,
        validators=[
            RegexValidator(
                regex=r"^[a-z0-9_:-]+$",
                message=_(
                    "Resource namespace must contain only lowercase letters, numbers, underscores, colons, or hyphens."
                ),
                code="invalid_resource_namespace",
            )
        ],
        help_text=_("Resource classification namespace (e.g., identity:user, organization, audit:log)."),
    )
    action = models.CharField(
        max_length=100,
        db_index=True,
        validators=[
            RegexValidator(
                regex=r"^[a-z0-9_-]+$",
                message=_(
                    "Action verb must contain only lowercase letters, numbers, underscores, or hyphens."
                ),
                code="invalid_action_verb",
            )
        ],
        help_text=_("Standard action verb (e.g., create, read, update, delete, manage, execute)."),
    )
    description = models.TextField(
        blank=True,
        null=True,
        help_text=_("Details about the scope, security implications, and impact of this capability."),
    )
    is_system = models.BooleanField(
        default=False,
        help_text=_("Flag indicating if this is an immutable system-defined permission."),
    )
    is_active = models.BooleanField(
        default=True,
        help_text=_("Soft-disable flag for administrative revocation without breaking relations."),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_("Timestamp when the permission was registered."),
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text=_("Timestamp when the permission definition was last updated."),
    )

    class Meta:
        db_table = "authx_permissions"
        verbose_name = _("Permission")
        verbose_name_plural = _("Permissions")
        ordering = ["resource", "action"]
        constraints = [
            models.UniqueConstraint(
                fields=["resource", "action"],
                name="unique_resource_action",
            )
        ]

    def __str__(self):
        return f"{self.code} ({'Active' if self.is_active else 'Disabled'})"

    def clean(self):
        """
        Validate semantic consistency of the catalog entry.
        Enforces that permission code matches the resource and action namespace.
        """
        super().clean()

        # Enforce that code, resource, and action are in sync
        if self.resource and self.action:
            expected_code = f"{self.resource}:{self.action}"
            if self.code and self.code != expected_code:
                raise ValidationError(
                    {
                        "code": _(
                            f"Permission code must match resource and action namespace. Expected: '{expected_code}'"
                        )
                    }
                )

    def save(self, *args, **kwargs):
        """
        Overridden save method to guarantee that data cleanliness is enforced
        before committing the transaction to the database.
        """
        self.full_clean()
        super().save(*args, **kwargs)


class Role(models.Model):
    """
    Enterprise Role Model.
    
    Represents job functions, operational duties, or capability scopes assigned to users.
    Each role contains a unique name and slug, and holds a priority ordering value for
    administrative precedence sorting.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text=_("Unique identifier for this role."),
    )
    name = models.CharField(
        max_length=100,
        unique=True,
        db_index=True,
        help_text=_("Human-readable label for the role (e.g., Administrator, HR Manager)."),
    )
    slug = models.SlugField(
        max_length=100,
        unique=True,
        db_index=True,
        validators=[
            RegexValidator(
                regex=r"^[a-z0-9_-]+$",
                message=_(
                    "Role slug must contain only lowercase letters, numbers, underscores, or hyphens."
                ),
                code="invalid_role_slug",
            )
        ],
        help_text=_("URL-safe, machine-readable unique identifier for the role."),
    )
    description = models.TextField(
        blank=True,
        null=True,
        help_text=_("Details about the duties, operational scope, and purpose of this role."),
    )
    priority = models.PositiveIntegerField(
        default=0,
        validators=[MinValueValidator(0)],
        help_text=_("Precedence ranking for administrative priority and resolution purposes."),
    )
    is_system = models.BooleanField(
        default=False,
        help_text=_("Flag indicating if this is a built-in immutable system role."),
    )
    is_active = models.BooleanField(
        default=True,
        help_text=_("Soft-disable flag for administrative revocation without deleting database records."),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_("Timestamp when the role was created."),
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text=_("Timestamp when the role definition was last updated."),
    )

    class Meta:
        db_table = "authx_roles"
        verbose_name = _("Role")
        verbose_name_plural = _("Roles")
        ordering = ["-priority", "name"]

    def __str__(self):
        return f"{self.name} ({self.slug})"

    def clean(self):
        """
        Validate and sanitize role attributes.
        """
        super().clean()
        if self.name:
            self.name = self.name.strip()
        if self.slug:
            self.slug = self.slug.strip().lower()

    def save(self, *args, **kwargs):
        """
        Overridden save method to guarantee validation checks are run.
        """
        self.full_clean()
        super().save(*args, **kwargs)


class RolePermission(models.Model):
    """
    Enterprise RolePermission Mapping Model.
    
    Acts as the explicit relationship entity mapping Role and Permission catalog items.
    Tracks mapping metadata, audit parameters, active status, and reasons for privilege grant
    to support enterprise governance and access reviews.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text=_("Unique identifier for this role-permission mapping."),
    )
    role = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        related_name="role_permissions",
        help_text=_("The role receiving the capability mapping."),
    )
    permission = models.ForeignKey(
        Permission,
        on_delete=models.RESTRICT,
        related_name="permission_roles",
        help_text=_("The permission catalog capability mapped to the role."),
    )
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_role_permissions",
        help_text=_("The administrative user who mapped this capability to the role."),
    )
    assignment_reason = models.TextField(
        blank=True,
        null=True,
        help_text=_("Justification for this permission assignment, required for compliance."),
    )
    is_active = models.BooleanField(
        default=True,
        help_text=_("Indicates whether this specific capability mapping is currently active."),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_("Timestamp when this mapping was established."),
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text=_("Timestamp when this mapping definition was last modified."),
    )

    class Meta:
        db_table = "authx_role_permissions"
        verbose_name = _("Role Permission")
        verbose_name_plural = _("Role Permissions")
        ordering = ["role", "permission"]
        indexes = [
            models.Index(fields=["role", "is_active"], name="idx_role_active_perms"),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["role", "permission"],
                name="unique_role_permission",
            )
        ]

    def __str__(self):
        return f"{self.role.name} → {self.permission.code} ({'Active' if self.is_active else 'Inactive'})"

    def clean(self):
        """
        Validate mapping attributes.
        Ensures permissions are not mapped to inactive roles (safeguard).
        """
        super().clean()
        
        # Enforce that permissions cannot be assigned to inactive roles
        if self.role_id and not self.role.is_active:
            raise ValidationError(
                {"role": _("Cannot map permissions to an inactive role.")}
            )

    def save(self, *args, **kwargs):
        """
        Overridden save method to guarantee that data validation is executed.
        """
        self.full_clean()
        super().save(*args, **kwargs)


class UserRole(models.Model):
    """
    Enterprise UserRole Assignment Model.
    
    Represents the mapping of one or more Roles to an Identity (User).
    Stores assignment audit headers, reason details, temporal parameters (expiry time),
    and active status flags to satisfy regulatory security compliance.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text=_("Unique identifier for this user-role assignment."),
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="user_roles",
        help_text=_("The user receiving the role assignment."),
    )
    role = models.ForeignKey(
        Role,
        on_delete=models.RESTRICT,
        related_name="role_users",
        help_text=_("The role assigned to the user."),
    )
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_user_roles",
        help_text=_("The administrator user who performed the assignment."),
    )
    assignment_reason = models.TextField(
        blank=True,
        null=True,
        help_text=_("Reason/justification for allocating this role to the user."),
    )
    assigned_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_("Timestamp when the assignment was originally made."),
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("Expiration timestamp for temporary or Just-in-Time (JIT) access grants."),
    )
    is_active = models.BooleanField(
        default=True,
        help_text=_("Indicates whether this role membership is currently active."),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_("Audit creation timestamp."),
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text=_("Audit modification timestamp."),
    )

    class Meta:
        db_table = "authx_user_roles"
        verbose_name = _("User Role")
        verbose_name_plural = _("User Roles")
        ordering = ["user", "role"]
        indexes = [
            models.Index(fields=["user"], name="idx_user_role_user"),
            models.Index(fields=["role"], name="idx_user_role_role"),
            models.Index(fields=["is_active"], name="idx_user_role_active"),
            models.Index(fields=["expires_at"], name="idx_user_role_expires"),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "role"],
                condition=models.Q(is_active=True),
                name="unique_active_user_role",
            )
        ]

    def __str__(self):
        # We handle case where user is soft-deleted or unavailable
        user_display = getattr(self.user, "email", str(self.user_id))
        return f"{user_display} → {self.role.name}"

    def clean(self):
        """
        Validate user-role mapping details.
        Ensures expiration times are set in the future.
        """
        super().clean()

        if self.expires_at and self.expires_at <= timezone.now():
            raise ValidationError(
                {"expires_at": _("Expiration date and time must be in the future.")}
            )

    def save(self, *args, **kwargs):
        """
        Overridden save method to guarantee data sanity.
        """
        self.full_clean()
        super().save(*args, **kwargs)

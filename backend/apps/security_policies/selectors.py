from typing import Optional
from django.db.models import QuerySet
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model

from apps.security_policies.models import SecurityPolicy, PasswordHistory
from apps.organizations.models import Organization, OrganizationMembership
from apps.organizations.constants import MembershipStatus

User = get_user_model()


def get_global_security_policy() -> SecurityPolicy:
    """
    Retrieve or initialize the active global default security policy.
    """
    policy, _ = SecurityPolicy.objects.get_or_create(
        organization=None,
        defaults={
            "name": "Global Default Security Policy",
            "is_active": True,
            "min_password_length": 12,
            "max_password_length": 128,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numeric": True,
            "require_special_char": True,
            "password_history_count": 5,
            "password_expiration_days": 90,
            "max_failed_login_attempts": 5,
            "lockout_duration_minutes": 15,
            "auto_unlock_enabled": True,
            "max_concurrent_sessions": 5,
            "session_absolute_timeout_minutes": 1440,
            "session_idle_timeout_minutes": 60,
            "force_logout_on_password_change": True,
            "require_mfa_for_admins": True,
            "require_mfa_for_all_org_members": False,
            "mfa_grace_period_days": 7,
        },
    )
    return policy


def get_organization_security_policy(organization: Organization | str) -> Optional[SecurityPolicy]:
    """
    Retrieve the security policy specific to an organization.
    Returns None if no active tenant policy is configured.
    """
    org_id = organization.id if isinstance(organization, Organization) else organization
    return SecurityPolicy.objects.filter(
        organization_id=org_id,
        is_active=True,
    ).first()


def get_user_effective_policy(user, organization: Optional[Organization | str] = None) -> SecurityPolicy:
    """
    Resolves the effective SecurityPolicy for a user context.
    
    Order of precedence:
    1. Specified organization policy (if provided and active)
    2. Primary active organization policy for user
    3. Global default security policy
    """
    if organization:
        tenant_policy = get_organization_security_policy(organization)
        if tenant_policy:
            return tenant_policy

    if hasattr(user, "is_authenticated") and user.is_authenticated:
        membership = OrganizationMembership.objects.filter(
            user=user,
            status=MembershipStatus.ACTIVE,
        ).select_related("organization__security_policy").first()

        if membership and hasattr(membership.organization, "security_policy"):
            policy = membership.organization.security_policy
            if policy and policy.is_active:
                return policy

    return get_global_security_policy()


def get_policy_by_id(policy_id: str) -> SecurityPolicy:
    """
    Retrieve a SecurityPolicy by its UUID identifier.
    """
    return get_object_or_404(SecurityPolicy, id=policy_id)


def get_user_password_history(user, limit: Optional[int] = None) -> QuerySet[PasswordHistory]:
    """
    Fetch historical password hashes for a user, ordered newest first.
    """
    qs = PasswordHistory.objects.filter(user=user).order_by("-created_at", "-id")
    if limit:
        return qs[:limit]
    return qs

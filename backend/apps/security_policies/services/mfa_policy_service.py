import logging
from typing import Any, Optional
from django.utils import timezone
from django.core.exceptions import ValidationError

from apps.security_policies.models import SecurityPolicy
from apps.security_policies.selectors import get_user_effective_policy
from apps.mfa.selectors.mfa_selector import MFASelector

logger = logging.getLogger(__name__)


class MFAPolicyService:
    """
    Enterprise MFA Policy Enforcement Service.
    
    Evaluates administrator MFA mandates, organization-wide member mandates,
    and MFA setup grace periods.
    """

    @classmethod
    def is_mfa_required_for_user(cls, user: Any, organization: Any = None) -> bool:
        """
        Determines whether MFA activation is mandatory for a given user.
        
        Evaluates:
        1. require_mfa_for_admins policy rule if user is staff/admin.
        2. require_mfa_for_all_org_members policy rule for organization members.
        """
        effective_policy = get_user_effective_policy(user, organization)

        if getattr(user, "is_staff", False) or getattr(user, "is_superuser", False):
            if effective_policy.require_mfa_for_admins:
                return True

        if effective_policy.require_mfa_for_all_org_members:
            return True

        return False

    @classmethod
    def evaluate_mfa_grace_period(cls, user: Any, organization: Any = None) -> bool:
        """
        Evaluates whether an un-enrolled user is still within their MFA setup grace period.
        
        Returns:
            True if within grace period, False if grace period has expired (access should be blocked).
        """
        effective_policy = get_user_effective_policy(user, organization)
        grace_days = effective_policy.mfa_grace_period_days

        join_date = getattr(user, "date_joined", timezone.now())
        grace_expiration = join_date + timezone.timedelta(days=grace_days)

        return timezone.now() <= grace_expiration

    @classmethod
    def enforce_mfa_policy_check(cls, user: Any, organization: Any = None) -> None:
        """
        Enforces MFA mandates. If MFA is required and not enabled, checks grace period.
        
        Raises:
            ValidationError if MFA is mandatory and grace period has elapsed.
        """
        if MFASelector.get_active_device_by_user(user):
            return

        if cls.is_mfa_required_for_user(user, organization):
            if not cls.evaluate_mfa_grace_period(user, organization):
                logger.warning("Access denied for user %s: mandatory MFA not configured and grace period expired.", user.email)
                raise ValidationError({"mfa": "Multi-Factor Authentication (MFA) setup is required for your account. Please configure MFA to proceed."})


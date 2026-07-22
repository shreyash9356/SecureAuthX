import logging
from typing import Any, Dict, Optional
from django.db import transaction
from django.core.exceptions import ValidationError

from apps.security_policies.models import SecurityPolicy
from apps.security_policies.selectors import (
    get_global_security_policy,
    get_organization_security_policy,
    get_user_effective_policy,
    get_policy_by_id,
)
from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService

logger = logging.getLogger(__name__)


class SecurityPolicyService:
    """
    Enterprise Security Policy Management Service.
    
    Orchestrates policy lifecycle management, configuration updates, enable/disable toggles,
    and tenant policy inheritance logic.
    """

    @classmethod
    def create_or_update_policy(
        cls,
        *,
        name: str = None,
        organization: Any = None,
        actor: Any = None,
        policy_id: Optional[str] = None,
        **kwargs,
    ) -> SecurityPolicy:
        """
        Creates or updates a SecurityPolicy instance for global default or organization scope.
        """
        try:
            with transaction.atomic():
                if policy_id:
                    policy = get_policy_by_id(policy_id)
                elif organization:
                    policy = get_organization_security_policy(organization)
                    if not policy:
                        policy = SecurityPolicy(organization=organization)
                else:
                    policy = get_global_security_policy()

                if name is not None:
                    policy.name = name.strip()

                for field, value in kwargs.items():
                    if hasattr(policy, field):
                        setattr(policy, field, value)

                policy.full_clean()
                policy.save()

                scope = policy.organization.slug if policy.organization else "Global Default"
                logger.info("Successfully saved SecurityPolicy '%s' [%s] by actor %s", policy.name, scope, getattr(actor, "email", "system"))

                AuditLogService.log(
                    event_type=AuditLog.EventType.ORGANIZATION_UPDATED if policy.organization else AuditLog.EventType.SYSTEM_SETTING_UPDATED if hasattr(AuditLog.EventType, "SYSTEM_SETTING_UPDATED") else AuditLog.EventType.ROLE_UPDATED,
                    status=AuditLog.Status.SUCCESS,
                    description=f"Security Policy '{policy.name}' updated for scope [{scope}].",
                    user=actor,
                    resource="SecurityPolicy",
                    resource_id=str(policy.id),
                    metadata={"policy_id": str(policy.id), "scope": scope},
                )

                return policy

        except ValidationError as e:
            logger.error("Validation error saving SecurityPolicy: %s", e.message_dict)
            raise ValidationError(e.message_dict)

    @classmethod
    def toggle_policy_status(cls, *, policy_id: str, is_active: bool, actor: Any = None) -> SecurityPolicy:
        """
        Enables or disables a SecurityPolicy.
        """
        policy = get_policy_by_id(policy_id)
        
        with transaction.atomic():
            policy.is_active = is_active
            policy.save(update_fields=["is_active", "updated_at"])

            logger.info("SecurityPolicy ID %s set active=%s by actor %s", policy_id, is_active, getattr(actor, "email", "system"))

            AuditLogService.log(
                event_type=AuditLog.EventType.ROLE_UPDATED,
                status=AuditLog.Status.SUCCESS,
                description=f"Security Policy '{policy.name}' {'enabled' if is_active else 'disabled'}.",
                user=actor,
                resource="SecurityPolicy",
                resource_id=str(policy.id),
                metadata={"policy_id": str(policy.id), "is_active": is_active},
            )

        return policy

    @classmethod
    def get_effective_policy(cls, user: Any = None, organization: Any = None) -> SecurityPolicy:
        """
        Retrieves the active effective SecurityPolicy for a user/tenant context.
        """
        return get_user_effective_policy(user, organization)

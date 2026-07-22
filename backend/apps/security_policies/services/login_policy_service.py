import ipaddress
import logging
from typing import Any, Optional
from django.utils import timezone
from django.core.exceptions import ValidationError

from apps.security_policies.models import SecurityPolicy
from apps.security_policies.selectors import get_user_effective_policy
from apps.audit_logs.models import AuditLog
from apps.audit_logs.services import AuditLogService

logger = logging.getLogger(__name__)


class LoginPolicyService:
    """
    Enterprise Network & Temporal Login Policy Enforcement Service.
    
    Evaluates allowed login hours (UTC), IP allowlist/denylist rules (CIDR subnet validation),
    country restrictions, and risk-based security checks.
    """

    @classmethod
    def validate_login_time(cls, organization: Any = None, policy: Optional[SecurityPolicy] = None) -> None:
        """
        Validates current time against allowed login hours window (UTC).
        
        Raises:
            ValidationError if current hour is outside permitted range.
        """
        effective_policy = policy or get_user_effective_policy(None, organization)
        start_hour = effective_policy.allowed_login_start_hour
        end_hour = effective_policy.allowed_login_end_hour

        if start_hour is None or end_hour is None:
            return

        current_hour = timezone.now().hour

        if start_hour <= end_hour:
            allowed = start_hour <= current_hour <= end_hour
        else:
            allowed = current_hour >= start_hour or current_hour <= end_hour

        if not allowed:
            logger.warning("Login attempt blocked due to temporal policy window (%d-%d UTC, current: %d).", start_hour, end_hour, current_hour)
            raise ValidationError({"time": f"Logins are restricted to permitted operating hours ({start_hour}:00 - {end_hour}:00 UTC)."})

    @classmethod
    def validate_ip_address(cls, ip_address_str: str, organization: Any = None, policy: Optional[SecurityPolicy] = None) -> None:
        """
        Validates client IP against policy IP denylist and IP allowlist (supporting single IPs and CIDR ranges).
        
        Raises:
            ValidationError if IP is in denylist or missing from non-empty allowlist.
        """
        if not ip_address_str:
            return

        effective_policy = policy or get_user_effective_policy(None, organization)

        try:
            client_ip = ipaddress.ip_address(ip_address_str)
        except ValueError:
            logger.warning("Invalid IP address format: %s", ip_address_str)
            return

        # 1. Denylist Check
        denylist = effective_policy.ip_denylist or []
        for blocked in denylist:
            try:
                network = ipaddress.ip_network(blocked, strict=False)
                if client_ip in network:
                    logger.warning("Blocked IP %s matched denylist rule %s.", ip_address_str, blocked)
                    raise ValidationError({"ip_address": "Login attempts from your network/IP are restricted by security policy."})
            except ValueError:
                continue

        # 2. Allowlist Check
        allowlist = effective_policy.ip_allowlist or []
        if allowlist:
            permitted = False
            for allowed in allowlist:
                try:
                    network = ipaddress.ip_network(allowed, strict=False)
                    if client_ip in network:
                        permitted = True
                        break
                except ValueError:
                    continue

            if not permitted:
                logger.warning("IP %s rejected: not present in IP allowlist rules.", ip_address_str)
                raise ValidationError({"ip_address": "Login attempts from your IP address are not authorized by enterprise security policy."})

    @classmethod
    def validate_country(cls, country_code: Optional[str], organization: Any = None, policy: Optional[SecurityPolicy] = None) -> None:
        """
        Validates client ISO 2-letter country code against policy country_denylist.
        
        Raises:
            ValidationError if country is explicitly blocked.
        """
        if not country_code:
            return

        effective_policy = policy or get_user_effective_policy(None, organization)
        denylist = effective_policy.country_denylist or []

        if country_code.upper() in [c.upper() for c in denylist]:
            logger.warning("Blocked login from restricted country: %s", country_code)
            raise ValidationError({"country": f"Authentication from location ({country_code}) is restricted by security policy."})

    @classmethod
    def perform_risk_based_login_check(
        cls,
        user: Any,
        ip_address: str,
        user_agent: str,
        country_code: Optional[str] = None,
        organization: Any = None,
    ) -> None:
        """
        Executes a consolidated risk-based evaluation combining time, IP subnet, and country checks.
        """
        policy = get_user_effective_policy(user, organization)

        cls.validate_login_time(organization=organization, policy=policy)
        cls.validate_ip_address(ip_address_str=ip_address, organization=organization, policy=policy)
        cls.validate_country(country_code=country_code, organization=organization, policy=policy)

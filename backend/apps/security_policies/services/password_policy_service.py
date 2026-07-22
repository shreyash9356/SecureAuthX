import re
import logging
from typing import Any, Optional
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone

from apps.security_policies.models import SecurityPolicy, PasswordHistory
from apps.security_policies.selectors import (
    get_user_effective_policy,
    get_user_password_history,
)

logger = logging.getLogger(__name__)


class PasswordPolicyService:
    """
    Enterprise Password Policy Enforcement Service.
    
    Validates password complexity rules (length, uppercase, lowercase, numeric, special characters),
    enforces password reuse prevention using PasswordHistory hashes, and evaluates password expiration.
    """

    @classmethod
    def validate_password_against_policy(
        cls,
        password: str,
        user: Any = None,
        organization: Any = None,
        policy: Optional[SecurityPolicy] = None,
    ) -> None:
        """
        Validates raw password string against effective SecurityPolicy complexity rules.
        
        Raises:
            ValidationError with message dictionary of specific rule violations.
        """
        effective_policy = policy or get_user_effective_policy(user, organization)
        errors = []

        if len(password) < effective_policy.min_password_length:
            errors.append(f"Password must be at least {effective_policy.min_password_length} characters long.")

        if len(password) > effective_policy.max_password_length:
            errors.append(f"Password cannot exceed {effective_policy.max_password_length} characters.")

        if effective_policy.require_uppercase and not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter (A-Z).")

        if effective_policy.require_lowercase and not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter (a-z).")

        if effective_policy.require_numeric and not re.search(r"[0-9]", password):
            errors.append("Password must contain at least one numeric digit (0-9).")

        if effective_policy.require_special_char and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            errors.append("Password must contain at least one special character (!@#$%^&*...).")

        if errors:
            raise ValidationError({"password": errors})

        if user and user.is_authenticated:
            cls.check_password_history_reuse(password, user, policy=effective_policy)

    @classmethod
    def check_password_history_reuse(
        cls,
        password: str,
        user: Any,
        policy: Optional[SecurityPolicy] = None,
    ) -> None:
        """
        Verifies that raw password does not match any of the user's recent N password hashes.
        
        Raises:
            ValidationError if password reuse is detected.
        """
        effective_policy = policy or get_user_effective_policy(user)
        history_limit = effective_policy.password_history_count

        if history_limit <= 0:
            return

        recent_hashes = get_user_password_history(user, limit=history_limit)

        for record in recent_hashes:
            if check_password(password, record.password_hash):
                logger.warning("User %s attempted password reuse matching history ID %s.", user.email, record.id)
                raise ValidationError({"password": "You cannot reuse a recently used password."})

    @classmethod
    def record_password_history(cls, user: Any, raw_or_hashed_password: str) -> PasswordHistory:
        """
        Records a password hash in PasswordHistory and trims entries beyond policy history limit.
        """
        effective_policy = get_user_effective_policy(user)
        
        # If passed string is raw, hash it; if already hashed, use directly
        if raw_or_hashed_password.startswith(("pbkdf2_sha256$", "argon2$", "bcrypt$")):
            p_hash = raw_or_hashed_password
        else:
            p_hash = make_password(raw_or_hashed_password)

        record = PasswordHistory.objects.create(
            user=user,
            password_hash=p_hash,
        )

        # Trim excess history
        limit = effective_policy.password_history_count
        if limit > 0:
            history_ids = PasswordHistory.objects.filter(user=user).order_by("-created_at").values_list("id", flat=True)[limit:]
            if history_ids:
                PasswordHistory.objects.filter(id__in=list(history_ids)).delete()

        logger.info("Recorded password history for user %s (history ID: %s)", user.email, record.id)
        return record

    @classmethod
    def check_password_expiration(cls, user: Any, policy: Optional[SecurityPolicy] = None) -> bool:
        """
        Evaluates whether user password has expired based on policy password_expiration_days.
        
        Returns:
            True if expired, False otherwise.
        """
        effective_policy = policy or get_user_effective_policy(user)
        exp_days = effective_policy.password_expiration_days

        if exp_days <= 0:
            return False

        last_change = getattr(user, "last_password_change", None) or user.date_joined
        expiration_date = last_change + timezone.timedelta(days=exp_days)

        return timezone.now() > expiration_date

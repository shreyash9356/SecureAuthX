"""
Recovery code utility module for Multi-Factor Authentication.
Handles generation and secure hashing of one-time recovery codes.
"""

import secrets
import string
from django.contrib.auth.hashers import make_password, check_password


def generate_recovery_codes(count: int = 10, length: int = 12) -> list[str]:
    """
    Generate a list of cryptographically secure random alphanumeric recovery codes.
    """
    alphabet = string.ascii_uppercase + string.digits
    codes = []
    for _ in range(count):
        code = "".join(secrets.choice(alphabet) for _ in range(length))
        codes.append(code)
    return codes


def hash_recovery_code(code: str) -> str:
    """
    Hash a recovery code using Django's standard credential password hasher.
    """
    return make_password(code)


def check_recovery_code(code: str, hashed_code: str) -> bool:
    """
    Verify a plaintext recovery code against its stored hash.
    """
    return check_password(code, hashed_code)

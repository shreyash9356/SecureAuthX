"""
Cryptographic utility module for the Multi-Factor Authentication (MFA) module.
Handles symmetric encryption and decryption of TOTP secrets.
"""

from django.conf import settings
from cryptography.fernet import Fernet


def _get_fernet() -> Fernet:
    """
    Instantiate and return a Fernet instance using the configured encryption key.
    """
    key = settings.MFA_ENCRYPTION_KEY
    if isinstance(key, str):
        key = key.encode()
    return Fernet(key)


def encrypt_secret(secret_plaintext: str) -> str:
    """
    Encrypt a plaintext TOTP secret key using symmetric Fernet encryption.

    Args:
        secret_plaintext: The raw base32 TOTP secret.

    Returns:
        str: The URL-safe base64-encoded encrypted token.
    """
    if not secret_plaintext:
        return ""
    fernet = _get_fernet()
    encrypted_bytes = fernet.encrypt(secret_plaintext.encode())
    return encrypted_bytes.decode()


def decrypt_secret(secret_ciphertext: str) -> str:
    """
    Decrypt a ciphertext TOTP secret key using symmetric Fernet decryption.

    Args:
        secret_ciphertext: The encrypted base64 string.

    Returns:
        str: The decrypted raw base32 TOTP secret.
    """
    if not secret_ciphertext:
        return ""
    fernet = _get_fernet()
    decrypted_bytes = fernet.decrypt(secret_ciphertext.encode())
    return decrypted_bytes.decode()

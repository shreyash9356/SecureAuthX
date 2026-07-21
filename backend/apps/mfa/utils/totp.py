"""
TOTP utility module for RFC 6238 Multi-Factor Authentication.
Handles secret generation, otpauth URI creation, and replay-safe OTP verification.
"""

from pathlib import Path
import base64
import io
import time
from django.conf import settings
import pyotp
import qrcode


def generate_qr_code_data_uri(provisioning_uri: str) -> str:
    """
    Generate an in-memory PNG QR code image from an otpauth provisioning URI
    and return it as a Base64-encoded Data URI string (data:image/png;base64,...).
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    png_bytes = buffer.getvalue()
    base64_encoded = base64.b64encode(png_bytes).decode("utf-8")
    return f"data:image/png;base64,{base64_encoded}"


def save_dev_qr_code(qr_data_uri: str) -> str | None:
    """
    Development-only utility to decode a Base64 QR Data URI and save it to disk
    at media/dev/mfa_qr.png for easy manual scanning with authenticator apps.

    Guarded by settings.DEBUG to ensure it never executes in production environments.
    """
    if not getattr(settings, "DEBUG", False):
        return None

    if not qr_data_uri or not qr_data_uri.startswith("data:image/png;base64,"):
        return None

    base64_str = qr_data_uri.replace("data:image/png;base64,", "")
    png_bytes = base64.b64decode(base64_str)

    media_root = getattr(settings, "MEDIA_ROOT", None)
    if not media_root:
        return None

    dev_dir = Path(media_root) / "dev"
    dev_dir.mkdir(parents=True, exist_ok=True)
    file_path = dev_dir / "mfa_qr.png"

    with open(file_path, "wb") as f:
        f.write(png_bytes)

    return str(file_path)


def generate_totp_secret() -> str:
    """
    Generate a cryptographically secure random base32 string (32 characters).
    """
    return pyotp.random_base32(length=32)


def get_totp_uri(secret_base32: str, email: str, issuer: str = "SecureAuthX") -> str:
    """
    Generate the standard OTP provisioning URI (otpauth://) for QR code creation.
    """
    totp = pyotp.TOTP(secret_base32)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


def verify_otp(
    secret_base32: str,
    otp_code: str,
    last_used_time_step: int | None = None,
    valid_window: int = 1,
) -> tuple[bool, int]:
    """
    Verify a TOTP code against the secret key, checking for clock drift and
    enforcing strict replay protection.

    Args:
        secret_base32:       The decrypted raw base32 TOTP secret.
        otp_code:            The 6-digit numeric OTP code to verify.
        last_used_time_step: The integer time-step index of the last verified OTP.
        valid_window:        The validation window (defaults to 1, meaning ±30s drift allowed).

    Returns:
        (bool, int): A tuple containing:
                     - bool: True if the code is valid, False otherwise.
                     - int: The matched time-step index (if valid), else 0.
    """
    totp = pyotp.TOTP(secret_base32)
    current_time = int(time.time())
    step_size = 30  # Standard TOTP step size in seconds
    current_step = current_time // step_size

    # Loop through the valid window (current_step - window to current_step + window)
    for i in range(-valid_window, valid_window + 1):
        step = current_step + i
        # Generate the expected OTP code at this time-step
        expected_otp = totp.at(step * step_size)
        if expected_otp == otp_code:
            # Replay protection: ensure the code has not been reused within the current window
            if last_used_time_step is not None and step <= last_used_time_step:
                return False, 0
            return True, step

    return False, 0

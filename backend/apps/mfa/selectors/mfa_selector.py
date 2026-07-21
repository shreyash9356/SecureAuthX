"""
Selectors for the Multi-Factor Authentication (MFA) module.
Only read database queries are allowed here.
"""

from typing import Optional
from django.contrib.auth.models import AbstractBaseUser
from apps.mfa.models import MFADevice, MFARecoveryCode


class MFASelector:
    """
    Selector layer for MFADevice and MFARecoveryCode.
    """

    @staticmethod
    def get_device_by_user(user: AbstractBaseUser) -> Optional[MFADevice]:
        """
        Retrieve the MFA device configuration for a user.

        Returns:
            MFADevice or None: The user's MFA device if configured, else None.
        """
        return MFADevice.objects.filter(user=user).first()

    @staticmethod
    def get_active_device_by_user(user: AbstractBaseUser) -> Optional[MFADevice]:
        """
        Retrieve the MFA device configuration for a user only if it is enabled.

        Returns:
            MFADevice or None: The active MFA device if enabled, else None.
        """
        return MFADevice.objects.filter(user=user, is_enabled=True).first()

    @staticmethod
    def get_device_by_id(device_id: str) -> MFADevice:
        """
        Retrieve an MFA device strictly by its unique ID.

        Raises:
            MFADevice.DoesNotExist: If the device is not found.
        """
        return MFADevice.objects.get(id=device_id)

    @staticmethod
    def list_active_recovery_codes(mfa_device: MFADevice):
        """
        List all unused recovery codes for a given MFA device.
        """
        return MFARecoveryCode.objects.filter(mfa_device=mfa_device, is_used=False)

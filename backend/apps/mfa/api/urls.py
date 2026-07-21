"""
URL configuration for the Multi-Factor Authentication (MFA) API.
"""

from django.urls import path
from apps.mfa.api.views import (
    MFADeviceStatusAPIView,
    MFASetupInitiateAPIView,
    MFAActivationAPIView,
    MFADisableAPIView,
    MFARecoveryCodeRegenerateAPIView,
    MFALoginVerifyAPIView,
    MFAAdminActionAPIView,
)

app_name = "mfa"

urlpatterns = [
    path("status/", MFADeviceStatusAPIView.as_view(), name="mfa-status"),
    path(
        "setup/initiate/",
        MFASetupInitiateAPIView.as_view(),
        name="mfa-setup-initiate",
    ),
    path(
        "setup/activate/",
        MFAActivationAPIView.as_view(),
        name="mfa-setup-activate",
    ),
    path("disable/", MFADisableAPIView.as_view(), name="mfa-disable"),
    path(
        "recovery/regenerate/",
        MFARecoveryCodeRegenerateAPIView.as_view(),
        name="mfa-recovery-regenerate",
    ),
    path("verify/", MFALoginVerifyAPIView.as_view(), name="mfa-login-verify"),
    path("admin/action/", MFAAdminActionAPIView.as_view(), name="mfa-admin-action"),
]

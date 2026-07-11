"""
URL configuration for the SecureAuthX authentication module.
"""

from django.urls import path

from apps.authentication.api.views import (
    ChangePasswordAPIView,
    ForgotPasswordAPIView,
    LoginAPIView,
    LogoutAPIView,
    MeAPIView,
    RefreshTokenAPIView,
    RegistrationAPIView,
    ResendVerificationAPIView,
    ResetPasswordAPIView,
    VerifyEmailAPIView,
)

app_name = "authentication"

urlpatterns = [
    # ── Account creation & identity ───────────────────────────────────────────
    path(
        "register/",
        RegistrationAPIView.as_view(),
        name="register",
    ),
    path(
        "me/",
        MeAPIView.as_view(),
        name="me",
    ),

    # ── Session management ────────────────────────────────────────────────────
    path(
        "login/",
        LoginAPIView.as_view(),
        name="login",
    ),
    path(
        "logout/",
        LogoutAPIView.as_view(),
        name="logout",
    ),
    path(
        "token/refresh/",
        RefreshTokenAPIView.as_view(),
        name="token_refresh",
    ),

    # ── Email verification ────────────────────────────────────────────────────
    path(
        "verify-email/",
        VerifyEmailAPIView.as_view(),
        name="verify_email",
    ),
    path(
        "resend-verification/",
        ResendVerificationAPIView.as_view(),
        name="resend_verification",
    ),

    # ── Password management ───────────────────────────────────────────────────
    path(
        "forgot-password/",
        ForgotPasswordAPIView.as_view(),
        name="forgot_password",
    ),
    path(
        "reset-password/",
        ResetPasswordAPIView.as_view(),
        name="reset_password",
    ),
    path(
        "change-password/",
        ChangePasswordAPIView.as_view(),
        name="change_password",
    ),
]

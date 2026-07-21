from pathlib import Path
from datetime import timedelta
from decouple import config

# ------------------------------------------------------------------------------
# Base Directory
# ------------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# ------------------------------------------------------------------------------
# Security
# ------------------------------------------------------------------------------

SECRET_KEY = config("SECRET_KEY")

DEBUG = config("DEBUG", default=False, cast=bool)

ALLOWED_HOSTS = config(
    "ALLOWED_HOSTS",
    default="127.0.0.1,localhost",
    cast=lambda value: [host.strip() for host in value.split(",")],
)

# ------------------------------------------------------------------------------
# Django Applications
# ------------------------------------------------------------------------------

DJANGO_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

# ------------------------------------------------------------------------------
# Third-Party Applications
# ------------------------------------------------------------------------------

THIRD_PARTY_APPS = [
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "drf_spectacular",
    "django_filters",
    "corsheaders",
]

# ------------------------------------------------------------------------------
# Local Applications
# ------------------------------------------------------------------------------

LOCAL_APPS = [
    "apps.accounts",
    "apps.authentication",
    "apps.authorization",
    "apps.users",
    "apps.roles",
    "apps.permissions",
    "apps.organizations",
    "apps.user_sessions",
    "apps.mfa",
    "apps.audit_logs",
    "apps.notifications",
    "apps.common",
    "apps.core",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

# ------------------------------------------------------------------------------
# Middleware
# ------------------------------------------------------------------------------

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# ------------------------------------------------------------------------------
# URL Configuration
# ------------------------------------------------------------------------------

ROOT_URLCONF = "config.urls"

# ------------------------------------------------------------------------------
# Templates
# ------------------------------------------------------------------------------

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# ------------------------------------------------------------------------------
# SIMPLE_JWT
# ------------------------------------------------------------------------------

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
}
# ------------------------------------------------------------------------------
# WSGI
# ------------------------------------------------------------------------------

WSGI_APPLICATION = "config.wsgi.application"

# ------------------------------------------------------------------------------
# Database (PostgreSQL)
# ------------------------------------------------------------------------------

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": config("POSTGRES_DB"),
        "USER": config("POSTGRES_USER"),
        "PASSWORD": config("POSTGRES_PASSWORD"),
        "HOST": config("POSTGRES_HOST", default="localhost"),
        "PORT": config("POSTGRES_PORT", default=5432, cast=int),
    }
}


# ------------------------------------------------------------------------------
# PASSWORD_HASHERS
# -------------------------------------------------------------------------------


PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

# ==============================================================================
# Email Configuration
# ==============================================================================

EMAIL_BACKEND = config("EMAIL_BACKEND")

EMAIL_HOST = config("EMAIL_HOST")
EMAIL_PORT = config("EMAIL_PORT", cast=int)

EMAIL_USE_TLS = config("EMAIL_USE_TLS", cast=bool)

EMAIL_HOST_USER = config("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD")

DEFAULT_FROM_EMAIL = config("DEFAULT_FROM_EMAIL")


# ------------------------------------------------------------------------------
# AUTH_USER_MODEL
# ------------------------------------------------------------------------------

AUTH_USER_MODEL = "accounts.User"

# ------------------------------------------------------------------------------
# Password Validation
# ------------------------------------------------------------------------------

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# ------------------------------------------------------------------------------
# Internationalization
# ------------------------------------------------------------------------------

LANGUAGE_CODE = "en-us"

TIME_ZONE = "Asia/Kolkata"

USE_I18N = True

USE_TZ = True

# ------------------------------------------------------------------------------
# Static Files
# ------------------------------------------------------------------------------

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# ------------------------------------------------------------------------------
# Media Files
# ------------------------------------------------------------------------------

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# ------------------------------------------------------------------------------
# Default Primary Key
# ------------------------------------------------------------------------------

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ------------------------------------------------------------------------------
# Django REST Framework
# ------------------------------------------------------------------------------

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "EXCEPTION_HANDLER": "apps.core.exceptions.custom_exception_handler",
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 20,
    "DEFAULT_THROTTLE_CLASSES": (
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ),
    "DEFAULT_THROTTLE_RATES": {
        "anon": "100/day",
        "user": "1000/day",
        "login": "5/min",
        "forgot_password": "3/15min",
        "resend_verification": "3/hour",
    },
}
# ------------------------------------------------------------------------------
# CORS
# ------------------------------------------------------------------------------

CORS_ALLOW_ALL_ORIGINS = True


# ------------------------------------------------------------------------------
# Swagger / drf-spectacular
# ------------------------------------------------------------------------------

SPECTACULAR_SETTINGS = {
    # ── Metadata ──────────────────────────────────────────────────────────────
    "TITLE": "SecureAuthX API",
    "DESCRIPTION": (
        "## Overview\n\n"
        "SecureAuthX is an **enterprise-grade Identity and Access Management (IAM)** "
        "platform built with Django REST Framework and React.\n\n"
        "The API provides secure authentication, authorization, user management, "
        "role-based access control (RBAC), multi-factor authentication (MFA), "
        "audit logging, and session management.\n\n"
        "## Authentication\n\n"
        "Most endpoints require a valid **JWT Bearer token**. "
        "Obtain tokens via `POST /api/v1/auth/login/` and include the access token "
        "in the `Authorization` header:\n\n"
        "```\nAuthorization: Bearer <access_token>\n```\n\n"
        "Access tokens expire after **15 minutes**. "
        "Use `POST /api/v1/auth/token/refresh/` to obtain a new access token "
        "using your refresh token.\n\n"
        "## Standards\n\n"
        "- OWASP Top 10\n"
        "- OWASP ASVS Level 2\n"
        "- NIST SP 800-63B\n"
    ),
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    # ── Contact & License ─────────────────────────────────────────────────────
    "CONTACT": {
        "name": "SecureAuthX Team",
        "email": "support@secureauthx.local",
    },
    "LICENSE": {
        "name": "MIT",
    },
    # ── JWT Bearer Security Scheme ────────────────────────────────────────────
    "SECURITY": [
        {
            "BearerAuth": [],
        }
    ],
    "SECURITY_DEFINITIONS": {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": (
                "JWT Bearer token authentication. "
                "Obtain a token via POST /api/v1/auth/login/ "
                "and prefix the value with 'Bearer '."
            ),
        }
    },
    # ── Schema Generation ─────────────────────────────────────────────────────
    "COMPONENT_SPLIT_REQUEST": True,
    "SORT_OPERATIONS": False,
    # ── Tags ordering ─────────────────────────────────────────────────────────
    "TAGS": [
        {
            "name": "Authentication",
            "description": (
                "Endpoints for registration, login, logout, "
                "email verification, and token management."
            ),
        },
        {
            "name": "Password Management",
            "description": (
                "Endpoints for forgot password, password reset via token, "
                "and changing password for authenticated users."
            ),
        },
        {
            "name": "Audit Logs",
            "description": (
                "Read-only audit trail of all security and domain events. "
                "Accessible by staff (admin) users only."
            ),
        },
    ],
}

from django.urls import path
from apps.security_policies.api.views import (
    EffectiveSecurityPolicyAPIView,
    GlobalSecurityPolicyAPIView,
    SecurityPolicyDetailAPIView,
    SecurityPolicyToggleAPIView,
    ValidatePasswordPolicyAPIView,
)

app_name = "security_policies"

urlpatterns = [
    path("effective/", EffectiveSecurityPolicyAPIView.as_view(), name="effective_policy"),
    path("global/", GlobalSecurityPolicyAPIView.as_view(), name="global_policy"),
    path("validate-password/", ValidatePasswordPolicyAPIView.as_view(), name="validate_password"),
    path("<uuid:pk>/", SecurityPolicyDetailAPIView.as_view(), name="detail"),
    path("<uuid:pk>/toggle/", SecurityPolicyToggleAPIView.as_view(), name="toggle"),
]

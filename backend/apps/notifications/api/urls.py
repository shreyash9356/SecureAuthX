from django.urls import path
from apps.notifications.api.views import (
    NotificationListAPIView,
    NotificationDetailAPIView,
    NotificationMarkAsReadAPIView,
    NotificationMarkAllAsReadAPIView,
    NotificationPreferenceAPIView,
)

app_name = "notifications"

urlpatterns = [
    path("", NotificationListAPIView.as_view(), name="list"),
    path("read-all/", NotificationMarkAllAsReadAPIView.as_view(), name="mark_all_as_read"),
    path("preferences/", NotificationPreferenceAPIView.as_view(), name="preferences"),
    path("<uuid:pk>/", NotificationDetailAPIView.as_view(), name="detail"),
    path("<uuid:pk>/read/", NotificationMarkAsReadAPIView.as_view(), name="mark_as_read"),
]

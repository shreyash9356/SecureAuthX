from django.apps import AppConfig


class UserSessionsConfig(AppConfig):
    name = "apps.user_sessions"

    def ready(self) -> None:
        import apps.user_sessions.schema  # noqa

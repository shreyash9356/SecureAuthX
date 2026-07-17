from django.apps import AppConfig


class AuthorizationConfig(AppConfig):
    name = "apps.authorization"

    def ready(self):
        import apps.authorization.signals  

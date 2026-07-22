import logging
from typing import Any, Dict
from django.template import Template, Context
from apps.notifications.models import NotificationChannel
from apps.notifications.selectors import get_notification_template

logger = logging.getLogger(__name__)


class TemplateService:
    """
    Enterprise Template Rendering Service.
    
    Provides placeholder substitution and template rendering using Django's core Template Engine.
    Supports dynamic context variable injection (e.g. {{ first_name }}, {{ organization }}, {{ device }}, {{ ip_address }}).
    """

    @classmethod
    def render_template_string(cls, template_string: str, context: Dict[str, Any]) -> str:
        """
        Renders a raw template string using Django's Template & Context engine.
        
        Args:
            template_string: Raw template string with Django tags/placeholders.
            context: Key-value mapping of dynamic variables.
            
        Returns:
            Rendered string output.
        """
        if not template_string:
            return ""
            
        try:
            django_template = Template(template_string)
            django_context = Context(context or {})
            return django_template.render(django_context)
        except Exception as e:
            logger.error("Template rendering failed: %s", str(e))
            # Fallback to simple format or unrendered string if syntax error occurs
            return template_string

    @classmethod
    def get_and_render_template(
        cls,
        *,
        name: str,
        channel: str = NotificationChannel.EMAIL,
        context: Dict[str, Any] = None,
        default_subject: str = "",
        default_title: str = "",
        default_body: str = "",
    ) -> Dict[str, str]:
        """
        Fetches an active template from the database via Selector layer and renders its
        subject, title, and body attributes using the provided context dictionary.
        
        Falls back to provided default strings if no database template exists.
        
        Returns:
            Dictionary with keys: "subject", "title", "body".
        """
        context = context or {}
        template_obj = get_notification_template(name=name, channel=channel)

        if template_obj:
            subject_str = template_obj.subject
            title_str = template_obj.title
            body_str = template_obj.body
        else:
            subject_str = default_subject
            title_str = default_title
            body_str = default_body

        rendered_subject = cls.render_template_string(subject_str, context)
        rendered_title = cls.render_template_string(title_str, context)
        rendered_body = cls.render_template_string(body_str, context)

        return {
            "subject": rendered_subject,
            "title": rendered_title,
            "body": rendered_body,
        }

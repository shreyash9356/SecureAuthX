import logging
import uuid
from typing import Optional
from django.db import transaction
from django.core.exceptions import ValidationError

from apps.organizations.models import OrganizationSettings
from apps.organizations.selectors import SettingsSelector

logger = logging.getLogger(__name__)


class SettingsService:
    """
    Enterprise Tenant Settings Configuration Service.
    
    Responsible exclusively for the persistence and modification of organization-specific
    preferences, localized configurations (timezones, countries), corporate branding parameters,
    and security session timeouts.
    """

    @classmethod
    def get_settings(cls, organization_id: uuid.UUID | str) -> OrganizationSettings:
        """
        Retrieves the configuration settings instance for the specified organization.
        
        Args:
            organization_id: Unique UUID or string identifier of the target organization.
            
        Returns:
            The associated OrganizationSettings model instance.
            
        Raises:
            OrganizationNotFoundException: If settings for the organization do not exist.
        """
        # Delegating to Selector layer to keep reads decoupled from mutator service responsibilities.
        return SettingsSelector.get_settings_by_organization_id(organization_id)

    @classmethod
    def update_settings(
        cls,
        organization_id: uuid.UUID | str,
        *,
        timezone_str: Optional[str] = None,
        country: Optional[str] = None,
        branding_name: Optional[str] = None,
        logo: Optional[str] = None,
        session_timeout_minutes: Optional[int] = None
    ) -> OrganizationSettings:
        """
        Modifies tenant preferences and session parameters.
        
        Performs updates within an atomic transaction to ensure complete data integrity.
        
        Args:
            organization_id: Unique UUID or string identifier of the target organization.
            timezone_str: Regional timezone (e.g. UTC, America/New_York).
            country: Regional country identifier.
            branding_name: Client-facing tenant name.
            logo: Fully qualified URL to branding logo image.
            session_timeout_minutes: Max active session duration.
            
        Returns:
            The updated OrganizationSettings instance.
            
        Raises:
            OrganizationNotFoundException: If the settings record is missing.
            ValidationError: If configuration options violate field limits or rules.
        """
        settings_obj = cls.get_settings(organization_id)

        try:
            with transaction.atomic():
                if timezone_str is not None:
                    settings_obj.timezone = timezone_str
                if country is not None:
                    settings_obj.country = country
                if branding_name is not None:
                    settings_obj.branding_name = branding_name
                if logo is not None:
                    settings_obj.logo = logo
                if session_timeout_minutes is not None:
                    settings_obj.session_timeout_minutes = session_timeout_minutes

                # Force model-level validation check to catch constraints before DB save
                settings_obj.full_clean()
                settings_obj.save()
                
                # Using UUID only to prevent logging PII metadata
                logger.info("Successfully updated settings for Organization: %s", organization_id)
                return settings_obj
                
        except ValidationError as e:
            logger.error("Validation failed during settings update for organization %s: %s", organization_id, e.message_dict)
            raise ValidationError(e.message_dict)

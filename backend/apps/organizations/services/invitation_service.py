import logging
import uuid
from typing import Any
from django.db import transaction
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.contrib.auth import get_user_model

from apps.authorization.models import Role
from apps.authorization.constants import RoleSlugs
from apps.authorization.exceptions import RoleNotFoundException
from apps.organizations.models import (
    Organization,
    OrganizationMembership,
    OrganizationInvitation,
)
from apps.organizations.constants import (
    MembershipStatus,
    InvitationStatus,
)
from apps.organizations.exceptions import (
    OrganizationNotFoundException,
    InvitationNotFoundException,
    InvitationExpiredException,
    InvitationAlreadyAcceptedException,
    InvalidInvitationStateException,
    MembershipAlreadyExistsException,
)
from apps.organizations.selectors import (
    OrganizationSelector,
    MembershipSelector,
    InvitationSelector,
)

logger = logging.getLogger(__name__)


def _mask_email(email_str: str) -> str:
    """
    Helper to mask email addresses in application logs to protect user PII.
    
    Example: admin@test.com -> a****@test.com
    """
    parts = email_str.split("@")
    if len(parts) == 2:
        local, domain = parts
        masked_local = local[0] + "*" * min(4, len(local) - 1) if len(local) > 1 else "*"
        return f"{masked_local}@{domain}"
    return email_str


class InvitationService:
    """
    Enterprise Tenant Recruitment and Invitation Service.
    
    Coordinates the secure verification of invitation tokens. Enforces TTL limits,
    invalidates legacy tokens, and bridges registration events with tenant access mapping.
    """

    @classmethod
    def invite_member(
        cls,
        *,
        organization_id: uuid.UUID | str,
        email: str,
        invited_by: Any,
        role_slug: str = RoleSlugs.EMPLOYEE,
        expires_in_days: int = 7
    ) -> OrganizationInvitation:
        """
        Generates and registers an invitation record for a prospective user by email address.
        
        Runs inside an atomic transaction block. Invalidates previously pending tokens for this
        email within the target organization to limit replay vectors. If the user account
        already exists in the system database, we pre-register their organization membership
        in PENDING status.
        
        Args:
            organization_id: UUID of the target organization.
            email: Target email address.
            invited_by: User model instance issuing the invitation.
            role_slug: Slug of the role the user will receive upon acceptance.
            expires_in_days: Lifetime duration (TTL) of the invitation link.
            
        Returns:
            The created OrganizationInvitation instance.
            
        Raises:
            OrganizationNotFoundException: If the organization does not exist.
            MembershipAlreadyExistsException: If the user is already a member.
            RoleNotFoundException: If the role slug cannot be resolved.
            ValidationError: If email formats or database constraints fail.
        """
        # Lookup organization via Selector layer
        org = OrganizationSelector.get_organization_by_id(organization_id)

        try:
            role_obj = Role.objects.get(slug=role_slug)
        except Role.DoesNotExist:
            raise RoleNotFoundException(f"Role with slug '{role_slug}' not found.")

        # Guard: Stop processing if the user already holds active or pending membership
        user_model = get_user_model()
        user_opt = user_model.objects.filter(email=email).first()
        if user_opt:
            existing = MembershipSelector.get_user_membership(organization_id=org.id, user_id=user_opt.id)
            if existing:
                if existing.status == MembershipStatus.ACTIVE:
                    raise MembershipAlreadyExistsException(f"User '{user_opt.id}' is already an active member of organization '{org.slug}'.")
                elif existing.status == MembershipStatus.PENDING:
                    if InvitationSelector.has_active_pending_invitation(organization_id=org.id, email=email):
                        raise MembershipAlreadyExistsException(f"User '{user_opt.id}' already has a pending membership in organization '{org.slug}'.")

        try:
            with transaction.atomic():
                # Administrative Revocation of previous pending invitations via selector filter
                InvitationSelector.list_pending_invitations(org.id).filter(email=email).update(
                    status=InvitationStatus.CANCELLED
                )

                expires_at = timezone.now() + timezone.timedelta(days=expires_in_days)
                invitation = OrganizationInvitation(
                    organization=org,
                    email=email,
                    invited_by=invited_by,
                    status=InvitationStatus.PENDING,
                    expires_at=expires_at
                )
                invitation.full_clean()
                invitation.save()

                # If the user already has a system identity, register a placeholder membership
                if user_opt:
                    membership, _ = OrganizationMembership.objects.update_or_create(
                        organization=org,
                        user=user_opt,
                        defaults={
                            "role": role_obj,
                            "status": MembershipStatus.PENDING,
                            "invited_by": invited_by,
                            "joined_at": None
                        }
                    )
                    membership.full_clean()
                    membership.save()

                # Sanitize Logs: Mask email PII and use organization slug
                logger.info("Sent invitation_id: %s to %s for organization: %s (Role: %s)", invitation.id, _mask_email(email), org.slug, role_slug)
                return invitation
                
        except ValidationError as e:
            logger.error("Validation failed during invitation creation: %s", e.message_dict)
            raise ValidationError(e.message_dict)

    @classmethod
    def accept_invitation(cls, *, token: uuid.UUID | str, user: Any) -> OrganizationMembership:
        """
        Validates and accepts a pending organization invitation token.
        
        Enforces security controls including expiration times and email identity verification
        before changing membership status.
        
        Args:
            token: The unique UUID invitation token.
            user: The authenticated User accepting the invitation.
            
        Returns:
            The activated OrganizationMembership model.
            
        Raises:
            InvitationNotFoundException: If the token is invalid.
            InvitationExpiredException: If the token has expired.
            InvitationAlreadyAcceptedException: If the invitation was already accepted.
            InvalidInvitationStateException: If the invitation is cancelled or rejected.
            ValidationError: If email constraints fail.
        """
        # Fetch invitation record via Selector layer
        invitation = InvitationSelector.get_invitation_by_token(token)

        # Guard: Check token lifetime freshness
        if invitation.expires_at <= timezone.now():
            if invitation.status == InvitationStatus.PENDING:
                invitation.status = InvitationStatus.EXPIRED
                invitation.save()
            raise InvitationExpiredException("This invitation has expired.")

        # Guard: Prevent double-spend / reuse of accepted tokens
        if invitation.status == InvitationStatus.ACCEPTED:
            raise InvitationAlreadyAcceptedException("This invitation has already been accepted.")
        elif invitation.status != InvitationStatus.PENDING:
            raise InvalidInvitationStateException(f"Invitation cannot be accepted in its current state: '{invitation.status}'.")

        # Security Guard: Prevent session hijacking (User B accepting User A's token)
        if invitation.email.lower() != user.email.lower():
            raise ValidationError({"email": "This invitation was issued to a different email address."})

        try:
            with transaction.atomic():
                invitation.status = InvitationStatus.ACCEPTED
                invitation.accepted_at = timezone.now()
                invitation.save()

                # Find or instantiate the membership using Selector layer
                membership = MembershipSelector.get_user_membership(
                    organization_id=invitation.organization_id,
                    user_id=user.id
                )

                if membership:
                    # Transition pending status to active
                    membership.status = MembershipStatus.ACTIVE
                    membership.joined_at = timezone.now()
                    membership.invited_by = invitation.invited_by
                    membership.full_clean()
                    membership.save()
                else:
                    # User registered post-invite generation: create initial membership mapping
                    try:
                        role_obj = Role.objects.get(slug=RoleSlugs.EMPLOYEE)
                    except Role.DoesNotExist:
                        raise RoleNotFoundException(f"Core Employee role '{RoleSlugs.EMPLOYEE}' must be seeded first.")

                    membership = OrganizationMembership(
                        organization=invitation.organization,
                        user=user,
                        role=role_obj,
                        status=MembershipStatus.ACTIVE,
                        invited_by=invitation.invited_by,
                        joined_at=timezone.now()
                    )
                    membership.full_clean()
                    membership.save()

                # Sanitize Logs: Use UUIDs and Slugs instead of user emails
                logger.info("User_id: %s successfully accepted invitation_id: %s for organization: %s", user.id, invitation.id, invitation.organization.slug)
                return membership
                
        except ValidationError as e:
            logger.error("Validation failed during invitation acceptance for user %s: %s", user.id, e.message_dict)
            raise ValidationError(e.message_dict)

    @classmethod
    def reject_invitation(cls, *, token: uuid.UUID | str) -> OrganizationInvitation:
        """
        Rejects a pending invitation, rendering the token permanently unusable.
        
        Args:
            token: Unique UUID invitation token.
            
        Returns:
            The updated OrganizationInvitation instance.
            
        Raises:
            InvitationNotFoundException: If the token does not exist.
            InvalidInvitationStateException: If the invitation is not pending.
        """
        # Fetch invitation record via Selector layer
        invitation = InvitationSelector.get_invitation_by_token(token)

        if invitation.status != InvitationStatus.PENDING:
            raise InvalidInvitationStateException(f"Invitation cannot be rejected from state: '{invitation.status}'.")

        invitation.status = InvitationStatus.REJECTED
        invitation.save()
        
        logger.info("Invitation_id: %s has been rejected.", invitation.id)
        return invitation

    @classmethod
    def cancel_invitation(cls, *, invitation_id: uuid.UUID | str, actor: Any) -> OrganizationInvitation:
        """
        Cancels a pending invitation administratively, preventing future acceptance.
        
        Args:
            invitation_id: UUID of the target invitation record.
            actor: User executing the cancellation.
            
        Returns:
            The updated OrganizationInvitation instance.
            
        Raises:
            InvitationNotFoundException: If the invitation does not exist.
            InvalidInvitationStateException: If the invitation is not pending.
        """
        # Fetch invitation record via Selector layer
        invitation = InvitationSelector.get_invitation_by_id(invitation_id)

        if invitation.status != InvitationStatus.PENDING:
            raise InvalidInvitationStateException(f"Invitation cannot be cancelled from state: '{invitation.status}'.")

        invitation.status = InvitationStatus.CANCELLED
        invitation.save()
        
        # Sanitize Logs: Use UUID instead of user email
        logger.info("Invitation %s was cancelled by actor_id: %s", invitation_id, actor.id)
        return invitation

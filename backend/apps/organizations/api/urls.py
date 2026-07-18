from django.urls import path

from apps.organizations.api.views import (
    OrganizationListCreateAPIView,
    OrganizationDetailAPIView,
    SettingsDetailAPIView,
    MembershipListCreateAPIView,
    MembershipRoleUpdateAPIView,
    MembershipStatusUpdateAPIView,
    MembershipDetailAPIView,
    InvitationListCreateAPIView,
    InvitationAcceptAPIView,
    InvitationRejectAPIView,
    InvitationCancelAPIView,
    OwnershipTransferAPIView,
)

app_name = "organizations"

urlpatterns = [
    # Organizations List & Create
    path(
        "",
        OrganizationListCreateAPIView.as_view(),
        name="organization-list-create",
    ),
    # Organization Detail, Update, Delete
    path(
        "<uuid:pk>/",
        OrganizationDetailAPIView.as_view(),
        name="organization-detail",
    ),
    # Organization Settings
    path(
        "<uuid:pk>/settings/",
        SettingsDetailAPIView.as_view(),
        name="settings-detail",
    ),
    # Organization Memberships (List / Add)
    path(
        "<uuid:pk>/members/",
        MembershipListCreateAPIView.as_view(),
        name="membership-list-create",
    ),
    # Organization Membership Role Update
    path(
        "<uuid:pk>/members/<uuid:membership_id>/role/",
        MembershipRoleUpdateAPIView.as_view(),
        name="membership-role-update",
    ),
    # Organization Membership Status Update
    path(
        "<uuid:pk>/members/<uuid:membership_id>/status/",
        MembershipStatusUpdateAPIView.as_view(),
        name="membership-status-update",
    ),
    # Organization Membership Detail / Remove
    path(
        "<uuid:pk>/members/<uuid:membership_id>/",
        MembershipDetailAPIView.as_view(),
        name="membership-detail",
    ),
    # Organization Invitations (List / Create)
    path(
        "<uuid:pk>/invitations/",
        InvitationListCreateAPIView.as_view(),
        name="invitation-list-create",
    ),
    # Organization Invitation Cancel
    path(
        "<uuid:pk>/invitations/<uuid:invitation_id>/cancel/",
        InvitationCancelAPIView.as_view(),
        name="invitation-cancel",
    ),
    # Organization Invitation Accept (Top-level token actions)
    path(
        "invitations/accept/<uuid:token>/",
        InvitationAcceptAPIView.as_view(),
        name="invitation-accept",
    ),
    # Organization Invitation Reject (Top-level token actions)
    path(
        "invitations/reject/<uuid:token>/",
        InvitationRejectAPIView.as_view(),
        name="invitation-reject",
    ),
    # Organization Ownership Transfer
    path(
        "<uuid:pk>/transfer-ownership/",
        OwnershipTransferAPIView.as_view(),
        name="ownership-transfer",
    ),
]

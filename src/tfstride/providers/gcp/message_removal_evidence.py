from __future__ import annotations

from typing import Literal, TypedDict

GcpPubsubMessageRemovalOperation = Literal["pubsub.subscriptions.consume"]
GcpPubsubMessageRemovalOperationClass = Literal["message_acknowledgement"]
GcpPubsubMessageRemovalInternalOperation = Literal["acknowledge_messages"]
GcpPubsubMessageRemovalManagementEffect = Literal["disruption"]
GcpPubsubMessageRemovalTargetGranularity = Literal["subscription_message_namespace"]
GcpPubsubMessageRemovalScopeType = Literal["project", "subscription"]
GcpPubsubActiveCustomRoleStage = Literal[
    "ALPHA",
    "BETA",
    "DEPRECATED",
    "EAP",
    "GA",
]
GcpPubsubCustomRoleGrantScopeCompatibilityState = Literal["compatible", "not_applicable"]
GcpPubsubAcknowledgedMessageReplayState = Literal[
    "retained_by_subscription",
    "retained_by_topic",
    "retained_by_subscription_and_topic",
    "not_established",
    "unknown",
]


class GcpPubsubMessageRemovalDeliveryEvidence(TypedDict):
    delivery_evidence_scope: Literal["pubsub_acknowledged_message_retention_posture"]
    subscription_message_retention_state: Literal[
        "configured",
        "not_configured",
        "unknown",
    ]
    subscription_message_retention_duration: str | None
    subscription_message_retention_seconds: int | None
    subscription_retain_acked_messages: bool | None
    topic_message_retention_state: Literal[
        "configured",
        "not_configured",
        "unknown",
    ]
    topic_message_retention_duration: str | None
    topic_message_retention_seconds: int | None
    acknowledged_message_replay_state: GcpPubsubAcknowledgedMessageReplayState
    replay_authority_evaluated: Literal[False]
    dead_letter_policy_state: Literal[
        "configured",
        "not_configured",
        "unknown",
    ]
    dead_letter_topic: str | None
    dead_letter_max_delivery_attempts: int | None
    dead_letter_policy_is_acknowledgement_recovery: Literal[False]
    uncertainties: list[str]


class GcpCloudRunPubsubMessageAcknowledgementPathCommon(TypedDict):
    workload_address: str
    workload_type: str
    service_account_email: str
    service_account_member: str
    identity_kind: Literal["cloud_run_service_account"]
    credential_context: Literal["workload_runtime"]
    topic_address: str
    topic_resource_type: str
    topic_name: str
    topic_project: str
    topic_reference: str
    subscription_address: str
    subscription_resource_type: str
    subscription_name: str
    subscription_project: str
    subscription_reference: str
    operation: Literal["pubsub.subscriptions.consume"]
    operation_class: Literal["message_acknowledgement"]
    internal_operation: Literal["acknowledge_messages"]
    management_effect: Literal["disruption"]
    target_granularity: Literal["subscription_message_namespace"]
    target_scope: Literal["exact_subscription_message_namespace"]
    target_model_evidence_addresses: list[str]
    acknowledgement_id_source: Literal["runtime_message_delivery"]
    acknowledgement_id_value: None
    iam_resource_address: str
    iam_resource_type: str
    iam_source_addresses: list[str]
    role: str
    role_kind: str
    role_definition_address: str | None
    custom_role_permissions: list[str]
    custom_role_stage: GcpPubsubActiveCustomRoleStage | None
    custom_role_deleted: Literal[False] | None
    custom_role_grant_scope_compatibility_state: GcpPubsubCustomRoleGrantScopeCompatibilityState
    matched_permissions: list[Literal["pubsub.subscriptions.consume"]]
    grant_basis: str
    authorization_state: Literal["granted"]
    policy_complete: Literal[True]
    condition: None
    condition_state: Literal["not_configured"]
    lifecycle_compatibility_state: Literal["not_applicable"]
    delivery_evidence: GcpPubsubMessageRemovalDeliveryEvidence
    posture_uncertainties: list[str]


class GcpCloudRunPubsubProjectMessageAcknowledgementPath(
    GcpCloudRunPubsubMessageAcknowledgementPathCommon,
):
    scope_type: Literal["project"]
    scope: str
    resource_scope: Literal["pubsub_project"]


class GcpCloudRunPubsubSubscriptionMessageAcknowledgementPath(
    GcpCloudRunPubsubMessageAcknowledgementPathCommon,
):
    scope_type: Literal["subscription"]
    scope: str
    resource_scope: Literal["exact_pubsub_subscription"]


GcpCloudRunPubsubMessageRemovalPath = (
    GcpCloudRunPubsubProjectMessageAcknowledgementPath | GcpCloudRunPubsubSubscriptionMessageAcknowledgementPath
)
GcpCloudRunPubsubMessageRemovalEvidence = GcpCloudRunPubsubMessageRemovalPath

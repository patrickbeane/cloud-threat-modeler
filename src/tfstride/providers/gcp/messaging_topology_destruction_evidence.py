from __future__ import annotations

from typing import Literal, Never, TypedDict

GcpPubsubTopologyDestructionOperation = Literal[
    "pubsub.topics.delete",
    "pubsub.subscriptions.delete",
]
GcpPubsubTopologyDestructionOperationClass = Literal[
    "topic_deletion",
    "subscription_deletion",
]
GcpPubsubTopologyDestructionInternalOperation = Literal[
    "delete_topic",
    "delete_subscription",
]
GcpPubsubTopologyDestructionTargetGranularity = Literal[
    "topic_topology",
    "subscription_topology",
]
GcpPubsubTopologyDestructionScopeType = Literal[
    "project",
    "topic",
    "subscription",
]
GcpPubsubTopologyActiveCustomRoleStage = Literal[
    "ALPHA",
    "BETA",
    "DEPRECATED",
    "EAP",
    "GA",
]


class GcpPubsubTopologyBuiltInRoleEvidence(TypedDict):
    role_kind: Literal["owner", "editor", "admin"]
    role_definition_address: None
    custom_role_permissions: list[Never]
    custom_role_stage: None
    custom_role_deleted: None
    custom_role_grant_scope_compatibility_state: Literal["not_applicable"]


class GcpPubsubTopologyCustomRoleEvidence(TypedDict):
    role_kind: Literal["custom"]
    role_definition_address: str
    custom_role_permissions: list[str]
    custom_role_stage: GcpPubsubTopologyActiveCustomRoleStage
    custom_role_deleted: Literal[False]
    custom_role_grant_scope_compatibility_state: Literal["compatible"]


GcpPubsubTopologyRoleEvidence = GcpPubsubTopologyBuiltInRoleEvidence | GcpPubsubTopologyCustomRoleEvidence


class GcpPubsubTopologyDestructionOutcomeEvidence(TypedDict):
    outcome_evidence_scope: Literal["plan_local_pubsub_topology_deletion_authority"]
    successful_deletion_observed: Literal[False]
    recovery_state: Literal["not_established_by_modeled_gcp_messaging_topology_evidence"]
    descendant_impact_evaluated: Literal[False]
    out_of_plan_topology_evaluated: Literal[False]
    uncertainties: list[str]


class GcpCloudRunPubsubTopologyDestructionPathCommon(TypedDict):
    workload_address: str
    workload_type: str
    service_account_email: str
    service_account_member: str
    identity_kind: Literal["cloud_run_service_account"]
    credential_context: Literal["workload_runtime"]
    messaging_resource_address: str
    messaging_resource_type: str
    messaging_resource_name: str
    messaging_resource_project: str
    messaging_resource_reference: str
    target_model_evidence_addresses: list[str]
    management_effect: Literal["disruption"]
    iam_resource_address: str
    iam_resource_type: str
    iam_source_addresses: list[str]
    role: str
    role_evidence: GcpPubsubTopologyRoleEvidence
    authorization_state: Literal["granted"]
    policy_complete: Literal[True]
    iam_manager_ambiguity_state: Literal["not_detected"]
    condition: None
    condition_state: Literal["not_configured"]
    lifecycle_compatibility_state: Literal["not_applicable"]
    outcome_evidence: GcpPubsubTopologyDestructionOutcomeEvidence
    posture_uncertainties: list[str]


class GcpCloudRunPubsubTopicDeletionPathCommon(
    GcpCloudRunPubsubTopologyDestructionPathCommon,
):
    messaging_resource_kind: Literal["topic"]
    operation: Literal["pubsub.topics.delete"]
    operation_class: Literal["topic_deletion"]
    internal_operation: Literal["delete_topic"]
    target_granularity: Literal["topic_topology"]
    target_scope: Literal["exact_pubsub_topic"]
    topic_address: str
    topic_resource_type: str
    topic_name: str
    topic_project: str
    topic_reference: str
    subscription_address: None
    subscription_resource_type: None
    subscription_name: None
    subscription_project: None
    subscription_reference: None
    matched_permissions: list[Literal["pubsub.topics.delete"]]


class GcpCloudRunPubsubSubscriptionDeletionPathCommon(
    GcpCloudRunPubsubTopologyDestructionPathCommon,
):
    messaging_resource_kind: Literal["subscription"]
    operation: Literal["pubsub.subscriptions.delete"]
    operation_class: Literal["subscription_deletion"]
    internal_operation: Literal["delete_subscription"]
    target_granularity: Literal["subscription_topology"]
    target_scope: Literal["exact_pubsub_subscription"]
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
    matched_permissions: list[Literal["pubsub.subscriptions.delete"]]


class GcpCloudRunPubsubProjectTopicDeletionPath(
    GcpCloudRunPubsubTopicDeletionPathCommon,
):
    scope_type: Literal["project"]
    scope: str
    resource_scope: Literal["pubsub_project"]
    grant_basis: Literal["pubsub_project_iam"]


class GcpCloudRunPubsubTopicDeletionPath(
    GcpCloudRunPubsubTopicDeletionPathCommon,
):
    scope_type: Literal["topic"]
    scope: str
    resource_scope: Literal["exact_pubsub_topic"]
    grant_basis: Literal["pubsub_topic_iam"]


class GcpCloudRunPubsubProjectSubscriptionDeletionPath(
    GcpCloudRunPubsubSubscriptionDeletionPathCommon,
):
    scope_type: Literal["project"]
    scope: str
    resource_scope: Literal["pubsub_project"]
    grant_basis: Literal["pubsub_project_iam"]


class GcpCloudRunPubsubSubscriptionDeletionPath(
    GcpCloudRunPubsubSubscriptionDeletionPathCommon,
):
    scope_type: Literal["subscription"]
    scope: str
    resource_scope: Literal["exact_pubsub_subscription"]
    grant_basis: Literal["pubsub_subscription_iam"]


GcpCloudRunPubsubTopologyDestructionPath = (
    GcpCloudRunPubsubProjectTopicDeletionPath
    | GcpCloudRunPubsubTopicDeletionPath
    | GcpCloudRunPubsubProjectSubscriptionDeletionPath
    | GcpCloudRunPubsubSubscriptionDeletionPath
)
GcpCloudRunPubsubTopologyDestructionEvidence = GcpCloudRunPubsubTopologyDestructionPath

from __future__ import annotations

from typing import Literal, Never, TypedDict

AwsSqsMessageRemovalOperation = Literal[
    "sqs:DeleteMessage",
    "sqs:PurgeQueue",
]
AwsSqsMessageRemovalOperationClass = Literal[
    "received_message_deletion",
    "queue_message_purge",
]
AwsSqsMessageRemovalInternalOperation = Literal[
    "delete_received_message",
    "purge_queue_messages",
]
AwsSqsMessageRemovalManagementEffect = Literal["disruption"]
AwsSqsMessageRemovalTargetGranularity = Literal[
    "queue_received_message_namespace",
    "queue_message_namespace",
]
AwsSqsMessageRemovalAuthorizationBasis = Literal[
    "identity_policy",
    "queue_policy_direct",
    "cross_account_identity_and_queue_policy",
]
AwsSqsMessageRemovalAuthorizationOperation = Literal[
    "sqs:ReceiveMessage",
    "sqs:DeleteMessage",
    "sqs:PurgeQueue",
]


class AwsSqsMessageRemovalPolicyStatementEvidence(TypedDict):
    source_address: str
    source_kind: Literal["identity_policy", "queue_policy"]
    effect: Literal["allow"]
    actions: list[str]
    matching_action_patterns: list[str]
    resources: list[str]
    matching_resources: list[str]
    principals: list[str]
    principal_match: Literal["role", "account", "wildcard"] | None
    conditions: list[Never]
    conditional: Literal[False]


class AwsSqsDeterministicAuthorizationProofCommon(TypedDict):
    queue_address: str
    queue_resource_type: str
    queue_arn: str
    principal_address: str
    principal_arn: str
    principal_kind: Literal["iam_role"]
    authorization_state: Literal["allowed"]
    authorization_bases: list[AwsSqsMessageRemovalAuthorizationBasis]
    same_account: bool
    identity_policy_required: bool
    queue_policy_required: bool
    identity_policy_complete: Literal[True]
    queue_policy_complete: Literal[True]
    identity_policy_source_addresses: list[str]
    queue_policy_source_addresses: list[str]
    identity_policy_statements: list[AwsSqsMessageRemovalPolicyStatementEvidence]
    queue_policy_statements: list[AwsSqsMessageRemovalPolicyStatementEvidence]
    explicit_deny: Literal[False]
    conditional_evaluation_required: Literal[False]
    evaluation_scope: Literal["modeled_identity_and_sqs_queue_policies"]


class AwsSqsReceiveAuthorizationProof(
    AwsSqsDeterministicAuthorizationProofCommon,
):
    operation: Literal["sqs:ReceiveMessage"]
    matched_actions: list[Literal["sqs:ReceiveMessage"]]


class AwsSqsDeleteMessageAuthorizationProof(
    AwsSqsDeterministicAuthorizationProofCommon,
):
    operation: Literal["sqs:DeleteMessage"]
    matched_actions: list[Literal["sqs:DeleteMessage"]]


class AwsSqsPurgeQueueAuthorizationProof(
    AwsSqsDeterministicAuthorizationProofCommon,
):
    operation: Literal["sqs:PurgeQueue"]
    matched_actions: list[Literal["sqs:PurgeQueue"]]


AwsSqsMessageRemovalAuthorizationProof = (
    AwsSqsReceiveAuthorizationProof | AwsSqsDeleteMessageAuthorizationProof | AwsSqsPurgeQueueAuthorizationProof
)


class AwsSqsMessageRemovalDeliveryEvidence(TypedDict):
    delivery_evidence_scope: Literal["sqs_retention_and_redrive_posture"]
    message_retention_seconds: int | None
    redrive_state: Literal["configured", "not_configured", "unknown"]
    redrive_target_arn: str | None
    redrive_max_receive_count: int | None
    removed_message_recovery_state: Literal["not_established_by_modeled_sqs_delivery_controls"]
    uncertainties: list[str]


class AwsEcsSqsMessageRemovalPathCommon(TypedDict):
    workload_address: str
    workload_type: str
    task_definition_address: str
    task_definition_arn: str | None
    internet_facing_load_balancers: list[str]
    role_kind: Literal["ecs_task_role"]
    credential_context: Literal["workload_runtime"]
    role_address: str
    role_arn: str
    queue_address: str
    queue_resource_type: str
    queue_name: str
    queue_arn: str
    queue_url: str | None
    target_model_evidence_addresses: list[str]
    management_effect: Literal["disruption"]
    authorization_source_addresses: list[str]
    authorization_state: Literal["allowed"]
    explicit_deny: Literal[False]
    conditional_evaluation_required: Literal[False]
    lifecycle_compatibility_state: Literal["not_applicable"]
    delivery_evidence: AwsSqsMessageRemovalDeliveryEvidence
    posture_uncertainties: list[str]


class AwsEcsSqsReceivedMessageDeletionPath(
    AwsEcsSqsMessageRemovalPathCommon,
):
    operation: Literal["sqs:DeleteMessage"]
    operation_class: Literal["received_message_deletion"]
    internal_operation: Literal["delete_received_message"]
    target_granularity: Literal["queue_received_message_namespace"]
    target_scope: Literal["exact_queue_received_message_namespace"]
    prerequisite_operation: Literal["sqs:ReceiveMessage"]
    receipt_handle_source: Literal["runtime_receive_response"]
    receipt_handle_value: None
    receive_authorization: AwsSqsReceiveAuthorizationProof
    removal_authorization: AwsSqsDeleteMessageAuthorizationProof


class AwsEcsSqsQueueMessagePurgePath(
    AwsEcsSqsMessageRemovalPathCommon,
):
    operation: Literal["sqs:PurgeQueue"]
    operation_class: Literal["queue_message_purge"]
    internal_operation: Literal["purge_queue_messages"]
    target_granularity: Literal["queue_message_namespace"]
    target_scope: Literal["exact_queue_message_namespace"]
    prerequisite_operation: None
    receipt_handle_source: None
    receipt_handle_value: None
    removal_authorization: AwsSqsPurgeQueueAuthorizationProof


AwsEcsSqsMessageRemovalPath = AwsEcsSqsReceivedMessageDeletionPath | AwsEcsSqsQueueMessagePurgePath
AwsEcsSqsMessageRemovalEvidence = AwsEcsSqsMessageRemovalPath

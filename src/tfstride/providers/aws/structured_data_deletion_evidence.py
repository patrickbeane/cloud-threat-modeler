from __future__ import annotations

from typing import Literal, Never, TypedDict

AwsDynamoDbItemDeletionOperation = Literal[
    "dynamodb:DeleteItem",
    "dynamodb:PartiQLDelete",
    "dynamodb:BatchWriteItem",
]
AwsDynamoDbItemDeletionOperationClass = Literal[
    "item_deletion",
    "batch_item_deletion",
]
AwsDynamoDbItemDeletionInternalOperation = Literal[
    "delete_item",
    "partiql_delete",
    "batch_write_delete",
]
AwsDynamoDbItemDeletionManagementEffect = Literal["disruption"]
AwsDynamoDbItemDeletionTargetGranularity = Literal["table_item_namespace",]
AwsDynamoDbItemDeletionLifecycleCompatibilityState = Literal["not_applicable",]


class AwsDynamoDbDeletionPolicyStatementEvidenceCommon(TypedDict):
    effect: Literal["allow"]
    actions: list[str]
    matching_action_patterns: list[str]
    resources: list[str]
    matching_resources: list[str]
    resource_scopes: list[Literal["exact_table"]]
    conditions: list[Never]
    conditional: Literal[False]


class AwsDynamoDbDeleteItemPolicyStatementEvidence(
    AwsDynamoDbDeletionPolicyStatementEvidenceCommon,
):
    matched_actions: list[Literal["dynamodb:DeleteItem"]]


class AwsDynamoDbPartiQlDeletePolicyStatementEvidence(
    AwsDynamoDbDeletionPolicyStatementEvidenceCommon,
):
    matched_actions: list[Literal["dynamodb:PartiQLDelete"]]


class AwsDynamoDbBatchWriteDeletePolicyStatementEvidence(
    AwsDynamoDbDeletionPolicyStatementEvidenceCommon,
):
    matched_actions: list[Literal["dynamodb:BatchWriteItem"]]


AwsDynamoDbDeletionPolicyStatementEvidence = (
    AwsDynamoDbDeleteItemPolicyStatementEvidence
    | AwsDynamoDbPartiQlDeletePolicyStatementEvidence
    | AwsDynamoDbBatchWriteDeletePolicyStatementEvidence
)


class AwsDynamoDbPitrEnabledRecoveryEvidence(TypedDict):
    recovery_evidence_scope: Literal["dynamodb_point_in_time_recovery"]
    pitr_state: Literal["enabled"]
    pitr_enabled: Literal[True]
    pitr_recovery_period_days: int | None
    uncertainties: list[str]


class AwsDynamoDbPitrDisabledRecoveryEvidence(TypedDict):
    recovery_evidence_scope: Literal["dynamodb_point_in_time_recovery"]
    pitr_state: Literal["disabled"]
    pitr_enabled: Literal[False]
    pitr_recovery_period_days: None
    uncertainties: list[str]


class AwsDynamoDbPitrProviderDefaultRecoveryEvidence(TypedDict):
    recovery_evidence_scope: Literal["dynamodb_point_in_time_recovery"]
    pitr_state: Literal["not_configured"]
    pitr_enabled: Literal[False]
    pitr_recovery_period_days: None
    uncertainties: list[str]


class AwsDynamoDbPitrUnknownRecoveryEvidence(TypedDict):
    recovery_evidence_scope: Literal["dynamodb_point_in_time_recovery"]
    pitr_state: Literal["unknown"]
    pitr_enabled: None
    pitr_recovery_period_days: None
    uncertainties: list[str]


AwsDynamoDbItemDeletionRecoveryEvidence = (
    AwsDynamoDbPitrEnabledRecoveryEvidence
    | AwsDynamoDbPitrDisabledRecoveryEvidence
    | AwsDynamoDbPitrProviderDefaultRecoveryEvidence
    | AwsDynamoDbPitrUnknownRecoveryEvidence
)


class AwsEcsDynamoDbItemDeletionPathCommon(TypedDict):
    workload_address: str
    workload_type: str
    task_definition_address: str
    task_definition_arn: str | None
    internet_facing_load_balancers: list[str]
    role_kind: Literal["ecs_task_role"]
    credential_context: Literal["workload_runtime"]
    role_address: str
    role_arn: str
    dynamodb_table_address: str
    dynamodb_table_resource_type: str
    dynamodb_table_name: str
    dynamodb_table_arn: str
    target_granularity: Literal["table_item_namespace"]
    target_scope: Literal["exact_table_item_namespace"]
    target_model_evidence_addresses: list[str]
    management_effect: Literal["disruption"]
    authorization_source_addresses: list[str]
    evaluation_basis: Literal["modeled_identity_policy"]
    authorization_state: Literal["allowed"]
    role_policy_complete: Literal[True]
    policy_action_patterns: list[str]
    policy_resources: list[str]
    resource_scopes: list[Literal["exact_table"]]
    explicit_deny: Literal[False]
    conditional_evaluation_required: Literal[False]
    lifecycle_compatibility_state: Literal["not_applicable"]
    recovery_evidence: AwsDynamoDbItemDeletionRecoveryEvidence
    posture_uncertainties: list[str]


class AwsEcsDynamoDbDeleteItemPath(AwsEcsDynamoDbItemDeletionPathCommon):
    operation: Literal["dynamodb:DeleteItem"]
    operation_class: Literal["item_deletion"]
    internal_operation: Literal["delete_item"]
    matched_actions: list[Literal["dynamodb:DeleteItem"]]
    policy_statements: list[AwsDynamoDbDeleteItemPolicyStatementEvidence]


class AwsEcsDynamoDbPartiQlDeletePath(
    AwsEcsDynamoDbItemDeletionPathCommon,
):
    operation: Literal["dynamodb:PartiQLDelete"]
    operation_class: Literal["item_deletion"]
    internal_operation: Literal["partiql_delete"]
    matched_actions: list[Literal["dynamodb:PartiQLDelete"]]
    policy_statements: list[AwsDynamoDbPartiQlDeletePolicyStatementEvidence]


class AwsEcsDynamoDbBatchWriteDeletePath(
    AwsEcsDynamoDbItemDeletionPathCommon,
):
    operation: Literal["dynamodb:BatchWriteItem"]
    operation_class: Literal["batch_item_deletion"]
    internal_operation: Literal["batch_write_delete"]
    matched_actions: list[Literal["dynamodb:BatchWriteItem"]]
    policy_statements: list[AwsDynamoDbBatchWriteDeletePolicyStatementEvidence]
    batch_write_includes_put_capability: Literal[True]


AwsEcsDynamoDbItemDeletionPath = (
    AwsEcsDynamoDbDeleteItemPath | AwsEcsDynamoDbPartiQlDeletePath | AwsEcsDynamoDbBatchWriteDeletePath
)
AwsEcsDynamoDbItemDeletionEvidence = AwsEcsDynamoDbItemDeletionPath

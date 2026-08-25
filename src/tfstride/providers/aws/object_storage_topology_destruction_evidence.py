from __future__ import annotations

from typing import Literal, Never, TypedDict

AwsS3BucketTopologyDestructionOperation = Literal["s3:DeleteBucket"]
AwsS3BucketTopologyDestructionOperationClass = Literal["bucket_deletion"]
AwsS3BucketTopologyDestructionInternalOperation = Literal["delete_bucket"]
AwsS3BucketTopologyDestructionTargetGranularity = Literal["bucket_topology"]
AwsS3BucketTopologyDestructionAuthorizationBasis = Literal[
    "identity_policy",
    "bucket_policy_direct",
]


class AwsS3BucketTopologyPolicyStatementEvidenceCommon(TypedDict):
    source_address: str
    effect: Literal["allow"]
    actions: list[str]
    matching_action_patterns: list[str]
    matched_actions: list[Literal["s3:DeleteBucket"]]
    resources: list[str]
    matching_resources: list[str]
    resource_scopes: list[Literal["exact_bucket"]]
    conditions: list[Never]
    conditional: Literal[False]


class AwsS3BucketTopologyIdentityPolicyStatementEvidence(
    AwsS3BucketTopologyPolicyStatementEvidenceCommon,
):
    source_kind: Literal["identity_policy"]
    principals: list[Never]
    principal_match: None


class AwsS3BucketTopologyResourcePolicyStatementEvidence(
    AwsS3BucketTopologyPolicyStatementEvidenceCommon,
):
    source_kind: Literal["bucket_policy"]
    principals: list[str]
    principal_match: Literal["role", "account", "wildcard"]


AwsS3BucketTopologyPolicyStatementEvidence = (
    AwsS3BucketTopologyIdentityPolicyStatementEvidence | AwsS3BucketTopologyResourcePolicyStatementEvidence
)


class AwsS3BucketTopologyDestructionRecoveryEvidence(TypedDict):
    recovery_evidence_scope: Literal["s3_bucket_deletion_prerequisites_and_recovery"]
    bucket_emptiness_required: Literal[True]
    bucket_emptiness_state: Literal["not_established"]
    versioning_status: str | None
    versioning_enabled: bool | None
    object_lock_enabled: bool | None
    object_lock_default_retention_mode: str | None
    object_lock_default_retention_days: int | None
    object_lock_default_retention_years: int | None
    out_of_plan_object_inventory_evaluated: Literal[False]
    attached_access_point_state: Literal["not_established"]
    bucket_recovery_state: Literal["not_established_by_modeled_aws_s3_bucket_evidence"]
    successful_deletion_observed: Literal[False]
    recovery_observed: Literal[False]
    uncertainties: list[str]


class AwsEcsS3BucketTopologyDestructionPath(TypedDict):
    workload_address: str
    workload_type: str
    task_definition_address: str
    task_definition_arn: str | None
    internet_facing_load_balancers: list[str]
    role_kind: Literal["ecs_task_role"]
    credential_context: Literal["workload_runtime"]
    role_address: str
    role_reference: str
    role_arn: str | None
    same_account: Literal[True]
    bucket_address: str
    bucket_name: str
    bucket_arn: str
    operation: Literal["s3:DeleteBucket"]
    operation_class: Literal["bucket_deletion"]
    internal_operation: Literal["delete_bucket"]
    management_effect: Literal["disruption"]
    target_granularity: Literal["bucket_topology"]
    target_scope: Literal["exact_s3_bucket"]
    target_model_evidence_addresses: list[str]
    authorization_source_addresses: list[str]
    authorization_bases: list[AwsS3BucketTopologyDestructionAuthorizationBasis]
    authorization_state: Literal["allowed"]
    evaluation_basis: Literal["modeled_identity_and_bucket_policies"]
    matched_actions: list[Literal["s3:DeleteBucket"]]
    identity_policy_complete: Literal[True]
    bucket_policy_complete: Literal[True]
    identity_policy_source_addresses: list[str]
    bucket_policy_source_addresses: list[str]
    authorization_statements: list[AwsS3BucketTopologyPolicyStatementEvidence]
    explicit_deny: Literal[False]
    conditional_evaluation_required: Literal[False]
    lifecycle_compatibility_state: Literal["bucket_emptiness_not_established"]
    recovery_evidence: AwsS3BucketTopologyDestructionRecoveryEvidence
    posture_uncertainties: list[str]


AwsEcsS3BucketTopologyDestructionEvidence = AwsEcsS3BucketTopologyDestructionPath

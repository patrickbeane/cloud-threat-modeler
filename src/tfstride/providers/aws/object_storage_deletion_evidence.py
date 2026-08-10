from __future__ import annotations

from typing import Literal, TypedDict

AwsS3ObjectDeletionOperation = Literal[
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
]
AwsS3ObjectDeletionOperationClass = Literal[
    "logical_object_deletion",
    "object_version_deletion",
]
AwsS3ObjectDeletionManagementEffect = Literal["disruption"]
AwsS3ObjectDeletionTargetGranularity = Literal[
    "object",
    "object_version",
    "object_prefix",
    "bucket_object_namespace",
    "object_version_namespace",
    "object_prefix_version_namespace",
    "bucket_object_version_namespace",
]
AwsS3ObjectDeletionAuthorizationState = Literal[
    "allowed",
    "denied",
    "unknown",
    "conditional",
    "not_modeled",
]
AwsS3ObjectDeletionLifecycleCompatibilityState = Literal[
    "compatible",
    "incompatible",
    "unknown",
    "not_applicable",
]


class AwsS3ObjectDeletionRecoveryEvidence(TypedDict):
    recovery_evidence_scope: Literal["s3_versioning_and_object_lock"]
    versioning_status: str | None
    versioning_enabled: bool | None
    object_lock_enabled: bool | None
    object_lock_default_retention_mode: str | None
    object_lock_default_retention_days: int | None
    object_lock_default_retention_years: int | None
    bypass_governance_retention_authorized: bool | None
    uncertainties: list[str]


class _AwsEcsS3ObjectDeletionPathCommon(TypedDict):
    workload_address: str
    workload_type: str
    task_definition_address: str
    task_definition_arn: str | None
    role_kind: Literal["ecs_task_role"]
    credential_context: Literal["workload_runtime"]
    role_address: str
    role_arn: str
    bucket_address: str
    bucket_arn: str
    management_effect: AwsS3ObjectDeletionManagementEffect
    target_scope: str
    target_model_evidence_addresses: list[str]
    authorization_source_addresses: list[str]
    authorization_state: Literal["allowed"]
    authorization_bases: list[str]
    matched_actions: list[AwsS3ObjectDeletionOperation]
    policy_action_patterns: list[str]
    policy_resources: list[str]
    identity_policy_complete: Literal[True]
    bucket_policy_complete: Literal[True]
    explicit_deny: Literal[False]
    conditional_evaluation_required: Literal[False]
    lifecycle_compatibility_state: AwsS3ObjectDeletionLifecycleCompatibilityState
    recovery_evidence: AwsS3ObjectDeletionRecoveryEvidence
    posture_uncertainties: list[str]


class AwsEcsS3ExactObjectDeletionPath(_AwsEcsS3ObjectDeletionPathCommon):
    operation: Literal["s3:DeleteObject"]
    operation_class: Literal["logical_object_deletion"]
    target_granularity: Literal["object"]
    object_key: str
    object_version: None


class AwsEcsS3ObjectPrefixDeletionPath(_AwsEcsS3ObjectDeletionPathCommon):
    operation: Literal["s3:DeleteObject"]
    operation_class: Literal["logical_object_deletion"]
    target_granularity: Literal["object_prefix"]
    object_key: str
    object_version: None


class AwsEcsS3BucketObjectNamespaceDeletionPath(_AwsEcsS3ObjectDeletionPathCommon):
    operation: Literal["s3:DeleteObject"]
    operation_class: Literal["logical_object_deletion"]
    target_granularity: Literal["bucket_object_namespace"]
    object_key: None
    object_version: None


class AwsEcsS3ObjectVersionDeletionPath(_AwsEcsS3ObjectDeletionPathCommon):
    operation: Literal["s3:DeleteObjectVersion"]
    operation_class: Literal["object_version_deletion"]
    target_granularity: Literal["object_version"]
    object_key: str
    object_version: str


class AwsEcsS3ObjectVersionNamespaceDeletionPath(_AwsEcsS3ObjectDeletionPathCommon):
    operation: Literal["s3:DeleteObjectVersion"]
    operation_class: Literal["object_version_deletion"]
    target_granularity: Literal["object_version_namespace"]
    object_key: str
    object_version: None


class AwsEcsS3ObjectPrefixVersionNamespaceDeletionPath(_AwsEcsS3ObjectDeletionPathCommon):
    operation: Literal["s3:DeleteObjectVersion"]
    operation_class: Literal["object_version_deletion"]
    target_granularity: Literal["object_prefix_version_namespace"]
    object_key: str
    object_version: None


class AwsEcsS3BucketObjectVersionNamespaceDeletionPath(_AwsEcsS3ObjectDeletionPathCommon):
    operation: Literal["s3:DeleteObjectVersion"]
    operation_class: Literal["object_version_deletion"]
    target_granularity: Literal["bucket_object_version_namespace"]
    object_key: None
    object_version: None


AwsEcsS3ObjectDeletionPath = (
    AwsEcsS3ExactObjectDeletionPath
    | AwsEcsS3ObjectPrefixDeletionPath
    | AwsEcsS3BucketObjectNamespaceDeletionPath
    | AwsEcsS3ObjectVersionDeletionPath
    | AwsEcsS3ObjectVersionNamespaceDeletionPath
    | AwsEcsS3ObjectPrefixVersionNamespaceDeletionPath
    | AwsEcsS3BucketObjectVersionNamespaceDeletionPath
)
AwsEcsS3ObjectDeletionEvidence = AwsEcsS3ObjectDeletionPath

from __future__ import annotations

from typing import Literal, NotRequired, TypedDict

AwsSecretsManagerOperation = Literal[
    "secretsmanager:PutSecretValue",
    "secretsmanager:UpdateSecret",
    "secretsmanager:UpdateSecretVersionStage",
    "secretsmanager:DeleteSecret",
]
AwsSecretsManagerOperationClass = Literal[
    "value_mutation",
    "version_stage_mutation",
    "destructive_administration",
]
AwsSecretsManagerManagementEffect = Literal["tampering", "disruption"]
AwsSecretsManagerAuthorizationBasis = Literal[
    "identity_policy",
    "resource_policy_direct",
    "cross_account_identity_and_resource_policy",
]
AwsSecretsManagerCandidateAuthorizationBasis = Literal[
    "identity_policy",
    "resource_policy_direct",
    "cross_account_identity_and_resource_policy",
    "wildcard_resource_policy",
]
AwsSecretsManagerAuthorizationState = Literal[
    "allowed",
    "denied",
    "unknown",
    "not_allowed",
]


class AwsSecretsManagerPolicyConditionEvidence(TypedDict):
    operator: str
    key: str
    values: list[str]


class AwsSecretsManagerPolicyStatementEvidence(TypedDict):
    source_address: str
    source_kind: Literal["identity_policy", "resource_policy"]
    effect: str
    actions: list[str]
    matching_action_patterns: list[str]
    resources: list[str]
    matching_resources: list[str]
    principals: list[str]
    principal_match: str | None
    conditions: list[AwsSecretsManagerPolicyConditionEvidence]
    conditional: bool


class AwsSecretsManagerOperationAuthorization(TypedDict):
    secret_address: str
    secret_resource_type: str
    secret_arn: str
    secret_name: str | None
    principal_address: str
    principal_arn: str
    principal_kind: Literal["iam_role"]
    operation: AwsSecretsManagerOperation
    operation_class: AwsSecretsManagerOperationClass
    management_effect: AwsSecretsManagerManagementEffect
    supported_authorization_bases: list[AwsSecretsManagerAuthorizationBasis]
    authorization_state: AwsSecretsManagerAuthorizationState
    authorization_bases: list[AwsSecretsManagerAuthorizationBasis]
    candidate_authorization_bases: list[AwsSecretsManagerCandidateAuthorizationBasis]
    same_account: bool | None
    identity_policy_required: bool
    resource_policy_required: bool
    identity_policy_complete: bool
    resource_policy_complete: bool
    identity_policy_source_addresses: list[str]
    secrets_manager_resource_policy_source_addresses: list[str]
    unresolved_attached_policy_arns: list[str]
    identity_policy_uncertainties: list[str]
    resource_policy_uncertainties: list[str]
    explicit_deny: bool
    conditional_policy_evidence_present: bool
    authorization_requires_condition_evaluation: bool
    identity_policy_statements: list[AwsSecretsManagerPolicyStatementEvidence]
    resource_policy_statements: list[AwsSecretsManagerPolicyStatementEvidence]
    evaluation_scope: Literal["modeled_identity_and_secrets_manager_resource_policies"]


class AwsEcsSecretsManagerManagementPath(TypedDict):
    workload_address: str
    workload_type: str
    task_definition_address: str
    task_definition_arn: str | None
    secret_address: str
    secret_resource_type: str
    secret_arn: str
    secret_name: str | None
    operation: AwsSecretsManagerOperation
    operation_class: AwsSecretsManagerOperationClass
    management_effect: AwsSecretsManagerManagementEffect
    role_kind: Literal["ecs_task_role"]
    credential_context: Literal["workload_runtime"]
    role_address: str
    role_arn: str
    role_policy_complete: bool
    authorization_state: Literal["allowed"]
    authorization_bases: list[AwsSecretsManagerAuthorizationBasis]
    candidate_authorization_bases: list[AwsSecretsManagerCandidateAuthorizationBasis]
    evaluation_basis: Literal["modeled_secrets_manager_authorization"]
    same_account: bool | None
    explicit_deny: bool
    conditional_policy_evidence_present: bool
    authorization_requires_condition_evaluation: bool
    identity_policy_source_addresses: list[str]
    secrets_manager_resource_policy_source_addresses: list[str]
    identity_policy_statements: list[AwsSecretsManagerPolicyStatementEvidence]
    resource_policy_statements: list[AwsSecretsManagerPolicyStatementEvidence]
    terraform_recovery_window_in_days: int | None
    recovery_window_evidence_scope: Literal["terraform_resource_deletion_only"]
    authorization_record: AwsSecretsManagerOperationAuthorization
    internet_facing_load_balancers: NotRequired[list[str]]

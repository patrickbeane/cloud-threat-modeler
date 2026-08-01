from __future__ import annotations

from typing import Any, Literal, NotRequired, TypedDict

AwsKmsAuthorizationBasis = Literal[
    "direct_key_policy",
    "iam_via_account_principal",
    "kms_grant",
]
AwsKmsCandidateAuthorizationBasis = Literal[
    "direct_key_policy",
    "iam_via_account_principal",
    "kms_grant",
    "wildcard_key_policy",
]
AwsKmsAuthorizationState = Literal["allowed", "denied", "unknown", "not_allowed"]
AwsEcsKmsAuthorizationBasis = Literal["key_policy_direct", "iam_via_key_policy", "grant"]


class AwsKmsPolicyConditionEvidence(TypedDict):
    operator: str
    key: str
    values: list[str]


class AwsKmsPolicyPrincipalEvidence(TypedDict):
    kind: str
    value: str


class AwsKmsSerializedPolicyStatement(TypedDict):
    effect: str
    actions: list[str]
    resources: list[str]
    principals: list[str]
    principal_entries: list[AwsKmsPolicyPrincipalEvidence]
    conditions: list[AwsKmsPolicyConditionEvidence]


class AwsKmsAliasRelationship(TypedDict):
    source: str
    alias_name: str | None
    alias_name_prefix: str | None
    alias_arn: str | None
    target_key_id: str | None
    target_key_arn: str | None
    target_key_reference: str
    resolved_key_address: str


class AwsKmsGrantRelationship(TypedDict):
    source: str
    grant_id: str | None
    name: str | None
    key_reference: str
    grantee_principal: str | None
    operations: list[str]
    retiring_principal: str | None
    constraints: dict[str, Any]
    retire_on_delete_state: str | None
    resolved_key_address: str


class AwsKmsKeyPolicyEvidence(TypedDict):
    source: str
    source_type: Literal["inline", "standalone"]
    configuration_state: str | None
    completeness_state: str | None
    bypass_lockout_safety_check_state: str | None
    policy_statements: list[AwsKmsSerializedPolicyStatement]
    posture_uncertainties: list[str]
    resolved_key_address: str


class AwsKmsPolicyStatementEvidence(TypedDict):
    source_kind: str
    effect: str
    actions: list[str]
    matching_action_patterns: list[str]
    resources: list[str]
    matching_resources: list[str]
    principals: list[str]
    principal_match: str | None
    conditions: list[AwsKmsPolicyConditionEvidence]
    conditional: bool


class AwsKmsGrantAuthorizationEvidence(TypedDict):
    source: str
    operation: str
    constraints: dict[str, Any]
    constraint_state: str
    posture_uncertainties: list[str]
    direct_role_authority: bool


class AwsKmsOperationAuthorization(TypedDict):
    key_address: str
    key_arn: str | None
    key_id: str | None
    key_usage: str | None
    key_spec: str | None
    principal_address: str
    principal_arn: str | None
    principal_kind: Literal["iam_role"]
    operation: str
    authorization_state: AwsKmsAuthorizationState
    authorization_bases: list[AwsKmsAuthorizationBasis]
    candidate_authorization_bases: list[AwsKmsCandidateAuthorizationBasis]
    key_policy_complete: bool
    identity_policy_complete: bool
    key_policy_source_addresses: list[str]
    identity_policy_source_addresses: list[str]
    unresolved_attached_policy_arns: list[str]
    key_policy_uncertainties: list[str]
    identity_policy_uncertainties: list[str]
    same_account: bool
    explicit_deny: bool
    conditional_policy_evidence_present: bool
    authorization_requires_condition_evaluation: bool
    conditional_evaluation_required: bool
    constraint_state: str
    identity_policy_statements: list[AwsKmsPolicyStatementEvidence]
    key_policy_statements: list[AwsKmsPolicyStatementEvidence]
    kms_grants: list[AwsKmsGrantAuthorizationEvidence]
    evaluation_scope: Literal["modeled_key_policy_identity_policies_and_grants"]


class AwsEcsKmsOperationPath(TypedDict):
    workload_address: str
    workload_type: str
    task_definition_address: str
    task_definition_arn: str | None
    key_address: str
    key_arn: str
    key_id: str | None
    key_usage: str | None
    key_spec: str | None
    operation: str
    role_kind: Literal["ecs_task_role"]
    credential_context: Literal["workload_runtime"]
    role_address: str
    role_arn: str | None
    role_policy_complete: bool
    authorization_state: AwsKmsAuthorizationState
    authorization_basis: AwsEcsKmsAuthorizationBasis | None
    authorization_bases: list[AwsEcsKmsAuthorizationBasis]
    candidate_authorization_bases: list[str]
    evaluation_basis: Literal["modeled_kms_authorization"]
    same_account: bool
    explicit_deny: bool
    conditional_evaluation_required: bool
    constraint_state: str
    policy_action_patterns: list[str]
    policy_resources: list[str]
    deny_action_patterns: list[str]
    deny_policy_resources: list[str]
    key_policy_complete: bool
    key_policy_source_addresses: list[str]
    identity_policy_source_addresses: list[str]
    key_policy_uncertainties: list[str]
    identity_policy_uncertainties: list[str]
    identity_policy_statements: list[AwsKmsPolicyStatementEvidence]
    key_policy_statements: list[AwsKmsPolicyStatementEvidence]
    kms_grants: list[AwsKmsGrantAuthorizationEvidence]
    grant_constraints: list[dict[str, Any]]
    authorization_record: AwsKmsOperationAuthorization
    internet_facing_load_balancers: NotRequired[list[str]]

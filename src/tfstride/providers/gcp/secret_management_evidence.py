from __future__ import annotations

from typing import Any, Literal, NotRequired, TypedDict

GcpSecretManagerScopeType = Literal["project", "secret"]
GcpSecretManagerGrantBasis = Literal["project_iam", "secret_resource_iam"]
GcpSecretManagerPermission = Literal[
    "secretmanager.versions.add",
    "secretmanager.versions.disable",
    "secretmanager.versions.destroy",
    "secretmanager.secrets.delete",
]
GcpSecretManagerOperationClass = Literal[
    "value_mutation",
    "version_disruption",
    "destructive_administration",
]
GcpSecretManagerManagementEffect = Literal["tampering", "disruption"]
GcpSecretManagerTargetType = Literal["secret", "secret_version"]
GcpSecretManagerLifecycleCompatibilityState = Literal[
    "compatible",
    "incompatible",
    "unknown",
    "not_applicable",
]


class GcpSecretManagerIamGrant(TypedDict):
    role: str
    role_kind: str
    role_resolution_state: str
    modeled_secret_permissions: list[str]
    scope_effective_permissions: list[str]
    members: list[str]
    source: str
    source_type: str
    scope_type: GcpSecretManagerScopeType
    scope: str
    source_scope_reference: str | None
    project: str
    secret_address: str
    secret_resource_name: str
    condition_state: str
    authorization_state: str
    management_mode: str
    management_state: str
    grant_basis: GcpSecretManagerGrantBasis
    custom_role_permissions: NotRequired[list[str]]
    role_definition_address: NotRequired[str]
    condition: NotRequired[dict[str, Any]]
    policy_data_state: NotRequired[str]
    members_state: NotRequired[str]


class GcpSecretManagerVersionEvidence(TypedDict):
    version_address: str
    version_resource_type: str
    version_resource_name: str
    version_number: str
    version_state: str | None
    secret_address: str
    secret_resource_name: str
    resolved_secret_address: str
    lifecycle_state: str
    deletion_policy: str | None
    posture_uncertainties: list[str]


class GcpCloudRunSecretManagementPath(TypedDict):
    workload_address: str
    workload_type: str
    service_account_email: str
    service_account_member: str
    identity_kind: Literal["cloud_run_service_account"]
    credential_context: Literal["workload_runtime"]
    operation: GcpSecretManagerPermission
    operation_class: GcpSecretManagerOperationClass
    management_effect: GcpSecretManagerManagementEffect
    matched_permissions: list[GcpSecretManagerPermission]
    target_type: GcpSecretManagerTargetType
    target_address: str
    target_resource_type: str
    target_resource_name: str
    target_model_evidence_addresses: list[str]
    secret_address: str
    secret_resource_name: str
    secret_project: str
    secret_version: GcpSecretManagerVersionEvidence | None
    version_destroy_ttl: str | None
    recovery_evidence_scope: Literal["secret_version_destruction_delay"]
    lifecycle_compatibility_state: GcpSecretManagerLifecycleCompatibilityState
    iam_resource_address: str
    iam_resource_type: str
    role: str
    role_kind: str
    role_resolution_state: str
    modeled_secret_permissions: list[str]
    custom_role_permissions: list[str]
    role_definition_address: str | None
    scope_effective_permissions: list[str]
    grant_members: list[str]
    grant_basis: GcpSecretManagerGrantBasis
    scope_type: GcpSecretManagerScopeType
    scope: str
    source_scope_reference: str | None
    management_mode: str
    management_state: str
    condition: dict[str, Any] | None
    condition_state: str
    authorization_state: Literal["granted"]
    authorization_model: Literal["secret_manager_iam"]
    iam_scope_is_secret_version: Literal[False]
    iam_grant_record: GcpSecretManagerIamGrant

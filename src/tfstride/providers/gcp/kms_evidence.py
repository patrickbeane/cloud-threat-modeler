from __future__ import annotations

from typing import Any, Literal, NotRequired, TypedDict

GcpKmsScopeType = Literal["project", "key_ring", "crypto_key"]
GcpKmsGrantBasis = Literal["project_iam", "key_ring_iam", "crypto_key_iam"]
GcpKmsOperationClass = Literal["decrypt", "sign", "mac_generation"]
GcpKmsOperationPermission = Literal[
    "cloudkms.cryptoKeyVersions.useToDecrypt",
    "cloudkms.cryptoKeyVersions.useToSign",
]


class GcpKmsIamGrant(TypedDict):
    role: str
    role_kind: str
    role_resolution_state: str
    modeled_kms_permissions: list[str]
    scope_effective_permissions: list[str]
    members: list[str]
    source: str
    source_type: str
    scope_type: GcpKmsScopeType
    scope: str
    source_scope_reference: str | None
    project: str
    key_ring: str
    crypto_key: str
    crypto_key_address: str
    condition_state: str
    authorization_state: str
    management_mode: str
    management_state: str
    grant_basis: GcpKmsGrantBasis
    custom_role_permissions: NotRequired[list[str]]
    role_definition_address: NotRequired[str]
    condition: NotRequired[dict[str, Any]]
    policy_data_state: NotRequired[str]
    members_state: NotRequired[str]


class GcpKmsKeyVersionEvidence(TypedDict):
    version_address: str
    version_resource_type: str
    version_resource_name: str | None
    version_identity_state: str
    version_number: str | None
    purpose: str | None
    algorithm: str | None
    protection_level: str | None
    state: str | None
    import_posture: str | None
    posture_uncertainties: list[str]


class GcpCloudRunKmsOperationPath(TypedDict):
    workload_address: str
    workload_type: str
    service_account_email: str
    service_account_member: str
    identity_kind: Literal["cloud_run_service_account"]
    credential_context: Literal["workload_runtime"]
    key_address: str
    key_resource_type: str
    key_resource_name: str
    key_project: str
    key_ring: str
    key_purpose: str | None
    operation: GcpKmsOperationPermission
    operation_class: GcpKmsOperationClass
    matched_permissions: list[GcpKmsOperationPermission]
    iam_resource_address: str
    iam_resource_type: str
    role: str
    role_kind: str
    role_resolution_state: str
    modeled_kms_permissions: list[str]
    custom_role_permissions: list[str]
    role_definition_address: str | None
    scope_effective_permissions: list[str]
    grant_members: list[str]
    grant_basis: GcpKmsGrantBasis
    scope_type: GcpKmsScopeType
    scope: str
    source_scope_reference: str | None
    management_mode: str
    management_state: str
    condition: dict[str, Any] | None
    condition_state: str
    authorization_state: str
    authorization_model: Literal["cloud_kms_iam"]
    key_versions: list[GcpKmsKeyVersionEvidence]
    key_version_evidence_scope: Literal["modeled_versions_of_crypto_key"]
    iam_scope_is_key_version: Literal[False]
    iam_grant_record: GcpKmsIamGrant

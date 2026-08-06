from __future__ import annotations

from typing import Literal, TypedDict

from tfstride.providers.azure.key_vault_dependency_evidence import (
    AzureKeyVaultEncryptionDependency,
)
from tfstride.providers.azure.key_vault_evidence import (
    AzureAppServiceKeyVaultOperationPath,
    AzureKeyVaultRuntimeIdentityKind,
)

AzureStorageAccessClass = Literal["read", "write", "delete", "administrative"]
AzureStorageAccessState = Literal["granted", "conditional"]
AzureStorageResourceScope = Literal[
    "exact_storage_account",
    "exact_storage_container",
]


class AzureAppServiceStorageAccessPath(TypedDict):
    workload_address: str
    workload_type: str
    identity_address: str
    identity_kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str | None
    credential_context: Literal["workload_runtime"]
    storage_resource_address: str
    storage_resource_type: str
    storage_resource_id: str | None
    storage_account_address: str | None
    storage_account_id: str | None
    container_address: str | None
    role_assignment_address: str
    role_definition_name: str
    role_definition_id: str | None
    role_kind: str
    access_classes: list[AzureStorageAccessClass]
    grant_basis: str
    evaluation_basis: Literal["modeled_rbac_assignment"]
    resource_scope: AzureStorageResourceScope
    assignment_scope: str | None
    assignment_scope_kind: str | None
    condition: str | None
    condition_state: Literal["configured", "not_configured"]
    access_state: AzureStorageAccessState
    role_definition_address: str | None
    custom_role_data_actions: list[str]
    custom_role_not_data_actions: list[str]
    matched_data_actions: list[str]
    excluded_data_actions: list[str]


class AzureAppServiceStorageProtectedDataConvergence(TypedDict):
    workload_address: str
    workload_type: str
    identity_address: str
    identity_kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str
    storage_resource_address: str
    storage_account_address: str
    storage_account_id: str
    key_address: str
    key_uri: str | None
    key_versionless_uri: str
    operation: Literal["decrypt", "unwrap"]
    access_class: Literal["read"]
    runtime_identity_match: Literal[True]
    protected_resource_match: Literal[True]
    key_identity_match: Literal[True]
    convergence_state: Literal["resolved"]
    evaluation_basis: Literal["exact_storage_access_key_vault_dependency_and_plaintext_recovery_authority"]
    access_path: AzureAppServiceStorageAccessPath
    key_operation_path: AzureAppServiceKeyVaultOperationPath
    encryption_dependency: AzureKeyVaultEncryptionDependency
    posture_uncertainties: list[str]

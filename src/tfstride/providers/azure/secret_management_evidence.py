from __future__ import annotations

from typing import Literal, TypedDict

from tfstride.providers.azure.key_vault_evidence import (
    AzureKeyVaultAuthorizationModel,
    AzureKeyVaultAuthorizationModelState,
    AzureKeyVaultAuthorizationState,
    AzureKeyVaultGrantBasis,
    AzureKeyVaultGrantKind,
    AzureKeyVaultGrantScopeType,
    AzureKeyVaultPathScopeType,
    AzureKeyVaultRuntimeIdentityKind,
)

AzureKeyVaultSecretGrantOperation = Literal["set", "delete", "purge"]
AzureKeyVaultSecretManagementOperation = Literal[
    "set",
    "delete",
    "delete_plus_purge",
]
AzureKeyVaultSecretOperationClass = Literal[
    "value_mutation",
    "destructive_administration",
]
AzureKeyVaultSecretManagementEffect = Literal["tampering", "disruption"]
AzureKeyVaultSecretLifecycleCompatibilityState = Literal[
    "compatible",
    "incompatible",
    "unknown",
    "not_applicable",
]


class _AzureKeyVaultSecretAuthorizationGrantRequired(TypedDict):
    grant_kind: AzureKeyVaultGrantKind
    grant_source_address: str
    grant_basis: AzureKeyVaultGrantBasis
    authorization_model: AzureKeyVaultAuthorizationModel
    authorization_model_state: AzureKeyVaultAuthorizationModelState
    authorization_state: AzureKeyVaultAuthorizationState
    grant_scope_type: AzureKeyVaultGrantScopeType
    grant_scope: str | None
    key_vault_address: str
    key_vault_id: str | None
    secret_address: str
    secret_uri: str | None
    secret_versionless_uri: str
    secret_resource_id: str | None
    secret_version: str | None
    principal_id: str | None
    principal_type: str | None
    principal_state: str
    matched_operations: list[AzureKeyVaultSecretGrantOperation]
    condition: str | None
    condition_state: str
    condition_applicability_state: str


class AzureKeyVaultSecretAuthorizationGrant(
    _AzureKeyVaultSecretAuthorizationGrantRequired,
    total=False,
):
    management_mode: str
    management_state: str
    tenant_id: object
    application_id: object
    secret_permissions: list[str]
    secret_permissions_state: str
    scope_resolution_state: str
    role_definition_name: str | None
    role_definition_id: str | None
    role_kind: str
    role_resolution_state: str
    role_definition_address: str | None
    role_data_actions: list[str]
    role_not_data_actions: list[str]
    matched_data_actions: list[str]
    excluded_data_actions: list[str]
    assignable_scope_compatibility_state: str
    condition_version: str | None


class AzureAppServiceKeyVaultSecretManagementPath(TypedDict):
    workload_address: str
    workload_type: str
    identity_address: str
    identity_kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str
    credential_context: Literal["workload_runtime"]
    key_vault_address: str
    key_vault_id: str
    secret_address: str
    secret_resource_type: str
    secret_name: str
    secret_uri: str | None
    secret_versionless_uri: str
    secret_resource_id: str | None
    secret_version: str | None
    operation: AzureKeyVaultSecretManagementOperation
    step_operations: list[AzureKeyVaultSecretGrantOperation]
    operation_class: AzureKeyVaultSecretOperationClass
    management_effect: AzureKeyVaultSecretManagementEffect
    target_type: Literal["secret"]
    target_address: str
    target_resource_id: str
    authorization_model: AzureKeyVaultAuthorizationModel
    authorization_model_state: AzureKeyVaultAuthorizationModelState
    authorization_state: Literal["granted"]
    grant_source_addresses: list[str]
    scope_types: list[AzureKeyVaultPathScopeType]
    scopes: list[str]
    scope_arm_ids: list[str]
    data_plane_grants: list[AzureKeyVaultSecretAuthorizationGrant]
    purge_protection_enabled: bool | None
    recovery_uncertainties: list[str]
    lifecycle_compatibility_state: AzureKeyVaultSecretLifecycleCompatibilityState
    condition: str | None
    condition_state: str
    evaluation_basis: Literal["modeled_key_vault_secret_authorization"]

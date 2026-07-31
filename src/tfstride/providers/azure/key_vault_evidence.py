from __future__ import annotations

from typing import Any, Literal, TypedDict

AzureKeyVaultOperation = Literal["decrypt", "unwrap", "sign"]
AzureKeyVaultOperationClass = Literal["plaintext_recovery", "authenticator_generation"]


class _AzureKeyVaultAuthorizationGrantRequired(TypedDict):
    grant_kind: Literal["access_policy", "rbac"]
    grant_source_address: str
    grant_basis: str
    authorization_model: Literal["access_policy", "azure_rbac"]
    authorization_model_state: str
    authorization_state: str
    grant_scope_type: str
    grant_scope: str | None
    key_vault_address: str
    key_vault_id: str | None
    key_address: str
    key_uri: str | None
    key_versionless_uri: str | None
    key_resource_id: str | None
    principal_id: str | None
    principal_type: str | None
    principal_state: str
    matched_operations: list[str]
    access_classes: list[str]
    condition: object
    condition_state: str
    condition_applicability_state: str


class AzureKeyVaultAuthorizationGrant(_AzureKeyVaultAuthorizationGrantRequired, total=False):
    management_mode: str
    management_state: str
    tenant_id: object
    application_id: object
    key_permissions: list[str]
    key_permissions_state: str
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


class AzureAppServiceKeyVaultOperationPath(TypedDict):
    workload_address: str
    workload_type: str
    identity_address: str
    identity_kind: str
    principal_id: str | None
    credential_context: Literal["workload_runtime"]
    key_address: str
    key_resource_type: str
    key_vault_address: str
    key_vault_id: str | None
    key_name: str | None
    key_type: str | None
    key_operations: list[str]
    key_identity_state: str | None
    key_uri: str | None
    key_versionless_uri: str | None
    key_resource_id: str | None
    key_versionless_resource_id: str | None
    key_version: str | None
    operation: AzureKeyVaultOperation
    operation_class: AzureKeyVaultOperationClass
    matched_key_operation: str
    grant_kind: str
    grant_basis: str
    grant_source_address: str
    grant_source_type: str | None
    scope_type: str
    scope: str | None
    scope_arm_id: str | None
    authorization_model: str
    authorization_model_state: str
    authorization_state: str
    management_mode: str | None
    management_state: str | None
    role_definition_name: str | None
    role_definition_id: str | None
    role_definition_address: str | None
    role_kind: str | None
    role_resolution_state: str | None
    matched_data_actions: list[str]
    key_permissions: list[str]
    condition: dict[str, Any] | None
    condition_state: str
    condition_applicability_state: str
    evaluation_basis: Literal["modeled_key_vault_key_authorization"]
    authorization_grant_record: AzureKeyVaultAuthorizationGrant

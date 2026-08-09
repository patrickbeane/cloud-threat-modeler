from __future__ import annotations

from typing import Any, Literal, TypedDict

from tfstride.providers.azure.arm_control_plane_evidence import AzureArmControlPlaneGrant

AzureKeyVaultOperation = Literal["decrypt", "unwrap", "sign"]
AzureKeyVaultOperationClass = Literal["plaintext_recovery", "authenticator_generation"]
AzureKeyVaultGrantKind = Literal["access_policy", "rbac"]
AzureKeyVaultGrantBasis = Literal["key_vault_access_policy", "azure_rbac_assignment"]
AzureKeyVaultAuthorizationModel = Literal["access_policy", "azure_rbac"]
AzureKeyVaultAuthorizationModelState = Literal["active", "unknown"]
AzureKeyVaultAuthorizationState = Literal["granted", "conditional", "ambiguous", "unknown"]
AzureKeyVaultGrantScopeType = Literal[
    "management_group",
    "subscription",
    "resource_group",
    "vault",
    "key",
    "secret",
]
AzureKeyVaultPathScopeType = Literal[
    "subscription",
    "resource_group",
    "vault",
    "key",
    "secret",
]
AzureKeyVaultRuntimeIdentityKind = Literal["system_assigned", "user_assigned"]
AzureKeyVaultManagementOperation = Literal[
    "update",
    "delete",
    "delete_plus_purge",
    "rbac_role_assignment_management",
    "legacy_access_policy_mutation",
    "authorization_model_mutation",
]
AzureKeyVaultManagementOperationClass = Literal[
    "configuration_administration",
    "destructive_administration",
    "authorization_administration",
]
AzureKeyVaultManagementEffect = Literal["disruption", "delegation"]
AzureKeyVaultManagementTargetType = Literal["key", "vault"]
AzureKeyVaultManagementAuthorizationBasis = Literal[
    "key_vault_data_plane_grant",
    "azure_control_plane_role_assignment",
]
AzureKeyVaultDelegationMechanism = Literal[
    "not_applicable",
    "azure_rbac_role_assignment",
    "legacy_access_policy",
    "authorization_model_transition",
]
AzureKeyVaultLifecycleCompatibilityState = Literal[
    "compatible",
    "incompatible",
    "unknown",
    "not_applicable",
]


class _AzureKeyVaultAuthorizationGrantRequired(TypedDict):
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
    identity_kind: AzureKeyVaultRuntimeIdentityKind
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
    grant_kind: AzureKeyVaultGrantKind
    grant_basis: AzureKeyVaultGrantBasis
    grant_source_address: str
    grant_source_type: str | None
    scope_type: AzureKeyVaultPathScopeType
    scope: str | None
    scope_arm_id: str | None
    authorization_model: AzureKeyVaultAuthorizationModel
    authorization_model_state: AzureKeyVaultAuthorizationModelState
    authorization_state: AzureKeyVaultAuthorizationState
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


class AzureAppServiceKeyVaultManagementPath(TypedDict):
    workload_address: str
    workload_type: str
    identity_address: str
    identity_kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str
    credential_context: Literal["workload_runtime"]
    key_vault_address: str
    key_vault_id: str
    key_address: str | None
    key_resource_type: str | None
    key_name: str | None
    key_uri: str | None
    key_versionless_uri: str | None
    key_resource_id: str | None
    key_versionless_resource_id: str | None
    key_version: str | None
    operation: AzureKeyVaultManagementOperation
    step_operations: list[str]
    operation_class: AzureKeyVaultManagementOperationClass
    management_effect: AzureKeyVaultManagementEffect
    target_type: AzureKeyVaultManagementTargetType
    target_address: str
    target_resource_id: str
    authorization_basis: AzureKeyVaultManagementAuthorizationBasis
    authorization_model: AzureKeyVaultAuthorizationModel
    authorization_model_state: AzureKeyVaultAuthorizationModelState
    authorization_state: Literal["granted"]
    delegation_mechanism: AzureKeyVaultDelegationMechanism
    grant_source_addresses: list[str]
    scope_types: list[AzureKeyVaultPathScopeType]
    scopes: list[str]
    scope_arm_ids: list[str]
    data_plane_grants: list[AzureKeyVaultAuthorizationGrant]
    control_plane_grants: list[AzureArmControlPlaneGrant]
    purge_protection_enabled: bool | None
    recovery_uncertainties: list[str]
    lifecycle_compatibility_state: AzureKeyVaultLifecycleCompatibilityState
    authorization_model_transition: Literal["azure_rbac_to_access_policy"] | None
    evaluation_basis: Literal[
        "modeled_key_vault_key_authorization",
        "modeled_arm_control_plane_authority",
    ]

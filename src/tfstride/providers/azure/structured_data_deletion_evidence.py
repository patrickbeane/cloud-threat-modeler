from __future__ import annotations

from typing import Literal, TypedDict

from tfstride.providers.azure.key_vault_evidence import (
    AzureKeyVaultRuntimeIdentityKind,
)

AzureCosmosDbItemDeletionOperation = Literal[
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/delete"
]
AzureCosmosDbItemDeletionOperationClass = Literal["item_deletion"]
AzureCosmosDbItemDeletionManagementEffect = Literal["disruption"]
AzureCosmosDbItemDeletionTargetGranularity = Literal[
    "account_item_namespace",
    "database_item_namespace",
    "container_item_namespace",
]
AzureCosmosDbItemDeletionScopeType = Literal[
    "account",
    "database",
    "container",
]
AzureCosmosDbItemDeletionLifecycleCompatibilityState = Literal["not_applicable",]


class AzureCosmosDbContinuousBackupRecoveryEvidence(TypedDict):
    recovery_evidence_scope: Literal["cosmosdb_backup_policy"]
    backup_posture_state: Literal["continuous"]
    backup_configuration_state: Literal["configured"]
    backup_type: Literal["Continuous"]
    backup_tier: str | None
    backup_interval_minutes: None
    backup_retention_hours: None
    backup_storage_redundancy: None
    uncertainties: list[str]


class AzureCosmosDbPeriodicBackupRecoveryEvidence(TypedDict):
    recovery_evidence_scope: Literal["cosmosdb_backup_policy"]
    backup_posture_state: Literal["periodic"]
    backup_configuration_state: Literal["configured"]
    backup_type: Literal["Periodic"]
    backup_tier: None
    backup_interval_minutes: int | None
    backup_retention_hours: int | None
    backup_storage_redundancy: str | None
    uncertainties: list[str]


class AzureCosmosDbProviderDefaultBackupRecoveryEvidence(TypedDict):
    recovery_evidence_scope: Literal["cosmosdb_backup_policy"]
    backup_posture_state: Literal["provider_default_periodic"]
    backup_configuration_state: Literal["not_configured"]
    backup_type: Literal["Periodic"]
    backup_tier: None
    backup_interval_minutes: Literal[240]
    backup_retention_hours: Literal[8]
    backup_storage_redundancy: Literal["Geo"]
    uncertainties: list[str]


class AzureCosmosDbUnknownBackupRecoveryEvidence(TypedDict):
    recovery_evidence_scope: Literal["cosmosdb_backup_policy"]
    backup_posture_state: Literal["unknown"]
    backup_configuration_state: Literal["configured", "unknown"]
    backup_type: str | None
    backup_tier: str | None
    backup_interval_minutes: int | None
    backup_retention_hours: int | None
    backup_storage_redundancy: str | None
    uncertainties: list[str]


AzureCosmosDbItemDeletionRecoveryEvidence = (
    AzureCosmosDbContinuousBackupRecoveryEvidence
    | AzureCosmosDbPeriodicBackupRecoveryEvidence
    | AzureCosmosDbProviderDefaultBackupRecoveryEvidence
    | AzureCosmosDbUnknownBackupRecoveryEvidence
)


class AzureAppServiceCosmosDbItemDeletionPathCommon(TypedDict):
    workload_address: str
    workload_type: str
    identity_address: str
    identity_kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str
    credential_context: Literal["workload_runtime"]
    cosmosdb_account_address: str
    cosmosdb_account_id: str
    operation: AzureCosmosDbItemDeletionOperation
    operation_class: Literal["item_deletion"]
    management_effect: Literal["disruption"]
    role_assignment_address: str
    role_assignment_id: str | None
    role_definition_reference: str
    role_definition_address: str | None
    role_definition_name: str | None
    role_kind: Literal[
        "built_in_data_contributor",
        "custom",
    ]
    role_data_actions: list[str]
    matched_data_actions: list[AzureCosmosDbItemDeletionOperation]
    grant_basis: Literal["cosmosdb_for_nosql_native_role_assignment"]
    evaluation_basis: Literal["modeled_native_rbac_assignment"]
    authorization_source_addresses: list[str]
    assignment_scope: str
    assignment_scope_state: Literal["resolved"]
    assignable_scope_compatibility_state: Literal["resolved"]
    authorization_state: Literal["granted"]
    policy_complete: Literal[True]
    authorization_model: Literal["cosmosdb_for_nosql_native_rbac"]
    lifecycle_compatibility_state: Literal["not_applicable"]
    recovery_evidence: AzureCosmosDbItemDeletionRecoveryEvidence
    posture_uncertainties: list[str]


class AzureAppServiceCosmosDbAccountItemDeletionPath(
    AzureAppServiceCosmosDbItemDeletionPathCommon,
):
    scope_type: Literal["account"]
    target_granularity: Literal["account_item_namespace"]
    target_scope: Literal["exact_cosmosdb_for_nosql_account"]
    target_model_evidence_addresses: list[str]
    cosmosdb_resource_address: str
    cosmosdb_resource_type: str
    cosmosdb_resource_id: str
    cosmosdb_database_address: None
    cosmosdb_database_id: None
    cosmosdb_database_name: None
    cosmosdb_container_address: None
    cosmosdb_container_id: None
    cosmosdb_container_name: None


class AzureAppServiceCosmosDbDatabaseItemDeletionPath(
    AzureAppServiceCosmosDbItemDeletionPathCommon,
):
    scope_type: Literal["database"]
    target_granularity: Literal["database_item_namespace"]
    target_scope: Literal["exact_cosmosdb_for_nosql_database"]
    target_model_evidence_addresses: list[str]
    cosmosdb_resource_address: str
    cosmosdb_resource_type: str
    cosmosdb_resource_id: str
    cosmosdb_database_address: str
    cosmosdb_database_id: str
    cosmosdb_database_name: str
    cosmosdb_container_address: None
    cosmosdb_container_id: None
    cosmosdb_container_name: None


class AzureAppServiceCosmosDbContainerItemDeletionPath(
    AzureAppServiceCosmosDbItemDeletionPathCommon,
):
    scope_type: Literal["container"]
    target_granularity: Literal["container_item_namespace"]
    target_scope: Literal["exact_cosmosdb_for_nosql_container"]
    target_model_evidence_addresses: list[str]
    cosmosdb_resource_address: str
    cosmosdb_resource_type: str
    cosmosdb_resource_id: str
    cosmosdb_database_address: str
    cosmosdb_database_id: str
    cosmosdb_database_name: str
    cosmosdb_container_address: str
    cosmosdb_container_id: str
    cosmosdb_container_name: str


AzureAppServiceCosmosDbItemDeletionPath = (
    AzureAppServiceCosmosDbAccountItemDeletionPath
    | AzureAppServiceCosmosDbDatabaseItemDeletionPath
    | AzureAppServiceCosmosDbContainerItemDeletionPath
)
AzureAppServiceCosmosDbItemDeletionEvidence = AzureAppServiceCosmosDbItemDeletionPath

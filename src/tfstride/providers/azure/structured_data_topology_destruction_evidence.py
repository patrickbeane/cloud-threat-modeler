from __future__ import annotations

from typing import Literal, Never, TypedDict

from tfstride.providers.azure.arm_control_plane_evidence import AzureArmScopeType
from tfstride.providers.azure.key_vault_evidence import (
    AzureKeyVaultRuntimeIdentityKind,
)

AzureCosmosDbTopologyDestructionOperation = Literal[
    "Microsoft.DocumentDB/databaseAccounts/delete",
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete",
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/delete",
]
AzureCosmosDbTopologyDestructionOperationClass = Literal[
    "account_deletion",
    "database_deletion",
    "container_deletion",
]
AzureCosmosDbTopologyDestructionInternalOperation = Literal[
    "delete_account",
    "delete_database",
    "delete_container",
]
AzureCosmosDbTopologyDestructionTargetGranularity = Literal[
    "account_topology",
    "database_topology",
    "container_topology",
]


class AzureCosmosDbTopologyBuiltInRoleEvidence(TypedDict):
    role_kind: Literal["built_in"]
    role_resolution_state: Literal["modeled_subset"]
    role_definition_address: None
    assignable_scope_compatibility_state: Literal["not_applicable"]


class AzureCosmosDbTopologyCustomRoleEvidence(TypedDict):
    role_kind: Literal["custom"]
    role_resolution_state: Literal["resolved"]
    role_definition_address: str
    assignable_scope_compatibility_state: Literal["resolved"]


AzureCosmosDbTopologyRoleEvidence = AzureCosmosDbTopologyBuiltInRoleEvidence | AzureCosmosDbTopologyCustomRoleEvidence


class AzureCosmosDbTopologyDestructionAuthorizationGrantCommon(TypedDict):
    source_address: str
    principal_id: str
    principal_type: str | None
    principal_state: Literal["resolved"]
    assignment_scope_type: AzureArmScopeType
    assignment_scope: str | None
    assignment_scope_arm_id: str
    assignment_scope_state: Literal["resolved"]
    target_arm_id: str
    role_definition_name: str | None
    role_definition_id: str | None
    role_evidence: AzureCosmosDbTopologyRoleEvidence
    role_actions: list[str]
    role_not_actions: list[str]
    excluded_actions: list[Never]
    assignment_condition: None
    assignment_condition_version: None
    assignment_condition_state: Literal["not_configured"]
    role_definition_condition_state: Literal["not_configured"]
    delegation_constraint_kind: Literal["none"]
    allowed_role_definition_ids: list[Never]
    authorization_state: Literal["granted"]
    deny_assignments_evaluated: Literal[False]
    evaluation_basis: Literal["modeled_arm_control_plane_authority"]
    cosmosdb_native_data_actions_authorization_effect: Literal["not_used_for_arm_topology_deletion"]


class AzureCosmosDbAccountDeletionAuthorizationGrant(
    AzureCosmosDbTopologyDestructionAuthorizationGrantCommon,
):
    requested_actions: list[Literal["Microsoft.DocumentDB/databaseAccounts/delete"]]
    matched_actions: list[Literal["Microsoft.DocumentDB/databaseAccounts/delete"]]


class AzureCosmosDbDatabaseDeletionAuthorizationGrant(
    AzureCosmosDbTopologyDestructionAuthorizationGrantCommon,
):
    requested_actions: list[Literal["Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete"]]
    matched_actions: list[Literal["Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete"]]


class AzureCosmosDbContainerDeletionAuthorizationGrant(
    AzureCosmosDbTopologyDestructionAuthorizationGrantCommon,
):
    requested_actions: list[Literal["Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/delete"]]
    matched_actions: list[Literal["Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/delete"]]


AzureCosmosDbTopologyDestructionAuthorizationGrant = (
    AzureCosmosDbAccountDeletionAuthorizationGrant
    | AzureCosmosDbDatabaseDeletionAuthorizationGrant
    | AzureCosmosDbContainerDeletionAuthorizationGrant
)


class AzureCosmosDbTopologyManagementLockNotObserved(TypedDict):
    lock_evidence_scope: Literal["plan_local_cosmosdb_arm_ancestry"]
    modeled_management_lock_state: Literal["not_observed"]
    applicable_lock_addresses: list[Never]
    applicable_lock_levels: list[Never]
    external_management_locks_evaluated: Literal[False]
    deletion_compatibility_state: Literal["compatible"]
    uncertainties: list[Never]


class AzureCosmosDbTopologyManagementLockBlocking(TypedDict):
    lock_evidence_scope: Literal["plan_local_cosmosdb_arm_ancestry"]
    modeled_management_lock_state: Literal["blocking"]
    blocking_lock_address: str
    blocking_lock_level: Literal["CanNotDelete", "ReadOnly"]
    applicable_lock_addresses: list[str]
    applicable_lock_levels: list[Literal["CanNotDelete", "ReadOnly"]]
    external_management_locks_evaluated: Literal[False]
    deletion_compatibility_state: Literal["blocked"]
    uncertainties: list[Never]


class AzureCosmosDbTopologyManagementLockUnknown(TypedDict):
    lock_evidence_scope: Literal["plan_local_cosmosdb_arm_ancestry"]
    modeled_management_lock_state: Literal["unknown"]
    potentially_applicable_lock_addresses: list[str]
    external_management_locks_evaluated: Literal[False]
    deletion_compatibility_state: Literal["unknown"]
    uncertainties: list[str]


AzureCosmosDbTopologyManagementLockEvidence = (
    AzureCosmosDbTopologyManagementLockNotObserved
    | AzureCosmosDbTopologyManagementLockBlocking
    | AzureCosmosDbTopologyManagementLockUnknown
)


class AzureCosmosDbTopologyRecoveryEvidenceCommon(TypedDict):
    recovery_evidence_scope: Literal["cosmosdb_topology_deletion_and_backup_policy"]
    successful_deletion_observed: Literal[False]
    restoration_observed: Literal[False]
    immediate_restoration_established: Literal[False]
    restore_target_evaluated: Literal[False]
    out_of_plan_restore_resources_evaluated: Literal[False]
    uncertainties: list[str]


class AzureCosmosDbTopologyContinuousBackupRecoveryEvidence(
    AzureCosmosDbTopologyRecoveryEvidenceCommon,
):
    backup_posture_state: Literal["continuous"]
    backup_configuration_state: Literal["configured"]
    backup_type: Literal["Continuous"]
    backup_tier: str | None
    backup_interval_minutes: None
    backup_retention_hours: None
    backup_storage_redundancy: None
    topology_recovery_state: Literal["continuous_backup_recovery_configured"]


class AzureCosmosDbTopologyPeriodicBackupRecoveryEvidence(
    AzureCosmosDbTopologyRecoveryEvidenceCommon,
):
    backup_posture_state: Literal["periodic"]
    backup_configuration_state: Literal["configured"]
    backup_type: Literal["Periodic"]
    backup_tier: None
    backup_interval_minutes: int | None
    backup_retention_hours: int | None
    backup_storage_redundancy: str | None
    topology_recovery_state: Literal["periodic_backup_recovery_configured"]


class AzureCosmosDbTopologyProviderDefaultBackupRecoveryEvidence(
    AzureCosmosDbTopologyRecoveryEvidenceCommon,
):
    backup_posture_state: Literal["provider_default_periodic"]
    backup_configuration_state: Literal["not_configured"]
    backup_type: Literal["Periodic"]
    backup_tier: None
    backup_interval_minutes: Literal[240]
    backup_retention_hours: Literal[8]
    backup_storage_redundancy: Literal["Geo"]
    topology_recovery_state: Literal["periodic_backup_recovery_configured"]


class AzureCosmosDbTopologyUnknownBackupRecoveryEvidence(
    AzureCosmosDbTopologyRecoveryEvidenceCommon,
):
    backup_posture_state: Literal["unknown"]
    backup_configuration_state: Literal["configured", "unknown"]
    backup_type: str | None
    backup_tier: str | None
    backup_interval_minutes: int | None
    backup_retention_hours: int | None
    backup_storage_redundancy: str | None
    topology_recovery_state: Literal["unknown"]


AzureCosmosDbTopologyDestructionRecoveryEvidence = (
    AzureCosmosDbTopologyContinuousBackupRecoveryEvidence
    | AzureCosmosDbTopologyPeriodicBackupRecoveryEvidence
    | AzureCosmosDbTopologyProviderDefaultBackupRecoveryEvidence
    | AzureCosmosDbTopologyUnknownBackupRecoveryEvidence
)


class AzureAppServiceCosmosDbTopologyDestructionPathCommon(TypedDict):
    workload_address: str
    workload_type: str
    identity_address: str
    identity_kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str
    credential_context: Literal["workload_runtime"]
    cosmosdb_account_address: str
    cosmosdb_account_id: str
    cosmosdb_resource_address: str
    cosmosdb_resource_type: str
    cosmosdb_resource_id: str
    target_model_evidence_addresses: list[str]
    management_effect: Literal["disruption"]
    authorization_evidence_kind: Literal["azure_rbac_action"]
    role_assignment_address: str
    authorization_source_addresses: list[str]
    authorization_state: Literal["granted"]
    modeled_allow_evidence_complete: Literal[True]
    condition: None
    condition_state: Literal["not_configured"]
    lifecycle_compatibility_state: Literal["compatible"]
    management_lock_evidence: AzureCosmosDbTopologyManagementLockNotObserved
    recovery_evidence: AzureCosmosDbTopologyDestructionRecoveryEvidence
    descendant_impact_evaluated: Literal[False]
    out_of_plan_topology_evaluated: Literal[False]
    posture_uncertainties: list[str]


class AzureAppServiceCosmosDbAccountTopologyDeletionPath(
    AzureAppServiceCosmosDbTopologyDestructionPathCommon,
):
    cosmosdb_resource_kind: Literal["account"]
    operation: Literal["Microsoft.DocumentDB/databaseAccounts/delete"]
    operation_class: Literal["account_deletion"]
    internal_operation: Literal["delete_account"]
    target_granularity: Literal["account_topology"]
    target_scope: Literal["exact_cosmosdb_account"]
    cosmosdb_database_address: None
    cosmosdb_database_id: None
    cosmosdb_database_name: None
    cosmosdb_container_address: None
    cosmosdb_container_id: None
    cosmosdb_container_name: None
    authorization_grant: AzureCosmosDbAccountDeletionAuthorizationGrant


class AzureAppServiceCosmosDbDatabaseTopologyDeletionPath(
    AzureAppServiceCosmosDbTopologyDestructionPathCommon,
):
    cosmosdb_resource_kind: Literal["database"]
    operation: Literal["Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete"]
    operation_class: Literal["database_deletion"]
    internal_operation: Literal["delete_database"]
    target_granularity: Literal["database_topology"]
    target_scope: Literal["exact_cosmosdb_sql_database"]
    cosmosdb_database_address: str
    cosmosdb_database_id: str
    cosmosdb_database_name: str
    cosmosdb_container_address: None
    cosmosdb_container_id: None
    cosmosdb_container_name: None
    authorization_grant: AzureCosmosDbDatabaseDeletionAuthorizationGrant


class AzureAppServiceCosmosDbContainerTopologyDeletionPath(
    AzureAppServiceCosmosDbTopologyDestructionPathCommon,
):
    cosmosdb_resource_kind: Literal["container"]
    operation: Literal["Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/delete"]
    operation_class: Literal["container_deletion"]
    internal_operation: Literal["delete_container"]
    target_granularity: Literal["container_topology"]
    target_scope: Literal["exact_cosmosdb_sql_container"]
    cosmosdb_database_address: str
    cosmosdb_database_id: str
    cosmosdb_database_name: str
    cosmosdb_container_address: str
    cosmosdb_container_id: str
    cosmosdb_container_name: str
    authorization_grant: AzureCosmosDbContainerDeletionAuthorizationGrant


AzureAppServiceCosmosDbTopologyDestructionPath = (
    AzureAppServiceCosmosDbAccountTopologyDeletionPath
    | AzureAppServiceCosmosDbDatabaseTopologyDeletionPath
    | AzureAppServiceCosmosDbContainerTopologyDeletionPath
)
AzureAppServiceCosmosDbTopologyDestructionEvidence = AzureAppServiceCosmosDbTopologyDestructionPath

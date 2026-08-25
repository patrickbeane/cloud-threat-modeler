from __future__ import annotations

from typing import Literal, Never, TypedDict

from tfstride.providers.azure.arm_control_plane_evidence import AzureArmScopeType
from tfstride.providers.azure.key_vault_evidence import (
    AzureKeyVaultRuntimeIdentityKind,
)

AzureStorageContainerTopologyDestructionOperation = Literal[
    "Microsoft.Storage/storageAccounts/blobServices/containers/delete"
]
AzureStorageContainerTopologyDestructionOperationClass = Literal["container_deletion"]
AzureStorageContainerTopologyDestructionInternalOperation = Literal["delete_container"]
AzureStorageContainerTopologyDestructionTargetGranularity = Literal["container_topology"]


class AzureStorageContainerTopologyBuiltInRoleEvidence(TypedDict):
    role_kind: Literal["built_in"]
    role_resolution_state: Literal["modeled_subset"]
    role_definition_address: None
    assignable_scope_compatibility_state: Literal["not_applicable"]


class AzureStorageContainerTopologyCustomRoleEvidence(TypedDict):
    role_kind: Literal["custom"]
    role_resolution_state: Literal["resolved"]
    role_definition_address: str
    assignable_scope_compatibility_state: Literal["resolved"]


AzureStorageContainerTopologyRoleEvidence = (
    AzureStorageContainerTopologyBuiltInRoleEvidence | AzureStorageContainerTopologyCustomRoleEvidence
)


class AzureStorageContainerTopologyDestructionAuthorizationGrant(TypedDict):
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
    role_evidence: AzureStorageContainerTopologyRoleEvidence
    role_actions: list[str]
    role_not_actions: list[str]
    requested_actions: list[Literal["Microsoft.Storage/storageAccounts/blobServices/containers/delete"]]
    matched_actions: list[Literal["Microsoft.Storage/storageAccounts/blobServices/containers/delete"]]
    excluded_actions: list[Never]
    assignment_condition: None
    assignment_condition_version: None
    assignment_condition_state: Literal["not_configured"]
    role_definition_condition_state: Literal["not_configured"]
    delegation_constraint_kind: Literal["none"]
    allowed_role_definition_ids: list[Never]
    authorization_state: Literal["granted"]
    deny_assignments_evaluated: Literal[False]
    evaluation_basis: Literal["modeled_azure_rbac_action_authority"]


class AzureStorageContainerTopologyDeletionConstraintsCompatible(TypedDict):
    constraint_evidence_scope: Literal["plan_local_storage_container_immutability_and_legal_hold"]
    has_immutability_policy: Literal[False]
    has_legal_hold: Literal[False]
    constraint_state: Literal["not_observed"]
    protected_content_emptiness_required: Literal[False]
    protected_content_emptiness_state: Literal["not_applicable"]
    arm_management_lock_applicability: Literal["not_applicable_to_storage_container_deletion"]
    uncertainties: list[str]


class AzureStorageContainerTopologyDeletionConstraintsBlockingCommon(TypedDict):
    constraint_evidence_scope: Literal["plan_local_storage_container_immutability_and_legal_hold"]
    constraint_state: Literal["blocking"]
    arm_management_lock_applicability: Literal["not_applicable_to_storage_container_deletion"]
    uncertainties: list[Never]


class AzureStorageContainerTopologyDeletionImmutabilityBlocking(
    AzureStorageContainerTopologyDeletionConstraintsBlockingCommon,
):
    has_immutability_policy: Literal[True]
    has_legal_hold: bool


class AzureStorageContainerTopologyDeletionLegalHoldBlocking(
    AzureStorageContainerTopologyDeletionConstraintsBlockingCommon,
):
    has_immutability_policy: Literal[False]
    has_legal_hold: Literal[True]


AzureStorageContainerTopologyDeletionConstraintsBlocking = (
    AzureStorageContainerTopologyDeletionImmutabilityBlocking | AzureStorageContainerTopologyDeletionLegalHoldBlocking
)


class AzureStorageContainerTopologyDeletionConstraintsUnknown(TypedDict):
    constraint_evidence_scope: Literal["plan_local_storage_container_immutability_and_legal_hold"]
    has_immutability_policy: bool | None
    has_legal_hold: bool | None
    constraint_state: Literal[
        "protected_content_emptiness_not_established",
        "unknown",
    ]
    protected_content_emptiness_required: bool | None
    protected_content_emptiness_state: Literal["not_established", "unknown"]
    arm_management_lock_applicability: Literal["not_applicable_to_storage_container_deletion"]
    uncertainties: list[str]


AzureStorageContainerTopologyDeletionConstraintEvidence = (
    AzureStorageContainerTopologyDeletionConstraintsCompatible
    | AzureStorageContainerTopologyDeletionImmutabilityBlocking
    | AzureStorageContainerTopologyDeletionLegalHoldBlocking
    | AzureStorageContainerTopologyDeletionConstraintsUnknown
)


class AzureStorageContainerTopologyDestructionRecoveryEvidenceCommon(
    TypedDict,
):
    recovery_evidence_scope: Literal["azure_storage_container_soft_delete"]
    successful_deletion_observed: Literal[False]
    restoration_observed: Literal[False]
    storage_account_deletion_evaluated: Literal[False]
    out_of_plan_blob_inventory_evaluated: Literal[False]
    uncertainties: list[str]


class AzureStorageContainerSoftDeleteEnabledRecoveryEvidence(
    AzureStorageContainerTopologyDestructionRecoveryEvidenceCommon,
):
    container_soft_delete_state: Literal["enabled"]
    container_delete_retention_days: int
    container_recovery_state: Literal["soft_delete_recovery_configured"]


class AzureStorageContainerSoftDeleteDisabledRecoveryEvidence(
    AzureStorageContainerTopologyDestructionRecoveryEvidenceCommon,
):
    container_soft_delete_state: Literal["disabled"]
    container_delete_retention_days: None
    container_recovery_state: Literal["not_established_by_modeled_azure_storage_container_evidence"]


class AzureStorageContainerSoftDeleteUnknownRecoveryEvidence(
    AzureStorageContainerTopologyDestructionRecoveryEvidenceCommon,
):
    container_soft_delete_state: Literal["unknown"]
    container_delete_retention_days: None
    container_recovery_state: Literal["unknown"]


AzureStorageContainerTopologyDestructionRecoveryEvidence = (
    AzureStorageContainerSoftDeleteEnabledRecoveryEvidence
    | AzureStorageContainerSoftDeleteDisabledRecoveryEvidence
    | AzureStorageContainerSoftDeleteUnknownRecoveryEvidence
)


class AzureAppServiceStorageContainerTopologyDestructionPathCommon(TypedDict):
    workload_address: str
    workload_type: str
    identity_address: str
    identity_kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str
    credential_context: Literal["workload_runtime"]
    storage_account_address: str
    storage_account_id: str
    container_address: str
    container_name: str
    container_resource_manager_id: str
    operation: Literal["Microsoft.Storage/storageAccounts/blobServices/containers/delete"]
    operation_class: Literal["container_deletion"]
    internal_operation: Literal["delete_container"]
    management_effect: Literal["disruption"]
    authorization_evidence_kind: Literal["azure_rbac_action"]
    target_granularity: Literal["container_topology"]
    target_scope: Literal["exact_storage_container"]
    target_model_evidence_addresses: list[str]
    role_assignment_address: str
    authorization_source_addresses: list[str]
    authorization_state: Literal["granted"]
    modeled_allow_evidence_complete: Literal[True]
    condition: None
    condition_state: Literal["not_configured"]
    authorization_grant: AzureStorageContainerTopologyDestructionAuthorizationGrant
    recovery_evidence: AzureStorageContainerTopologyDestructionRecoveryEvidence
    posture_uncertainties: list[str]


class AzureAppServiceStorageContainerTopologyDestructionCompatiblePath(
    AzureAppServiceStorageContainerTopologyDestructionPathCommon,
):
    lifecycle_compatibility_state: Literal["compatible"]
    deletion_constraint_evidence: AzureStorageContainerTopologyDeletionConstraintsCompatible


class AzureAppServiceStorageContainerTopologyDestructionUnknownPath(
    AzureAppServiceStorageContainerTopologyDestructionPathCommon,
):
    lifecycle_compatibility_state: Literal["unknown"]
    deletion_constraint_evidence: AzureStorageContainerTopologyDeletionConstraintsUnknown


AzureAppServiceStorageContainerTopologyDestructionPath = (
    AzureAppServiceStorageContainerTopologyDestructionCompatiblePath
    | AzureAppServiceStorageContainerTopologyDestructionUnknownPath
)
AzureAppServiceStorageContainerTopologyDestructionEvidence = AzureAppServiceStorageContainerTopologyDestructionPath

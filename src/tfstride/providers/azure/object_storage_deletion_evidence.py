from __future__ import annotations

from typing import Literal, TypedDict

from tfstride.providers.azure.key_vault_evidence import (
    AzureKeyVaultRuntimeIdentityKind,
)

AzureBlobStandardDeletionOperation = Literal[
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action",
]
AzureBlobPermanentDeletionOperation = Literal[
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/permanentDelete/action"
]
AzureBlobDeletionOperation = AzureBlobStandardDeletionOperation | AzureBlobPermanentDeletionOperation
AzureBlobStandardDeletionOperationClass = Literal[
    "logical_blob_deletion",
    "blob_version_deletion",
]
AzureBlobPermanentDeletionOperationClass = Literal["soft_deleted_blob_data_permanent_deletion"]
AzureBlobDeletionOperationClass = AzureBlobStandardDeletionOperationClass | AzureBlobPermanentDeletionOperationClass
AzureBlobDeletionManagementEffect = Literal["disruption"]
AzureBlobDeletionTargetGranularity = Literal[
    "blob",
    "blob_version",
    "snapshot",
    "blob_prefix",
    "container_blob_namespace",
    "container_blob_version_namespace",
]
AzureBlobPermanentDeletionTargetGranularity = Literal[
    "blob_version",
    "snapshot",
]
AzureBlobDeletionAuthorizationState = Literal[
    "granted",
    "denied",
    "conditional",
    "unknown",
    "not_modeled",
]
AzureBlobDeletionLifecycleCompatibilityState = Literal[
    "compatible",
    "incompatible",
    "unknown",
    "not_applicable",
]


class AzureBlobDeletionRecoveryEvidence(TypedDict):
    recovery_evidence_scope: Literal["azure_blob_versioning_and_soft_delete"]
    versioning_enabled: bool | None
    blob_delete_retention_days: int | None
    permanent_delete_enabled: bool | None
    hierarchical_namespace_enabled: bool | None
    uncertainties: list[str]


class AzureAppServiceBlobDeletionPathCommon(TypedDict):
    workload_address: str
    workload_type: str
    identity_address: str
    identity_kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str
    credential_context: Literal["workload_runtime"]
    storage_account_address: str
    storage_account_id: str | None
    container_address: str | None
    container_resource_id: str | None
    target_scope: str
    target_model_evidence_addresses: list[str]
    role_assignment_address: str
    role_definition_name: str
    role_definition_id: str | None
    role_definition_address: str | None
    grant_basis: str
    assignment_scope: str | None
    assignment_scope_kind: str | None
    authorization_source_addresses: list[str]
    matched_data_actions: list[AzureBlobDeletionOperation]
    excluded_data_actions: list[str]
    condition: None
    condition_state: Literal["not_configured"]
    authorization_state: Literal["granted"]
    policy_complete: Literal[True]
    recovery_evidence: AzureBlobDeletionRecoveryEvidence
    posture_uncertainties: list[str]


class AzureAppServiceExactBlobDeletionPath(AzureAppServiceBlobDeletionPathCommon):
    operation: Literal["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"]
    operation_class: Literal["logical_blob_deletion"]
    management_effect: AzureBlobDeletionManagementEffect
    target_granularity: Literal["blob"]
    blob_name: str
    blob_version: None
    snapshot: None
    lifecycle_compatibility_state: AzureBlobDeletionLifecycleCompatibilityState


class AzureAppServiceBlobPrefixDeletionPath(AzureAppServiceBlobDeletionPathCommon):
    operation: Literal["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"]
    operation_class: Literal["logical_blob_deletion"]
    management_effect: AzureBlobDeletionManagementEffect
    target_granularity: Literal["blob_prefix"]
    blob_name: str
    blob_version: None
    snapshot: None
    lifecycle_compatibility_state: AzureBlobDeletionLifecycleCompatibilityState


class AzureAppServiceContainerBlobNamespaceDeletionPath(AzureAppServiceBlobDeletionPathCommon):
    operation: Literal["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"]
    operation_class: Literal["logical_blob_deletion"]
    management_effect: AzureBlobDeletionManagementEffect
    target_granularity: Literal["container_blob_namespace"]
    blob_name: None
    blob_version: None
    snapshot: None
    lifecycle_compatibility_state: AzureBlobDeletionLifecycleCompatibilityState


class AzureAppServiceBlobVersionDeletionPath(AzureAppServiceBlobDeletionPathCommon):
    operation: Literal["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action"]
    operation_class: Literal["blob_version_deletion"]
    management_effect: AzureBlobDeletionManagementEffect
    target_granularity: Literal["blob_version"]
    blob_name: str
    blob_version: str
    snapshot: None
    lifecycle_compatibility_state: AzureBlobDeletionLifecycleCompatibilityState


class AzureAppServiceBlobVersionNamespaceDeletionPath(AzureAppServiceBlobDeletionPathCommon):
    operation: Literal["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action"]
    operation_class: Literal["blob_version_deletion"]
    management_effect: AzureBlobDeletionManagementEffect
    target_granularity: Literal["container_blob_version_namespace"]
    blob_name: None
    blob_version: None
    snapshot: None
    lifecycle_compatibility_state: AzureBlobDeletionLifecycleCompatibilityState


class AzureAppServiceBlobPermanentVersionDeletionPath(AzureAppServiceBlobDeletionPathCommon):
    operation: AzureBlobPermanentDeletionOperation
    operation_class: AzureBlobPermanentDeletionOperationClass
    management_effect: AzureBlobDeletionManagementEffect
    target_granularity: Literal["blob_version"]
    blob_name: str
    blob_version: str
    snapshot: None
    permanent_delete_enabled: Literal[True]
    soft_deleted_target_state: Literal["soft_deleted"]
    lifecycle_compatibility_state: Literal["compatible"]


class AzureAppServiceBlobPermanentSnapshotDeletionPath(AzureAppServiceBlobDeletionPathCommon):
    operation: AzureBlobPermanentDeletionOperation
    operation_class: AzureBlobPermanentDeletionOperationClass
    management_effect: AzureBlobDeletionManagementEffect
    target_granularity: Literal["snapshot"]
    blob_name: str
    blob_version: None
    snapshot: str
    permanent_delete_enabled: Literal[True]
    soft_deleted_target_state: Literal["soft_deleted"]
    lifecycle_compatibility_state: Literal["compatible"]


AzureAppServiceBlobDeletionPath = (
    AzureAppServiceExactBlobDeletionPath
    | AzureAppServiceBlobPrefixDeletionPath
    | AzureAppServiceContainerBlobNamespaceDeletionPath
    | AzureAppServiceBlobVersionDeletionPath
    | AzureAppServiceBlobVersionNamespaceDeletionPath
    | AzureAppServiceBlobPermanentVersionDeletionPath
    | AzureAppServiceBlobPermanentSnapshotDeletionPath
)
AzureAppServiceBlobDeletionEvidence = AzureAppServiceBlobDeletionPath

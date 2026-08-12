from __future__ import annotations

from typing import Literal, NotRequired, TypedDict

GcpFirestoreDeletionOperation = Literal[
    "datastore.entities.delete",
    "datastore.databases.bulkDelete",
]
GcpFirestoreDeletionOperationClass = Literal[
    "entity_deletion",
    "bulk_entity_deletion",
]
GcpFirestoreDeletionManagementEffect = Literal["disruption"]
GcpFirestoreDeletionTargetGranularity = Literal[
    "database_entity_namespace",
    "database_bulk_entity_namespace",
]
GcpFirestoreDeletionScopeType = Literal["project", "database"]
GcpFirestoreDeletionLifecycleCompatibilityState = Literal["not_applicable",]
GcpFirestoreActiveCustomRoleStage = Literal[
    "ALPHA",
    "BETA",
    "DEPRECATED",
    "EAP",
    "GA",
]


class GcpFirestoreExactDatabaseConditionEvidence(TypedDict):
    expression: str
    title: NotRequired[str]
    description: NotRequired[str]


class GcpFirestorePitrEnabledRecoveryEvidence(TypedDict):
    recovery_evidence_scope: Literal["firestore_point_in_time_recovery"]
    pitr_state: Literal["enabled"]
    pitr_enabled: Literal[True]
    historical_version_retention_state: Literal["pitr_up_to_seven_days"]
    uncertainties: list[str]


class GcpFirestorePitrDisabledRecoveryEvidence(TypedDict):
    recovery_evidence_scope: Literal["firestore_point_in_time_recovery"]
    pitr_state: Literal["disabled"]
    pitr_enabled: Literal[False]
    historical_version_retention_state: Literal["native_approximately_one_hour"]
    uncertainties: list[str]


class GcpFirestorePitrProviderDefaultRecoveryEvidence(TypedDict):
    recovery_evidence_scope: Literal["firestore_point_in_time_recovery"]
    pitr_state: Literal["not_configured"]
    pitr_enabled: Literal[False]
    historical_version_retention_state: Literal["native_approximately_one_hour"]
    uncertainties: list[str]


class GcpFirestorePitrUnknownRecoveryEvidence(TypedDict):
    recovery_evidence_scope: Literal["firestore_point_in_time_recovery"]
    pitr_state: Literal["unknown"]
    pitr_enabled: None
    historical_version_retention_state: Literal["unknown"]
    uncertainties: list[str]


GcpFirestoreDeletionRecoveryEvidence = (
    GcpFirestorePitrEnabledRecoveryEvidence
    | GcpFirestorePitrDisabledRecoveryEvidence
    | GcpFirestorePitrProviderDefaultRecoveryEvidence
    | GcpFirestorePitrUnknownRecoveryEvidence
)


class GcpCloudRunFirestoreDeletionPathCommon(TypedDict):
    workload_address: str
    workload_type: str
    service_account_email: str
    service_account_member: str
    identity_kind: Literal["cloud_run_service_account"]
    credential_context: Literal["workload_runtime"]
    firestore_database_address: str
    firestore_database_resource_type: str
    firestore_database_resource_name: str
    firestore_database_name: str
    firestore_database_project: str
    firestore_database_type: str
    target_model_evidence_addresses: list[str]
    management_effect: Literal["disruption"]
    iam_resource_address: str
    iam_resource_type: str
    iam_source_addresses: list[str]
    role: str
    role_kind: str
    role_definition_address: str | None
    custom_role_permissions: list[str]
    custom_role_stage: GcpFirestoreActiveCustomRoleStage | None
    custom_role_deleted: Literal[False] | None
    grant_basis: str
    authorization_state: Literal["granted"]
    policy_complete: Literal[True]
    authorization_model: Literal["iam_authorized_server_api"]
    firestore_security_rules_evaluated: Literal[False]
    firestore_security_rules_applicability: Literal["not_in_server_api_authorization_path"]
    lifecycle_compatibility_state: Literal["not_applicable"]
    recovery_evidence: GcpFirestoreDeletionRecoveryEvidence
    posture_uncertainties: list[str]


class GcpCloudRunFirestoreEntityDeletionPathCommon(
    GcpCloudRunFirestoreDeletionPathCommon,
):
    operation: Literal["datastore.entities.delete"]
    operation_class: Literal["entity_deletion"]
    target_granularity: Literal["database_entity_namespace"]
    matched_permissions: list[Literal["datastore.entities.delete"]]


class GcpCloudRunFirestoreBulkEntityDeletionPathCommon(
    GcpCloudRunFirestoreDeletionPathCommon,
):
    operation: Literal["datastore.databases.bulkDelete"]
    operation_class: Literal["bulk_entity_deletion"]
    target_granularity: Literal["database_bulk_entity_namespace"]
    matched_permissions: list[Literal["datastore.databases.bulkDelete"]]


class GcpCloudRunFirestoreProjectEntityDeletionPath(
    GcpCloudRunFirestoreEntityDeletionPathCommon,
):
    scope_type: Literal["project"]
    scope: str
    resource_scope: Literal["firestore_project"]
    condition: None
    condition_state: Literal["not_configured"]
    condition_evaluation: Literal["not_configured"]


class GcpCloudRunFirestoreDatabaseEntityDeletionPath(
    GcpCloudRunFirestoreEntityDeletionPathCommon,
):
    scope_type: Literal["database"]
    scope: str
    resource_scope: Literal["exact_firestore_database"]
    condition: GcpFirestoreExactDatabaseConditionEvidence
    condition_state: Literal["configured"]
    condition_evaluation: Literal["exact_database_scope_match"]


class GcpCloudRunFirestoreProjectBulkEntityDeletionPath(
    GcpCloudRunFirestoreBulkEntityDeletionPathCommon,
):
    scope_type: Literal["project"]
    scope: str
    resource_scope: Literal["firestore_project"]
    condition: None
    condition_state: Literal["not_configured"]
    condition_evaluation: Literal["not_configured"]


class GcpCloudRunFirestoreDatabaseBulkEntityDeletionPath(
    GcpCloudRunFirestoreBulkEntityDeletionPathCommon,
):
    scope_type: Literal["database"]
    scope: str
    resource_scope: Literal["exact_firestore_database"]
    condition: GcpFirestoreExactDatabaseConditionEvidence
    condition_state: Literal["configured"]
    condition_evaluation: Literal["exact_database_scope_match"]


GcpCloudRunFirestoreDeletionPath = (
    GcpCloudRunFirestoreProjectEntityDeletionPath
    | GcpCloudRunFirestoreDatabaseEntityDeletionPath
    | GcpCloudRunFirestoreProjectBulkEntityDeletionPath
    | GcpCloudRunFirestoreDatabaseBulkEntityDeletionPath
)
GcpCloudRunFirestoreDeletionEvidence = GcpCloudRunFirestoreDeletionPath

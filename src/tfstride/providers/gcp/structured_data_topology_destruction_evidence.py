from __future__ import annotations

from typing import Literal, Never, NotRequired, TypedDict

GcpFirestoreDatabaseTopologyDestructionOperation = Literal["datastore.databases.delete"]
GcpFirestoreDatabaseTopologyDestructionOperationClass = Literal["database_deletion"]
GcpFirestoreDatabaseTopologyDestructionInternalOperation = Literal["delete_database"]
GcpFirestoreDatabaseTopologyDestructionTargetGranularity = Literal["database_topology"]
GcpFirestoreDatabaseTopologyDestructionScopeType = Literal[
    "project",
    "database",
]
GcpFirestoreTopologyActiveCustomRoleStage = Literal[
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


class GcpFirestoreTopologyProjectBuiltInRoleEvidence(TypedDict):
    role_kind: Literal[
        "owner",
        "datastore_owner",
        "datastore_admin",
        "firebase_admin",
        "firebase_develop_admin",
    ]
    role_definition_address: None
    custom_role_permissions: list[Never]
    custom_role_stage: None
    custom_role_deleted: None
    custom_role_wildcard_permissions_present: Literal[False]
    custom_role_grant_scope_compatibility_state: Literal["not_applicable"]


class GcpFirestoreTopologyDatabaseBuiltInRoleEvidence(TypedDict):
    role_kind: Literal[
        "datastore_owner",
        "datastore_admin",
        "firebase_admin",
        "firebase_develop_admin",
    ]
    role_definition_address: None
    custom_role_permissions: list[Never]
    custom_role_stage: None
    custom_role_deleted: None
    custom_role_wildcard_permissions_present: Literal[False]
    custom_role_grant_scope_compatibility_state: Literal["not_applicable"]


class GcpFirestoreTopologyCustomRoleEvidence(TypedDict):
    role_kind: Literal["custom"]
    role_definition_address: str
    custom_role_permissions: list[str]
    custom_role_stage: GcpFirestoreTopologyActiveCustomRoleStage
    custom_role_deleted: Literal[False]
    custom_role_wildcard_permissions_present: Literal[False]
    custom_role_grant_scope_compatibility_state: Literal["compatible"]


GcpFirestoreTopologyProjectRoleEvidence = (
    GcpFirestoreTopologyProjectBuiltInRoleEvidence | GcpFirestoreTopologyCustomRoleEvidence
)
GcpFirestoreTopologyDatabaseRoleEvidence = (
    GcpFirestoreTopologyDatabaseBuiltInRoleEvidence | GcpFirestoreTopologyCustomRoleEvidence
)


class GcpFirestoreDatabaseDeleteProtectionEnabled(TypedDict):
    constraint_evidence_scope: Literal["firestore_database_delete_protection"]
    delete_protection_state: Literal["DELETE_PROTECTION_ENABLED"]
    delete_protection_enablement: Literal["enabled"]
    delete_protection_enabled: Literal[True]
    provider_default_applied: Literal[False]
    deletion_compatibility_state: Literal["blocked"]
    uncertainties: list[Never]


class GcpFirestoreDatabaseDeleteProtectionDisabled(TypedDict):
    constraint_evidence_scope: Literal["firestore_database_delete_protection"]
    delete_protection_state: Literal["DELETE_PROTECTION_DISABLED"]
    delete_protection_enablement: Literal["disabled"]
    delete_protection_enabled: Literal[False]
    provider_default_applied: Literal[False]
    deletion_compatibility_state: Literal["compatible"]
    uncertainties: list[Never]


class GcpFirestoreDatabaseDeleteProtectionProviderDefault(TypedDict):
    constraint_evidence_scope: Literal["firestore_database_delete_protection"]
    delete_protection_state: Literal["DELETE_PROTECTION_STATE_UNSPECIFIED"] | None
    delete_protection_enablement: Literal["not_configured"]
    delete_protection_enabled: Literal[False]
    provider_default_applied: Literal[True]
    deletion_compatibility_state: Literal["compatible"]
    uncertainties: list[Never]


class GcpFirestoreDatabaseDeleteProtectionUnknown(TypedDict):
    constraint_evidence_scope: Literal["firestore_database_delete_protection"]
    delete_protection_state: str | None
    delete_protection_enablement: Literal["unknown"]
    delete_protection_enabled: None
    provider_default_applied: Literal[False]
    deletion_compatibility_state: Literal["unknown"]
    uncertainties: list[str]


GcpFirestoreDatabaseDeletionConstraintEvidence = (
    GcpFirestoreDatabaseDeleteProtectionEnabled
    | GcpFirestoreDatabaseDeleteProtectionDisabled
    | GcpFirestoreDatabaseDeleteProtectionProviderDefault
    | GcpFirestoreDatabaseDeleteProtectionUnknown
)
GcpFirestoreDatabaseDeletionCompatibleConstraintEvidence = (
    GcpFirestoreDatabaseDeleteProtectionDisabled | GcpFirestoreDatabaseDeleteProtectionProviderDefault
)


class GcpFirestoreTerraformDeletionPolicyEvidenceCommon(TypedDict):
    evidence_scope: Literal["terraform_firestore_database_deletion_policy"]
    runtime_api_authorization_effect: Literal["none"]


class GcpFirestoreTerraformDeletionPolicyConfigured(
    GcpFirestoreTerraformDeletionPolicyEvidenceCommon,
):
    policy_state: Literal["configured"]
    policy: Literal["ABANDON", "DELETE"]
    uncertainties: list[Never]


class GcpFirestoreTerraformDeletionPolicyNotConfigured(
    GcpFirestoreTerraformDeletionPolicyEvidenceCommon,
):
    policy_state: Literal["not_configured"]
    policy: None
    uncertainties: list[Never]


class GcpFirestoreTerraformDeletionPolicyUnknown(
    GcpFirestoreTerraformDeletionPolicyEvidenceCommon,
):
    policy_state: Literal["unknown"]
    policy: str | None
    uncertainties: list[str]


GcpFirestoreTerraformDeletionPolicyEvidence = (
    GcpFirestoreTerraformDeletionPolicyConfigured
    | GcpFirestoreTerraformDeletionPolicyNotConfigured
    | GcpFirestoreTerraformDeletionPolicyUnknown
)


class GcpFirestoreDatabaseTopologyRecoveryEvidenceCommon(TypedDict):
    recovery_evidence_scope: Literal["firestore_database_deletion_and_point_in_time_recovery"]
    successful_deletion_observed: Literal[False]
    restoration_observed: Literal[False]
    database_content_prerequisites_evaluated: Literal[False]
    app_engine_search_and_blob_entity_prerequisite_state: Literal["not_established"]
    eventarc_trigger_impact_evaluated: Literal[False]
    out_of_plan_topology_evaluated: Literal[False]
    uncertainties: list[str]


class GcpFirestoreDatabasePitrEnabledRecoveryEvidence(
    GcpFirestoreDatabaseTopologyRecoveryEvidenceCommon,
):
    pitr_state: Literal["enabled"]
    pitr_enabled: Literal[True]
    historical_version_retention_state: Literal["pitr_up_to_seven_days"]
    database_recovery_state: Literal["not_established_by_modeled_firestore_pitr_evidence"]


class GcpFirestoreDatabasePitrDisabledRecoveryEvidence(
    GcpFirestoreDatabaseTopologyRecoveryEvidenceCommon,
):
    pitr_state: Literal["disabled"]
    pitr_enabled: Literal[False]
    historical_version_retention_state: Literal["native_approximately_one_hour"]
    database_recovery_state: Literal["not_established_by_modeled_firestore_pitr_evidence"]


class GcpFirestoreDatabasePitrProviderDefaultRecoveryEvidence(
    GcpFirestoreDatabaseTopologyRecoveryEvidenceCommon,
):
    pitr_state: Literal["not_configured"]
    pitr_enabled: Literal[False]
    historical_version_retention_state: Literal["native_approximately_one_hour"]
    database_recovery_state: Literal["not_established_by_modeled_firestore_pitr_evidence"]


class GcpFirestoreDatabasePitrUnknownRecoveryEvidence(
    GcpFirestoreDatabaseTopologyRecoveryEvidenceCommon,
):
    pitr_state: Literal["unknown"]
    pitr_enabled: None
    historical_version_retention_state: Literal["unknown"]
    database_recovery_state: Literal["unknown"]


GcpFirestoreDatabaseTopologyDestructionRecoveryEvidence = (
    GcpFirestoreDatabasePitrEnabledRecoveryEvidence
    | GcpFirestoreDatabasePitrDisabledRecoveryEvidence
    | GcpFirestoreDatabasePitrProviderDefaultRecoveryEvidence
    | GcpFirestoreDatabasePitrUnknownRecoveryEvidence
)


class GcpCloudRunFirestoreDatabaseTopologyDestructionPathCommon(TypedDict):
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
    operation: Literal["datastore.databases.delete"]
    operation_class: Literal["database_deletion"]
    internal_operation: Literal["delete_database"]
    management_effect: Literal["disruption"]
    target_granularity: Literal["database_topology"]
    target_scope: Literal["exact_firestore_database"]
    target_model_evidence_addresses: list[str]
    iam_resource_address: str
    iam_resource_type: str
    iam_source_addresses: list[str]
    role: str
    matched_permissions: list[Literal["datastore.databases.delete"]]
    authorization_state: Literal["granted"]
    policy_complete: Literal[True]
    iam_manager_ambiguity_state: Literal["not_detected"]
    authorization_model: Literal["iam_authorized_server_api"]
    firestore_security_rules_evaluated: Literal[False]
    firestore_security_rules_applicability: Literal["not_in_server_api_authorization_path"]
    lifecycle_compatibility_state: Literal["compatible"]
    deletion_constraint_evidence: GcpFirestoreDatabaseDeletionCompatibleConstraintEvidence
    terraform_deletion_policy_evidence: GcpFirestoreTerraformDeletionPolicyEvidence
    recovery_evidence: GcpFirestoreDatabaseTopologyDestructionRecoveryEvidence
    posture_uncertainties: list[str]


class GcpCloudRunFirestoreProjectDatabaseTopologyDeletionPath(
    GcpCloudRunFirestoreDatabaseTopologyDestructionPathCommon,
):
    scope_type: Literal["project"]
    scope: str
    resource_scope: Literal["firestore_project"]
    grant_basis: Literal["firestore_project_iam"]
    condition: None
    condition_state: Literal["not_configured"]
    condition_evaluation: Literal["not_configured"]
    role_evidence: GcpFirestoreTopologyProjectRoleEvidence


class GcpCloudRunFirestoreExactDatabaseTopologyDeletionPath(
    GcpCloudRunFirestoreDatabaseTopologyDestructionPathCommon,
):
    scope_type: Literal["database"]
    scope: str
    resource_scope: Literal["exact_firestore_database"]
    grant_basis: Literal["firestore_project_iam_exact_database_condition"]
    condition: GcpFirestoreExactDatabaseConditionEvidence
    condition_state: Literal["configured"]
    condition_evaluation: Literal["exact_database_scope_match"]
    role_evidence: GcpFirestoreTopologyDatabaseRoleEvidence


GcpCloudRunFirestoreDatabaseTopologyDestructionPath = (
    GcpCloudRunFirestoreProjectDatabaseTopologyDeletionPath | GcpCloudRunFirestoreExactDatabaseTopologyDeletionPath
)
GcpCloudRunFirestoreDatabaseTopologyDestructionEvidence = GcpCloudRunFirestoreDatabaseTopologyDestructionPath

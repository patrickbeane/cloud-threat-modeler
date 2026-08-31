from __future__ import annotations

from typing import Literal, Never, TypedDict

from tfstride.providers.azure.arm_control_plane_evidence import AzureArmScopeType
from tfstride.providers.azure.key_vault_evidence import (
    AzureKeyVaultRuntimeIdentityKind,
)

AzureDiagnosticSettingAuditTelemetryDisruptionOperation = Literal["Microsoft.Insights/DiagnosticSettings/Delete"]
AzureDiagnosticSettingAuditTelemetryDisruptionOperationClass = Literal["diagnostic_setting_deletion"]
AzureDiagnosticSettingAuditTelemetryDisruptionInternalOperation = Literal["delete_diagnostic_setting"]
AzureDiagnosticSettingAuditTelemetryDisruptionTargetGranularity = Literal["diagnostic_setting"]


class AzureDiagnosticSettingBuiltInRoleEvidence(TypedDict):
    role_kind: Literal["built_in"]
    role_resolution_state: Literal["modeled_subset"]
    role_definition_address: None
    assignable_scope_compatibility_state: Literal["not_applicable"]


class AzureDiagnosticSettingCustomRoleEvidence(TypedDict):
    role_kind: Literal["custom"]
    role_resolution_state: Literal["resolved"]
    role_definition_address: str
    assignable_scope_compatibility_state: Literal["resolved"]


AzureDiagnosticSettingRoleEvidence = (
    AzureDiagnosticSettingBuiltInRoleEvidence | AzureDiagnosticSettingCustomRoleEvidence
)


class AzureDiagnosticSettingDeletionAuthorizationGrant(TypedDict):
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
    role_evidence: AzureDiagnosticSettingRoleEvidence
    role_actions: list[str]
    role_not_actions: list[str]
    requested_actions: list[Literal["Microsoft.Insights/DiagnosticSettings/Delete"]]
    matched_actions: list[Literal["Microsoft.Insights/DiagnosticSettings/Delete"]]
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
    diagnostic_settings_data_actions_authorization_effect: Literal["not_used_for_arm_diagnostic_setting_deletion"]


class AzureDiagnosticSettingLogAnalyticsDestinationEvidence(TypedDict):
    destination_evidence_scope: Literal["plan_local_diagnostic_setting_destinations"]
    destination_state: Literal["configured"]
    destination_basis: Literal["log_analytics_workspace"]
    log_analytics_workspace_id: str
    storage_account_id: str | None
    eventhub_authorization_rule_id: str | None
    eventhub_name: str | None
    marketplace_partner_resource_id: str | None
    uncertainties: list[str]


class AzureDiagnosticSettingStorageDestinationEvidence(TypedDict):
    destination_evidence_scope: Literal["plan_local_diagnostic_setting_destinations"]
    destination_state: Literal["configured"]
    destination_basis: Literal["storage_account"]
    log_analytics_workspace_id: str | None
    storage_account_id: str
    eventhub_authorization_rule_id: str | None
    eventhub_name: str | None
    marketplace_partner_resource_id: str | None
    uncertainties: list[str]


class AzureDiagnosticSettingEventHubDestinationEvidence(TypedDict):
    destination_evidence_scope: Literal["plan_local_diagnostic_setting_destinations"]
    destination_state: Literal["configured"]
    destination_basis: Literal["event_hub"]
    log_analytics_workspace_id: str | None
    storage_account_id: str | None
    eventhub_authorization_rule_id: str
    eventhub_name: str | None
    marketplace_partner_resource_id: str | None
    uncertainties: list[str]


class AzureDiagnosticSettingMarketplaceDestinationEvidence(TypedDict):
    destination_evidence_scope: Literal["plan_local_diagnostic_setting_destinations"]
    destination_state: Literal["configured"]
    destination_basis: Literal["marketplace_partner"]
    log_analytics_workspace_id: str | None
    storage_account_id: str | None
    eventhub_authorization_rule_id: str | None
    eventhub_name: str | None
    marketplace_partner_resource_id: str
    uncertainties: list[str]


class AzureDiagnosticSettingUnknownDestinationEvidence(TypedDict):
    destination_evidence_scope: Literal["plan_local_diagnostic_setting_destinations"]
    destination_state: Literal["unknown"]
    destination_basis: Literal["unknown"]
    log_analytics_workspace_id: str | None
    storage_account_id: str | None
    eventhub_authorization_rule_id: str | None
    eventhub_name: str | None
    marketplace_partner_resource_id: str | None
    uncertainties: list[str]


AzureDiagnosticSettingDestinationEvidence = (
    AzureDiagnosticSettingLogAnalyticsDestinationEvidence
    | AzureDiagnosticSettingStorageDestinationEvidence
    | AzureDiagnosticSettingEventHubDestinationEvidence
    | AzureDiagnosticSettingMarketplaceDestinationEvidence
    | AzureDiagnosticSettingUnknownDestinationEvidence
)
AzureDiagnosticSettingConfiguredDestinationEvidence = (
    AzureDiagnosticSettingLogAnalyticsDestinationEvidence
    | AzureDiagnosticSettingStorageDestinationEvidence
    | AzureDiagnosticSettingEventHubDestinationEvidence
    | AzureDiagnosticSettingMarketplaceDestinationEvidence
)


class AzureDiagnosticSettingAuditCategoryRelevanceEvidence(TypedDict):
    relevance_evidence_scope: Literal["plan_local_diagnostic_setting_enabled_log_categories"]
    relevance_basis: Literal["audit_security_category"]
    matched_audit_security_category: str
    matched_audit_security_category_group: None
    enabled_log_categories: list[str]
    enabled_log_category_groups: list[str]
    audit_telemetry_relevance_state: Literal["established"]
    uncertainties: list[str]


class AzureDiagnosticSettingAuditCategoryGroupRelevanceEvidence(TypedDict):
    relevance_evidence_scope: Literal["plan_local_diagnostic_setting_enabled_log_categories"]
    relevance_basis: Literal["audit_security_category_group"]
    matched_audit_security_category: None
    matched_audit_security_category_group: str
    enabled_log_categories: list[str]
    enabled_log_category_groups: list[str]
    audit_telemetry_relevance_state: Literal["established"]
    uncertainties: list[str]


class AzureDiagnosticSettingIrrelevantCategoriesEvidence(TypedDict):
    relevance_evidence_scope: Literal["plan_local_diagnostic_setting_enabled_log_categories"]
    relevance_basis: Literal["no_audit_security_category"]
    matched_audit_security_category: None
    matched_audit_security_category_group: None
    enabled_log_categories: list[str]
    enabled_log_category_groups: list[str]
    audit_telemetry_relevance_state: Literal["not_established"]
    uncertainties: list[Never]


class AzureDiagnosticSettingUnknownCategoriesEvidence(TypedDict):
    relevance_evidence_scope: Literal["plan_local_diagnostic_setting_enabled_log_categories"]
    relevance_basis: Literal["unknown"]
    matched_audit_security_category: None
    matched_audit_security_category_group: None
    enabled_log_categories: list[str]
    enabled_log_category_groups: list[str]
    audit_telemetry_relevance_state: Literal["unknown"]
    uncertainties: list[str]


AzureDiagnosticSettingAuditTelemetryRelevanceEvidence = (
    AzureDiagnosticSettingAuditCategoryRelevanceEvidence
    | AzureDiagnosticSettingAuditCategoryGroupRelevanceEvidence
    | AzureDiagnosticSettingIrrelevantCategoriesEvidence
    | AzureDiagnosticSettingUnknownCategoriesEvidence
)
AzureDiagnosticSettingEstablishedAuditTelemetryRelevanceEvidence = (
    AzureDiagnosticSettingAuditCategoryRelevanceEvidence | AzureDiagnosticSettingAuditCategoryGroupRelevanceEvidence
)


class AzureDiagnosticSettingManagementLockNotObserved(TypedDict):
    lock_evidence_scope: Literal["plan_local_diagnostic_setting_arm_ancestry"]
    modeled_management_lock_state: Literal["not_observed"]
    applicable_lock_addresses: list[Never]
    applicable_lock_levels: list[Never]
    external_management_locks_evaluated: Literal[False]
    deletion_compatibility_state: Literal["compatible"]
    uncertainties: list[Never]


class AzureDiagnosticSettingManagementLockBlocking(TypedDict):
    lock_evidence_scope: Literal["plan_local_diagnostic_setting_arm_ancestry"]
    modeled_management_lock_state: Literal["blocking"]
    blocking_lock_address: str
    blocking_lock_level: Literal["CanNotDelete", "ReadOnly"]
    applicable_lock_addresses: list[str]
    applicable_lock_levels: list[Literal["CanNotDelete", "ReadOnly"]]
    external_management_locks_evaluated: Literal[False]
    deletion_compatibility_state: Literal["blocked"]
    uncertainties: list[Never]


class AzureDiagnosticSettingManagementLockUnknown(TypedDict):
    lock_evidence_scope: Literal["plan_local_diagnostic_setting_arm_ancestry"]
    modeled_management_lock_state: Literal["unknown"]
    potentially_applicable_lock_addresses: list[str]
    external_management_locks_evaluated: Literal[False]
    deletion_compatibility_state: Literal["unknown"]
    uncertainties: list[str]


AzureDiagnosticSettingManagementLockEvidence = (
    AzureDiagnosticSettingManagementLockNotObserved
    | AzureDiagnosticSettingManagementLockBlocking
    | AzureDiagnosticSettingManagementLockUnknown
)


class AzureDiagnosticSettingAuditTelemetryDisruptionOutcomeEvidence(TypedDict):
    outcome_evidence_scope: Literal["plan_local_diagnostic_setting_deletion_authority"]
    successful_operation_observed: Literal[False]
    historical_log_deletion_authorized_by_operation: Literal[False]
    historical_log_deletion_observed: Literal[False]
    destination_resource_deletion_authorized_by_operation: Literal[False]
    destination_resource_deletion_observed: Literal[False]
    all_resource_diagnostic_settings_evaluated: Literal[False]
    out_of_plan_diagnostic_settings_evaluated: Literal[False]
    telemetry_recovery_state: Literal["not_established_by_modeled_azure_diagnostic_setting_evidence"]
    restoration_observed: Literal[False]
    uncertainties: list[str]


class AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath(TypedDict):
    workload_address: str
    workload_type: str
    identity_address: str
    identity_kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str
    credential_context: Literal["workload_runtime"]
    diagnostic_setting_address: str
    diagnostic_setting_resource_type: str
    diagnostic_setting_name: str
    diagnostic_setting_reference: str
    diagnostic_setting_id: str | None
    diagnostic_setting_arm_id: str
    monitored_resource_address: str
    monitored_resource_type: str
    monitored_resource_id: str
    operation: Literal["Microsoft.Insights/DiagnosticSettings/Delete"]
    operation_class: Literal["diagnostic_setting_deletion"]
    internal_operation: Literal["delete_diagnostic_setting"]
    management_effect: Literal["audit_telemetry_disruption"]
    authorization_evidence_kind: Literal["azure_rbac_action"]
    target_granularity: Literal["diagnostic_setting"]
    target_scope: Literal["exact_monitor_diagnostic_setting"]
    target_model_evidence_addresses: list[str]
    role_assignment_address: str
    authorization_source_addresses: list[str]
    authorization_state: Literal["granted"]
    modeled_allow_evidence_complete: Literal[True]
    condition: None
    condition_state: Literal["not_configured"]
    authorization_grant: AzureDiagnosticSettingDeletionAuthorizationGrant
    lifecycle_compatibility_state: Literal["compatible"]
    management_lock_evidence: AzureDiagnosticSettingManagementLockNotObserved
    destination_evidence: AzureDiagnosticSettingConfiguredDestinationEvidence
    audit_telemetry_relevance_evidence: AzureDiagnosticSettingEstablishedAuditTelemetryRelevanceEvidence
    outcome_evidence: AzureDiagnosticSettingAuditTelemetryDisruptionOutcomeEvidence
    posture_uncertainties: list[str]


AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionEvidence = (
    AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath
)

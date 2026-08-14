from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, cast

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource
from tfstride.providers.coercion import STATE_DISABLED, STATE_ENABLED, STATE_NOT_CONFIGURED
from tfstride.providers.gcp.constants import PUBLIC_GCP_IAM_MEMBERS
from tfstride.providers.gcp.iam_reference_utils import (
    custom_role_reference_keys,
    normalize_gcp_project,
)
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_CUSTOM_ROLE_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import (
    GCP_ROLE_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
)

_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker", "roles/run.servicesInvoker"})
_ENTITY_READ_PERMISSION_OPERATIONS = {
    "datastore.entities.get": "get",
    "datastore.entities.list": "list",
}
_ENTITY_READ_WILDCARDS = frozenset({"*", "datastore.*", "datastore.entities.*"})
_ENTITY_MUTATION_PERMISSION_OPERATIONS = {
    "datastore.entities.create": "create",
    "datastore.entities.update": "update",
}
_ENTITY_MUTATION_WILDCARDS = frozenset({"*", "datastore.*", "datastore.entities.*"})
_DATABASE_ADMINISTRATION_CLASSES = frozenset({"destructive_administration", "configuration_administration"})
_ENTITY_DELETION_OPERATION_CLASSES = {
    "datastore.entities.delete": "entity_deletion",
    "datastore.databases.bulkDelete": "bulk_entity_deletion",
}
_ENTITY_DELETION_TARGET_GRANULARITIES = {
    "datastore.entities.delete": "database_entity_namespace",
    "datastore.databases.bulkDelete": "database_bulk_entity_namespace",
}
_ACTIVE_CUSTOM_ROLE_STAGES = frozenset({"ALPHA", "BETA", "DEPRECATED", "EAP", "GA"})


class GcpCloudRunFirestoreAccessRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_cloud_run_firestore_mutation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = _unconditional_public_invokers(workload)
            invoker_iam_check_disabled = gcp_facts(workload).cloud_run_invoker_iam_disabled is True
            if not workload.public_exposure or (not public_invokers and not invoker_iam_check_disabled):
                continue

            mutation_paths = [
                path
                for path in gcp_facts(workload).cloud_run_firestore_access_paths
                if _is_deterministic_entity_mutation_path(path, workload, context)
            ]
            if not mutation_paths:
                continue

            database_addresses = _path_string_values(
                mutation_paths,
                "firestore_database_address",
            )
            iam_resource_addresses = _path_string_values(
                mutation_paths,
                "iam_resource_address",
            )
            public_source_addresses = sorted({binding["source"] for binding in public_invokers})
            operations = _entity_mutation_operations(mutation_paths)
            administration_classes = _database_administration_classes(mutation_paths)
            has_project_scope = any(path.get("scope_type") == "project" for path in mutation_paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2 if administration_classes else 1,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=(2 if has_project_scope or len(database_addresses) > 1 else 1),
            )
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", workload.address))
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            workload.address,
                            *public_source_addresses,
                            *database_addresses,
                            *iam_resource_addresses,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_mutation_rationale(
                        workload,
                        operations,
                        database_addresses,
                        administration_classes=administration_classes,
                        has_project_scope=has_project_scope,
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "public_invoker_bindings",
                            _public_invoker_evidence(public_invokers),
                        ),
                        evidence_item(
                            "public_exposure_reasons",
                            workload.public_exposure_reasons,
                        ),
                        evidence_item(
                            "public_exposure_configuration",
                            _public_exposure_configuration(workload),
                        ),
                        evidence_item(
                            "runtime_identity",
                            _runtime_identity_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "firestore_mutation_paths",
                            _mutation_path_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "scope_breadth",
                            _scope_breadth_evidence(
                                mutation_paths,
                                database_addresses,
                            ),
                        ),
                        evidence_item(
                            "authorization_scope",
                            [
                                (
                                    "establishes=modeled IAM allow grant containing deterministic "
                                    "Firestore entity mutation permissions"
                                ),
                                (
                                    "firestore_security_rules=not evaluated for server/API access "
                                    "authenticated as the Cloud Run runtime service account"
                                ),
                                (
                                    "does_not_establish=effective access after IAM deny or principal "
                                    "access boundary evaluation"
                                ),
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_cloud_run_firestore_entity_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = _unconditional_public_invokers(workload)
            invoker_iam_check_disabled = gcp_facts(workload).cloud_run_invoker_iam_disabled is True
            if not workload.public_exposure or (not public_invokers and not invoker_iam_check_disabled):
                continue

            deletion_paths = [
                path
                for path in gcp_facts(workload).cloud_run_firestore_entity_deletion_paths
                if _is_current_entity_deletion_path(path, workload, context)
            ]
            if not deletion_paths:
                continue

            database_addresses = _path_string_values(
                deletion_paths,
                "firestore_database_address",
            )
            iam_source_addresses = sorted(
                {source for path in deletion_paths for source in _string_values(path.get("iam_source_addresses"))}
            )
            public_source_addresses = sorted({binding["source"] for binding in public_invokers})
            operations = _entity_deletion_operations(deletion_paths)
            has_project_scope = any(path.get("scope_type") == "project" for path in deletion_paths)
            has_bulk_deletion = "datastore.databases.bulkDelete" in operations
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2 if has_bulk_deletion else 1,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=(2 if has_project_scope or len(database_addresses) > 1 else 1),
            )
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", workload.address))
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            workload.address,
                            *public_source_addresses,
                            *database_addresses,
                            *iam_source_addresses,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_entity_deletion_rationale(
                        workload,
                        operations,
                        database_addresses,
                        has_project_scope=has_project_scope,
                        has_bulk_deletion=has_bulk_deletion,
                        paths=deletion_paths,
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "public_invoker_bindings",
                            _public_invoker_evidence(public_invokers),
                        ),
                        evidence_item(
                            "public_exposure_reasons",
                            workload.public_exposure_reasons,
                        ),
                        evidence_item(
                            "public_exposure_configuration",
                            _public_exposure_configuration(workload),
                        ),
                        evidence_item(
                            "runtime_identity",
                            _runtime_identity_evidence(deletion_paths),
                        ),
                        evidence_item(
                            "firestore_entity_deletion_paths",
                            _entity_deletion_path_evidence(deletion_paths),
                        ),
                        evidence_item(
                            "firestore_entity_deletion_path_uncertainties",
                            gcp_facts(workload).cloud_run_firestore_entity_deletion_path_uncertainties,
                        ),
                        evidence_item(
                            "recovery_posture",
                            _entity_deletion_recovery_posture_evidence(deletion_paths),
                        ),
                        evidence_item(
                            "scope_breadth",
                            _scope_breadth_evidence(
                                deletion_paths,
                                database_addresses,
                            ),
                        ),
                        evidence_item(
                            "authorization_scope",
                            _entity_deletion_authorization_scope_evidence(deletion_paths),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_cloud_run_firestore_read_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = _unconditional_public_invokers(workload)
            invoker_iam_check_disabled = gcp_facts(workload).cloud_run_invoker_iam_disabled is True
            if not workload.public_exposure or (not public_invokers and not invoker_iam_check_disabled):
                continue

            read_paths = [
                path
                for path in gcp_facts(workload).cloud_run_firestore_access_paths
                if _is_deterministic_entity_read_path(path, workload, context)
            ]
            if not read_paths:
                continue

            database_addresses = _path_string_values(
                read_paths,
                "firestore_database_address",
            )
            iam_resource_addresses = _path_string_values(
                read_paths,
                "iam_resource_address",
            )
            public_source_addresses = sorted({binding["source"] for binding in public_invokers})
            operations = _entity_read_operations(read_paths)
            has_project_scope = any(path.get("scope_type") == "project" for path in read_paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=1,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=(2 if has_project_scope or len(database_addresses) > 1 else 1),
            )
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", workload.address))
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            workload.address,
                            *public_source_addresses,
                            *database_addresses,
                            *iam_resource_addresses,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_read_rationale(
                        workload,
                        operations,
                        database_addresses,
                        has_project_scope=has_project_scope,
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "public_invoker_bindings",
                            _public_invoker_evidence(public_invokers),
                        ),
                        evidence_item(
                            "public_exposure_reasons",
                            workload.public_exposure_reasons,
                        ),
                        evidence_item(
                            "public_exposure_configuration",
                            _public_exposure_configuration(workload),
                        ),
                        evidence_item(
                            "runtime_identity",
                            _runtime_identity_evidence(read_paths),
                        ),
                        evidence_item(
                            "firestore_read_paths",
                            _read_path_evidence(read_paths),
                        ),
                        evidence_item(
                            "scope_breadth",
                            _scope_breadth_evidence(
                                read_paths,
                                database_addresses,
                            ),
                        ),
                        evidence_item(
                            "authorization_scope",
                            [
                                (
                                    "establishes=modeled IAM allow grant containing deterministic "
                                    "datastore.entities.get or datastore.entities.list permission"
                                ),
                                (
                                    "firestore_security_rules=not evaluated for server/API access "
                                    "authenticated as the Cloud Run runtime service account"
                                ),
                                (
                                    "permission_semantics=datastore.entities.list permits document-name "
                                    "enumeration; datastore.entities.get is required for document data"
                                ),
                                (
                                    "does_not_establish=effective access after IAM deny or principal "
                                    "access boundary evaluation"
                                ),
                                (
                                    "excludes=datastore.databases.export bulk-transfer workflows and "
                                    "their additional destination authorization semantics"
                                ),
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_current_entity_deletion_path(
    path: Mapping[str, Any],
    workload: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    operation = _known_string(path.get("operation"))
    if (
        operation not in _ENTITY_DELETION_OPERATION_CLASSES
        or path.get("workload_address") != workload.address
        or path.get("workload_type") != workload.resource_type
        or path.get("identity_kind") != "cloud_run_service_account"
        or path.get("credential_context") != "workload_runtime"
        or path.get("operation_class") != _ENTITY_DELETION_OPERATION_CLASSES[operation]
        or path.get("target_granularity") != _ENTITY_DELETION_TARGET_GRANULARITIES[operation]
        or path.get("matched_permissions") != [operation]
        or path.get("management_effect") != "disruption"
        or path.get("authorization_state") != "granted"
        or path.get("policy_complete") is not True
        or path.get("authorization_model") != "iam_authorized_server_api"
        or path.get("firestore_security_rules_evaluated") is not False
        or path.get("firestore_security_rules_applicability") != "not_in_server_api_authorization_path"
        or path.get("lifecycle_compatibility_state") != "not_applicable"
        or path.get("target_model_evidence_addresses") != [path.get("firestore_database_address")]
        or not _scope_is_deterministic(path)
    ):
        return False

    workload_facts = gcp_facts(workload)
    service_account_email = _known_string(workload_facts.service_account_email)
    service_account_member = _known_string(workload_facts.service_account_member)
    if (
        service_account_email is None
        or service_account_member is None
        or path.get("service_account_email") != service_account_email
        or path.get("service_account_member") != service_account_member
        or service_account_member != f"serviceAccount:{service_account_email}"
    ):
        return False

    database_address = _known_string(path.get("firestore_database_address"))
    database_resource_name = _known_string(path.get("firestore_database_resource_name"))
    iam_resource_address = _known_string(path.get("iam_resource_address"))
    role = _known_string(path.get("role"))
    if database_address is None or database_resource_name is None or iam_resource_address is None or role is None:
        return False

    database = context.inventory.get_by_address(database_address)
    iam_resource = context.inventory.get_by_address(iam_resource_address)
    if (
        database is None
        or database.resource_type != GcpResourceType.FIRESTORE_DATABASE
        or iam_resource is None
        or iam_resource.resource_type not in GCP_PROJECT_IAM_RESOURCE_TYPES
        or path.get("firestore_database_resource_type") != database.resource_type
        or path.get("iam_resource_type") != iam_resource.resource_type
        or _database_resource_name(database) != database_resource_name
        or path.get("target_model_evidence_addresses") != [database.address]
    ):
        return False

    database_facts = gcp_facts(database)
    if (
        path.get("firestore_database_name") != _known_string(database_facts.firestore_database_name)
        or path.get("firestore_database_project") != _known_string(database_facts.project)
        or path.get("firestore_database_type") != _known_string(database_facts.firestore_database_type)
    ):
        return False

    if not _firestore_grant_is_current(path, database, service_account_member):
        return False
    if not _firestore_access_path_is_current(path, workload, database, operation):
        return False
    if not _firestore_role_evidence_is_current(path, iam_resource, context):
        return False
    return _firestore_recovery_evidence_is_current(path, database)


def _firestore_grant_is_current(
    path: Mapping[str, Any],
    database: NormalizedResource,
    service_account_member: str,
) -> bool:
    facts = gcp_facts(database)
    for grant in facts.firestore_iam_grants:
        if (
            grant.get("source") != path.get("iam_resource_address")
            or grant.get("source_type") != path.get("iam_resource_type")
            or grant.get("role") != path.get("role")
            or service_account_member not in binding_members(grant)
            or grant.get("scope_type") != path.get("scope_type")
            or grant.get("scope") != path.get("scope")
            or normalize_gcp_project(grant.get("project"))
            != normalize_gcp_project(path.get("firestore_database_project"))
            or grant.get("database_resource_name") != path.get("firestore_database_resource_name")
            or grant.get("grant_basis") != path.get("grant_basis")
            or grant.get("condition_state") != path.get("condition_state")
            or grant.get("condition") != path.get("condition")
        ):
            continue
        return True
    return False


def _firestore_access_path_is_current(
    path: Mapping[str, Any],
    workload: NormalizedResource,
    database: NormalizedResource,
    operation: str,
) -> bool:
    comparable_fields = (
        "workload_address",
        "workload_type",
        "service_account_email",
        "service_account_member",
        "identity_kind",
        "credential_context",
        "firestore_database_address",
        "firestore_database_resource_type",
        "firestore_database_resource_name",
        "firestore_database_name",
        "firestore_database_project",
        "firestore_database_type",
        "iam_resource_address",
        "iam_resource_type",
        "role",
        "role_kind",
        "custom_role_permissions",
        "grant_basis",
        "scope_type",
        "scope",
        "resource_scope",
        "condition",
        "condition_state",
        "condition_evaluation",
        "authorization_model",
        "firestore_security_rules_evaluated",
        "firestore_security_rules_applicability",
    )
    for access_path in gcp_facts(workload).cloud_run_firestore_access_paths:
        if (
            access_path.get("firestore_database_address") != database.address
            or access_path.get("access_state") != "granted"
            or any(access_path.get(field) != path.get(field) for field in comparable_fields)
        ):
            continue
        if _permission_allows_entity_deletion(_string_values(access_path.get("matched_permissions")), operation):
            return True
    return False


def _permission_allows_entity_deletion(permissions: Sequence[str], operation: str) -> bool:
    operation_key = operation.casefold()
    for permission in permissions:
        normalized = permission.strip().casefold()
        if normalized in {"*", "datastore.*", operation_key}:
            return True
        if operation == "datastore.entities.delete" and normalized == "datastore.entities.*":
            return True
        if operation == "datastore.databases.bulkDelete" and normalized == "datastore.databases.*":
            return True
    return False


def _firestore_role_evidence_is_current(
    path: Mapping[str, Any],
    iam_resource: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    role = _known_string(path.get("role"))
    role_kind = _known_string(path.get("role_kind"))
    source_addresses = path.get("iam_source_addresses")
    if (
        role is None
        or role_kind is None
        or not isinstance(source_addresses, list)
        or not all(isinstance(address, str) for address in source_addresses)
    ):
        return False

    if role_kind != "custom":
        return (
            source_addresses == [iam_resource.address]
            and path.get("role_definition_address") is None
            and path.get("custom_role_permissions") == []
            and path.get("custom_role_stage") is None
            and path.get("custom_role_deleted") is None
        )

    if (
        len(source_addresses) != 2
        or source_addresses[0] != iam_resource.address
        or path.get("role_definition_address") != source_addresses[1]
    ):
        return False
    role_definition = context.inventory.get_by_address(source_addresses[1])
    if (
        role_definition is None
        or role_definition.resource_type not in GCP_CUSTOM_ROLE_RESOURCE_TYPES
        or gcp_reference_key(role, GCP_ROLE_REFERENCE_SUFFIXES) not in custom_role_reference_keys(role_definition)
    ):
        return False

    role_facts = gcp_facts(role_definition)
    stage = role_facts.custom_role_stage
    return (
        role_facts.custom_role_deleted is False
        and stage is not None
        and stage.upper() in _ACTIVE_CUSTOM_ROLE_STAGES
        and role_facts.custom_role_permissions_state == "configured"
        and path.get("custom_role_stage") == stage.upper()
        and path.get("custom_role_deleted") is False
        and path.get("custom_role_permissions") == sorted(set(role_facts.custom_role_permissions))
    )


def _expected_firestore_recovery_evidence(
    database: NormalizedResource,
) -> dict[str, object]:
    facts = gcp_facts(database)
    uncertainties = [
        uncertainty
        for uncertainty in facts.firestore_posture_uncertainties
        if uncertainty.startswith("point_in_time_recovery_enablement")
    ]
    state = facts.firestore_pitr_state
    if state == STATE_ENABLED:
        return {
            "recovery_evidence_scope": "firestore_point_in_time_recovery",
            "pitr_state": "enabled",
            "pitr_enabled": True,
            "historical_version_retention_state": "pitr_up_to_seven_days",
            "uncertainties": _dedupe_strings(uncertainties),
        }
    if state == STATE_DISABLED:
        return {
            "recovery_evidence_scope": "firestore_point_in_time_recovery",
            "pitr_state": "disabled",
            "pitr_enabled": False,
            "historical_version_retention_state": "native_approximately_one_hour",
            "uncertainties": _dedupe_strings(uncertainties),
        }
    if state == STATE_NOT_CONFIGURED:
        return {
            "recovery_evidence_scope": "firestore_point_in_time_recovery",
            "pitr_state": "not_configured",
            "pitr_enabled": False,
            "historical_version_retention_state": "native_approximately_one_hour",
            "uncertainties": _dedupe_strings(uncertainties),
        }
    if not uncertainties:
        uncertainties.append(f"{database.address}: Firestore PITR state is unresolved")
    return {
        "recovery_evidence_scope": "firestore_point_in_time_recovery",
        "pitr_state": "unknown",
        "pitr_enabled": None,
        "historical_version_retention_state": "unknown",
        "uncertainties": _dedupe_strings(uncertainties),
    }


def _firestore_recovery_evidence_is_current(
    path: Mapping[str, Any],
    database: NormalizedResource,
) -> bool:
    expected = _expected_firestore_recovery_evidence(database)
    actual = path.get("recovery_evidence")
    return (
        isinstance(actual, Mapping)
        and dict(actual) == expected
        and path.get("posture_uncertainties") == expected["uncertainties"]
    )


def _unconditional_public_invokers(
    resource: NormalizedResource,
) -> list[dict[str, str]]:
    invokers: list[dict[str, str]] = []
    for binding in gcp_facts(resource).bindings:
        role = _known_string(binding.get("role"))
        source = _known_string(binding.get("source"))
        if (
            role not in _PUBLIC_INVOKER_ROLES
            or source is None
            or binding.get("condition")
            or binding.get("condition_state") == "unknown"
        ):
            continue
        for member in binding_members(binding):
            if member in PUBLIC_GCP_IAM_MEMBERS:
                invokers.append({"source": source, "role": role, "member": member})
    return invokers


def _is_deterministic_entity_mutation_path(
    path: Mapping[str, Any],
    workload: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    return bool(_path_entity_mutation_operations(path)) and _is_deterministic_firestore_path(
        path,
        workload,
        context,
    )


def _is_deterministic_entity_read_path(
    path: Mapping[str, Any],
    workload: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    return bool(_path_entity_read_operations(path)) and _is_deterministic_firestore_path(
        path,
        workload,
        context,
    )


def _is_deterministic_firestore_path(
    path: Mapping[str, Any],
    workload: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    if (
        path.get("workload_address") != workload.address
        or path.get("workload_type") != workload.resource_type
        or path.get("identity_kind") != "cloud_run_service_account"
        or path.get("credential_context") != "workload_runtime"
        or path.get("firestore_database_resource_type") != GcpResourceType.FIRESTORE_DATABASE
        or path.get("access_state") != "granted"
        or path.get("authorization_model") != "iam_authorized_server_api"
        or path.get("firestore_security_rules_evaluated") is not False
        or path.get("firestore_security_rules_applicability") != "not_in_server_api_authorization_path"
        or not _scope_is_deterministic(path)
    ):
        return False

    service_account_member = _known_string(path.get("service_account_member"))
    role = _known_string(path.get("role"))
    database_address = _known_string(path.get("firestore_database_address"))
    database_resource_name = _known_string(path.get("firestore_database_resource_name"))
    iam_resource_address = _known_string(path.get("iam_resource_address"))
    if not all(
        (
            service_account_member,
            role,
            database_address,
            database_resource_name,
            iam_resource_address,
        )
    ):
        return False

    database = context.inventory.get_by_address(database_address)
    iam_resource = context.inventory.get_by_address(iam_resource_address)
    if (
        database is None
        or database.resource_type != GcpResourceType.FIRESTORE_DATABASE
        or _database_resource_name(database) != database_resource_name
        or iam_resource is None
        or iam_resource.resource_type not in GCP_PROJECT_IAM_RESOURCE_TYPES
        or path.get("iam_resource_type") != iam_resource.resource_type
    ):
        return False
    return True


def _database_resource_name(database: NormalizedResource) -> str | None:
    identifier = _known_string(database.identifier)
    if identifier and identifier.startswith("projects/") and "/databases/" in identifier:
        return identifier

    facts = gcp_facts(database)
    project = normalize_gcp_project(facts.project)
    database_name = _known_string(facts.firestore_database_name)
    if project and database_name and "/" not in database_name:
        return f"projects/{project}/databases/{database_name}"
    return None


def _scope_is_deterministic(path: Mapping[str, Any]) -> bool:
    scope_type = path.get("scope_type")
    if scope_type == "database":
        condition = path.get("condition")
        return (
            path.get("grant_basis") == "project_iam_condition"
            and path.get("resource_scope") == "exact_firestore_database"
            and path.get("scope") == path.get("firestore_database_resource_name")
            and path.get("condition_state") == "configured"
            and isinstance(condition, Mapping)
            and path.get("condition_evaluation") == "exact_database_scope_match"
        )
    if scope_type == "project":
        return (
            path.get("grant_basis") == "project_iam"
            and path.get("resource_scope") == "firestore_project"
            and normalize_gcp_project(path.get("scope"))
            == normalize_gcp_project(path.get("firestore_database_project"))
            and path.get("condition_state") == "not_configured"
            and path.get("condition") is None
            and path.get("condition_evaluation") == "not_configured"
        )
    return False


def _read_rationale(
    workload: NormalizedResource,
    operations: list[str],
    database_addresses: list[str],
    *,
    has_project_scope: bool,
) -> str:
    permission_names = ", ".join(f"datastore.entities.{operation}" for operation in operations)
    rationale = (
        f"{workload.display_name} is publicly invokable and its Cloud Run runtime "
        f"service account has deterministic IAM allow grants containing {permission_names} "
        f"on {len(database_addresses)} exact modeled database(s). A compromise of the public "
        f"workload could attempt to {_read_capability_summary(operations)} through the "
        "service-account-authenticated server/API path. "
    )
    if has_project_scope:
        rationale += (
            "At least one grant is project-applicable and can reach Firestore databases "
            "across the project, so its blast radius is broader than an exact "
            "database-scoped grant. "
        )
    else:
        rationale += "The modeled grants are limited by exact Firestore database-name conditions. "
    return rationale + (
        "Firestore Security Rules are not evaluated for server/API access authenticated "
        "through the Cloud Run runtime service account. IAM deny and principal access "
        "boundary policies are independent controls not evaluated by this path. This path "
        "does not mean that the Firestore database itself is public."
    )


def _read_capability_summary(operations: list[str]) -> str:
    operation_set = set(operations)
    if {"get", "list"} <= operation_set:
        return "enumerate document names and read document data"
    if "get" in operation_set:
        return "read document data"
    return "enumerate document names without establishing access to document contents"


def _entity_deletion_rationale(
    workload: NormalizedResource,
    operations: Sequence[str],
    database_addresses: Sequence[str],
    *,
    has_project_scope: bool,
    has_bulk_deletion: bool,
    paths: Sequence[Mapping[str, Any]],
) -> str:
    operation_text = _operation_text(list(operations))
    rationale = (
        f"{workload.display_name} is publicly invokable and its Cloud Run runtime service account has "
        f"deterministic Firestore entity-deletion authority ({operation_text}) across "
        f"{len(database_addresses)} exact modeled database(s). A compromise of the public workload could "
        "disrupt Firestore entity availability through the service-account-authenticated server/API path. "
    )
    if has_bulk_deletion:
        rationale += (
            "The modeled authority includes the database bulk-delete workflow, which is broader than "
            "ordinary entity deletion. "
        )
    if has_project_scope:
        rationale += (
            "At least one grant is project-applicable and can reach Firestore databases across the project, "
            "so its blast radius is broader than an exact database-scoped grant. "
        )
    else:
        rationale += "The modeled grants are limited by exact Firestore database-name conditions. "
    recovery_states = {_firestore_recovery_state(path) for path in paths}
    if "pitr_enabled" in recovery_states:
        rationale += "Point-in-time recovery evidence supports historical recovery for up to seven days. "
    if "recovery_posture_unknown" in recovery_states:
        rationale += (
            "Recovery posture is partly unknown, but that uncertainty does not remove deterministic "
            "deletion authority. "
        )
    return rationale + (
        "Firestore Security Rules are not evaluated for server/API access authenticated through the Cloud Run "
        "runtime service account. IAM deny and principal access boundary policies are independent controls "
        "not evaluated by this path. This path does not mean that the Firestore database itself is public "
        "or that deletion succeeds."
    )


def _firestore_recovery_state(path: Mapping[str, Any]) -> str:
    recovery = path.get("recovery_evidence")
    if not isinstance(recovery, Mapping):
        return "recovery_posture_unknown"
    if recovery.get("pitr_state") == "enabled":
        return "pitr_enabled"
    if recovery.get("pitr_state") == "unknown":
        return "recovery_posture_unknown"
    return "pitr_not_enabled"


def _entity_deletion_operations(paths: Sequence[Mapping[str, Any]]) -> list[str]:
    return [
        operation
        for operation in (
            "datastore.entities.delete",
            "datastore.databases.bulkDelete",
        )
        if any(path.get("operation") == operation for path in paths)
    ]


def _entity_deletion_path_evidence(paths: Sequence[Mapping[str, Any]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        values.add(
            "; ".join(
                (
                    f"database_address={path.get('firestore_database_address')}",
                    f"database_resource_name={path.get('firestore_database_resource_name')}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"iam_resource={path.get('iam_resource_address')}",
                    f"role={path.get('role')}",
                    f"role_kind={path.get('role_kind')}",
                    f"matched_permissions={','.join(_string_values(path.get('matched_permissions')))}",
                    f"scope_type={path.get('scope_type')}",
                    f"scope={path.get('scope')}",
                    f"resource_scope={path.get('resource_scope')}",
                    f"condition_state={path.get('condition_state')}",
                    f"condition_evaluation={path.get('condition_evaluation')}",
                    "authorization_state=granted",
                    "management_effect=disruption",
                    "firestore_security_rules_evaluated=false",
                )
            )
        )
    return sorted(values)


def _entity_deletion_recovery_posture_evidence(
    paths: Sequence[Mapping[str, Any]],
) -> list[str]:
    values: set[str] = set()
    for path in paths:
        recovery = path.get("recovery_evidence")
        recovery_map: Mapping[str, Any] = cast(Mapping[str, Any], recovery) if isinstance(recovery, Mapping) else {}
        values.add(
            "; ".join(
                (
                    f"database_address={path.get('firestore_database_address')}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"pitr_state={recovery_map.get('pitr_state')}",
                    f"pitr_enabled={str(recovery_map.get('pitr_enabled')).lower()}",
                    f"historical_version_retention_state={recovery_map.get('historical_version_retention_state')}",
                    f"recovery_state={_firestore_recovery_state(path)}",
                    f"uncertainties={','.join(_string_values(recovery_map.get('uncertainties'))) or 'none'}",
                )
            )
        )
    return sorted(values)


def _entity_deletion_authorization_scope_evidence(
    paths: Sequence[Mapping[str, Any]],
) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"operation={path.get('operation')}",
                    f"scope_type={path.get('scope_type')}",
                    f"scope={path.get('scope')}",
                    f"iam_resource={path.get('iam_resource_address')}",
                    f"role={path.get('role')}",
                    f"grant_basis={path.get('grant_basis')}",
                    f"iam_sources={','.join(_string_values(path.get('iam_source_addresses'))) or 'none'}",
                )
            )
            for path in paths
        }
    )


def _operation_text(operations: list[str]) -> str:
    if len(operations) == 1:
        return operations[0]
    if len(operations) == 2:
        return f"{operations[0]} and {operations[1]}"
    return ", ".join(operations[:-1]) + f", and {operations[-1]}"


def _dedupe_strings(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _mutation_rationale(
    workload: NormalizedResource,
    operations: list[str],
    database_addresses: list[str],
    *,
    administration_classes: list[str],
    has_project_scope: bool,
) -> str:
    rationale = (
        f"{workload.display_name} is publicly invokable and its Cloud Run runtime "
        f"service account has deterministic IAM allow grants for Firestore entity "
        f"{', '.join(operations)} operations on {len(database_addresses)} exact modeled "
        "database(s). A compromise of the public workload could attempt to mutate "
        "Firestore documents through the service-account-authenticated server/API path. "
    )
    if has_project_scope:
        rationale += (
            "At least one grant is project-applicable and can reach Firestore databases "
            "across the project, so its blast radius is broader than an exact "
            "database-scoped grant. "
        )
    else:
        rationale += "The modeled grants are limited by exact Firestore database-name conditions. "
    if administration_classes:
        rationale += (
            "The same paths separately include "
            f"{', '.join(administration_classes)} database capabilities; those are not "
            "relabeled as entity mutation but increase the modeled privilege breadth. "
        )
    return rationale + (
        "Firestore Security Rules are not evaluated for server/API access authenticated "
        "through the Cloud Run runtime service account. This path does not mean that the "
        "Firestore database itself is public."
    )


def _entity_read_operations(paths: list[dict[str, Any]]) -> list[str]:
    operations = {operation for path in paths for operation in _path_entity_read_operations(path)}
    return [operation for operation in ("get", "list") if operation in operations]


def _path_entity_read_operations(path: Mapping[str, Any]) -> list[str]:
    operations: set[str] = set()
    for permission in _string_values(path.get("matched_permissions")):
        normalized = permission.strip().lower()
        if normalized in _ENTITY_READ_WILDCARDS:
            operations.update({"get", "list"})
            continue
        operation = _ENTITY_READ_PERMISSION_OPERATIONS.get(normalized)
        if operation is not None:
            operations.add(operation)
    return [operation for operation in ("get", "list") if operation in operations]


def _entity_mutation_operations(paths: list[dict[str, Any]]) -> list[str]:
    operations = {operation for path in paths for operation in _path_entity_mutation_operations(path)}
    return [operation for operation in ("create", "update") if operation in operations]


def _path_entity_mutation_operations(path: Mapping[str, Any]) -> list[str]:
    operations: set[str] = set()
    for permission in _string_values(path.get("matched_permissions")):
        normalized = permission.strip().lower()
        if normalized in _ENTITY_MUTATION_WILDCARDS:
            operations.update({"create", "update"})
            continue
        operation = _ENTITY_MUTATION_PERMISSION_OPERATIONS.get(normalized)
        if operation is not None:
            operations.add(operation)
    return [operation for operation in ("create", "update") if operation in operations]


def _path_entity_mutation_permissions(path: Mapping[str, Any]) -> list[str]:
    return [
        permission
        for permission in _string_values(path.get("matched_permissions"))
        if permission.strip().lower() in _ENTITY_MUTATION_WILDCARDS
        or permission.strip().lower() in _ENTITY_MUTATION_PERMISSION_OPERATIONS
    ]


def _database_administration_classes(
    paths: list[dict[str, Any]],
) -> list[str]:
    classes = {
        access_class
        for path in paths
        for access_class in _string_values(path.get("access_classes"))
        if access_class in _DATABASE_ADMINISTRATION_CLASSES
    }
    return [
        access_class
        for access_class in (
            "destructive_administration",
            "configuration_administration",
        )
        if access_class in classes
    ]


def _path_string_values(paths: list[dict[str, Any]], key: str) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get(key))) is not None})


def _public_exposure_configuration(resource: NormalizedResource) -> list[str]:
    if gcp_facts(resource).cloud_run_invoker_iam_disabled is not True:
        return []
    ingress = gcp_facts(resource).serverless_ingress or "unknown"
    return [f"invoker_iam_check=disabled; ingress={ingress}"]


def _public_invoker_evidence(invokers: list[dict[str, str]]) -> list[str]:
    return sorted(
        {
            f"source={invoker['source']}; role={invoker['role']}; member={invoker['member']}; condition=none"
            for invoker in invokers
        }
    )


def _runtime_identity_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"service_account={path.get('service_account_email') or 'unknown'}",
                    f"member={path['service_account_member']}",
                    f"role={path['role']}",
                    f"role_kind={path['role_kind']}",
                    "credential_context=workload_runtime",
                )
            )
            for path in paths
        }
    )


def _read_path_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"database_address={path['firestore_database_address']}",
                    f"database_resource_name={path['firestore_database_resource_name']}",
                    f"iam_resource={path['iam_resource_address']}",
                    f"role={path['role']}",
                    f"role_kind={path['role_kind']}",
                    f"entity_read_operations={','.join(_path_entity_read_operations(path))}",
                    f"matched_permissions={','.join(_string_values(path.get('matched_permissions')))}",
                    f"scope_type={path['scope_type']}",
                    f"scope={path['scope']}",
                    f"resource_scope={path['resource_scope']}",
                    f"condition_state={path['condition_state']}",
                    f"condition_evaluation={path['condition_evaluation']}",
                    "access_state=granted",
                    "authorization_model=iam_authorized_server_api",
                    "firestore_security_rules_evaluated=false",
                )
            )
            for path in paths
        }
    )


def _mutation_path_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"database_address={path['firestore_database_address']}",
                    f"database_resource_name={path['firestore_database_resource_name']}",
                    f"iam_resource={path['iam_resource_address']}",
                    f"role={path['role']}",
                    f"role_kind={path['role_kind']}",
                    (f"entity_mutation_operations={','.join(_path_entity_mutation_operations(path))}"),
                    (
                        "database_administration_classes="
                        f"{','.join(_path_database_administration_classes(path)) or 'none'}"
                    ),
                    (f"matched_permissions={','.join(_path_entity_mutation_permissions(path))}"),
                    f"scope_type={path['scope_type']}",
                    f"scope={path['scope']}",
                    f"resource_scope={path['resource_scope']}",
                    f"condition_state={path['condition_state']}",
                    f"condition_evaluation={path['condition_evaluation']}",
                    "access_state=granted",
                    "authorization_model=iam_authorized_server_api",
                    "firestore_security_rules_evaluated=false",
                )
            )
            for path in paths
        }
    )


def _path_database_administration_classes(path: Mapping[str, Any]) -> list[str]:
    return [
        access_class
        for access_class in _string_values(path.get("access_classes"))
        if access_class in _DATABASE_ADMINISTRATION_CLASSES
    ]


def _scope_breadth_evidence(
    paths: list[dict[str, Any]],
    database_addresses: list[str],
) -> list[str]:
    grants_by_scope: dict[str, set[tuple[object, ...]]] = {
        "project": set(),
        "database": set(),
    }
    for path in paths:
        scope_type = path.get("scope_type")
        if scope_type in grants_by_scope:
            grants_by_scope[scope_type].add(_iam_grant_fingerprint(path))
    project_grants = len(grants_by_scope["project"])
    database_grants = len(grants_by_scope["database"])
    basis = "project_applicable_grant" if project_grants else "exact_database_scoped_grant"
    return [
        "; ".join(
            (
                f"project_applicable_grants={project_grants}",
                f"exact_database_grants={database_grants}",
                f"modeled_databases={len(database_addresses)}",
                f"blast_radius_basis={basis}",
            )
        )
    ]


def _iam_grant_fingerprint(path: Mapping[str, Any]) -> tuple[object, ...]:
    scope_type = path.get("scope_type")
    scope = path.get("scope")
    if scope_type == "project":
        scope = normalize_gcp_project(scope) or scope
    return (
        path.get("iam_resource_address"),
        path.get("service_account_member"),
        path.get("role"),
        scope_type,
        scope,
        path.get("grant_basis"),
        path.get("condition_evaluation"),
        json.dumps(path.get("condition"), sort_keys=True, default=str),
    )


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None

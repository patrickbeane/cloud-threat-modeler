from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource
from tfstride.providers.gcp.constants import PUBLIC_GCP_IAM_MEMBERS
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import binding_members

_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker", "roles/run.servicesInvoker"})
_ENTITY_READ_PERMISSION_OPERATIONS = {
    "datastore.entities.get": "get",
    "datastore.entities.list": "list",
}
_ENTITY_READ_WILDCARDS = frozenset({"*", "datastore.*", "datastore.entities.*"})
_ENTITY_MUTATION_PERMISSION_OPERATIONS = {
    "datastore.entities.create": "create",
    "datastore.entities.update": "update",
    "datastore.entities.delete": "delete",
}
_ENTITY_MUTATION_WILDCARDS = frozenset({"*", "datastore.*", "datastore.entities.*"})
_DATABASE_ADMINISTRATION_CLASSES = frozenset({"destructive_administration", "configuration_administration"})


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
    project = _known_string(facts.project)
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
            and path.get("scope") == path.get("firestore_database_project")
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
    return [operation for operation in ("create", "update", "delete") if operation in operations]


def _path_entity_mutation_operations(path: Mapping[str, Any]) -> list[str]:
    operations: set[str] = set()
    for permission in _string_values(path.get("matched_permissions")):
        normalized = permission.strip().lower()
        if normalized in _ENTITY_MUTATION_WILDCARDS:
            operations.update({"create", "update", "delete"})
            continue
        operation = _ENTITY_MUTATION_PERMISSION_OPERATIONS.get(normalized)
        if operation is not None:
            operations.add(operation)
    return [operation for operation in ("create", "update", "delete") if operation in operations]


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
                    (f"matched_permissions={','.join(_string_values(path.get('matched_permissions')))}"),
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
    project_grants = sum(path.get("scope_type") == "project" for path in paths)
    database_grants = sum(path.get("scope_type") == "database" for path in paths)
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


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None

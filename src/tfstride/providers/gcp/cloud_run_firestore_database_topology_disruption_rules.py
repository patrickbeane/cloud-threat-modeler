from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource
from tfstride.providers.gcp.cloud_run_pubsub_rules import (
    _current_public_exposure_reasons,
    _public_exposure_configuration,
    _public_invoker_evidence,
    _unconditional_public_invokers,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_firestore_database_topology_destruction_paths import (
    current_cloud_run_firestore_database_topology_destruction_paths,
)
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext, GcpResourceIndexBuilder
from tfstride.providers.gcp.resource_types import GCP_CLOUD_RUN_RESOURCE_TYPES, GcpResourceType
from tfstride.providers.gcp.structured_data_topology_destruction_evidence import (
    GcpCloudRunFirestoreDatabaseTopologyDestructionPath,
)

_DELETE_DATABASE = "datastore.databases.delete"
_AUTHORIZATION_RELATIONSHIP_FIELDS = (
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
    "operation",
    "operation_class",
    "internal_operation",
    "management_effect",
    "target_granularity",
    "target_scope",
    "target_model_evidence_addresses",
    "iam_resource_address",
    "iam_resource_type",
    "iam_source_addresses",
    "role",
    "matched_permissions",
    "scope_type",
    "scope",
    "resource_scope",
    "grant_basis",
    "condition",
    "condition_state",
    "condition_evaluation",
    "authorization_model",
    "firestore_security_rules_evaluated",
    "firestore_security_rules_applicability",
)


class GcpCloudRunFirestoreDatabaseTopologyDisruptionRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_cloud_run_firestore_database_topology_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        resources = list(context.inventory.resources)
        decoration_context = GcpDecorationContext(GcpResourceIndexBuilder().build(resources))
        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = _unconditional_public_invokers(
                workload,
                resources,
            )
            invoker_iam_check_disabled = gcp_facts(workload).cloud_run_invoker_iam_disabled is True
            if not workload.public_access_configured or (not public_invokers and not invoker_iam_check_disabled):
                continue

            paths: list[GcpCloudRunFirestoreDatabaseTopologyDestructionPath] = []
            seen_keys: set[tuple[str, ...]] = set()
            for cached_path in gcp_facts(workload).cloud_run_firestore_database_topology_destruction_paths:
                current_path = _current_topology_path(
                    cached_path,
                    workload,
                    context,
                    decoration_context,
                )
                if current_path is None:
                    continue
                key = _authorization_relationship_key(current_path)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                paths.append(current_path)
            if not paths:
                continue

            database_addresses = _path_string_values(paths, "firestore_database_address")
            iam_source_addresses = _path_string_values(paths, "iam_source_addresses")
            public_source_addresses = sorted({binding["source"] for binding in public_invokers})
            has_project_scope = any(path.get("scope_type") == "project" for path in paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2 if has_project_scope else 1,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if has_project_scope or len(database_addresses) > 1 else 1,
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
                    rationale=_rationale(
                        workload,
                        len(database_addresses),
                        has_project_scope=has_project_scope,
                        paths=paths,
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "public_invoker_bindings",
                            _public_invoker_evidence(public_invokers),
                        ),
                        evidence_item(
                            "public_exposure_reasons",
                            _current_public_exposure_reasons(
                                workload,
                                public_invokers,
                                invoker_iam_check_disabled=invoker_iam_check_disabled,
                            ),
                        ),
                        evidence_item(
                            "public_exposure_configuration",
                            _public_exposure_configuration(workload),
                        ),
                        evidence_item(
                            "runtime_identity",
                            _runtime_identity_evidence(paths),
                        ),
                        evidence_item(
                            "firestore_database_topology_destruction_paths",
                            _topology_path_evidence(paths),
                        ),
                        evidence_item(
                            "firestore_database_deletion_constraint_evidence",
                            _constraint_evidence(paths),
                        ),
                        evidence_item(
                            "firestore_database_terraform_deletion_policy_evidence",
                            _terraform_deletion_policy_evidence(paths),
                        ),
                        evidence_item(
                            "firestore_database_recovery_evidence",
                            _recovery_evidence(paths),
                        ),
                        evidence_item(
                            "firestore_database_topology_destruction_path_uncertainties",
                            _current_path_uncertainties(paths),
                        ),
                        evidence_item(
                            "assessment_scope",
                            _assessment_scope(),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _current_topology_path(
    cached_path: Mapping[str, object],
    workload: NormalizedResource,
    context: RuleEvaluationContext,
    decoration_context: GcpDecorationContext,
) -> GcpCloudRunFirestoreDatabaseTopologyDestructionPath | None:
    if not _cached_path_is_coherent(cached_path, workload):
        return None

    database_address = _known_string(cached_path.get("firestore_database_address"))
    if database_address is None:
        return None
    database = context.inventory.get_by_address(database_address)
    if database is None or database.provider != "gcp" or database.resource_type != GcpResourceType.FIRESTORE_DATABASE:
        return None

    current_paths = current_cloud_run_firestore_database_topology_destruction_paths(
        workload,
        database,
        list(context.inventory.resources),
        decoration_context,
    )
    return next(
        (
            current_path
            for current_path in current_paths
            if _authorization_relationship_matches(cached_path, current_path)
        ),
        None,
    )


def _cached_path_is_coherent(
    path: Mapping[str, object],
    workload: NormalizedResource,
) -> bool:
    database_address = _known_string(path.get("firestore_database_address"))
    return bool(
        database_address
        and path.get("workload_address") == workload.address
        and path.get("workload_type") == workload.resource_type
        and path.get("identity_kind") == "cloud_run_service_account"
        and path.get("credential_context") == "workload_runtime"
        and path.get("operation") == _DELETE_DATABASE
        and path.get("operation_class") == "database_deletion"
        and path.get("internal_operation") == "delete_database"
        and path.get("management_effect") == "disruption"
        and path.get("target_granularity") == "database_topology"
        and path.get("target_scope") == "exact_firestore_database"
        and path.get("target_model_evidence_addresses") == [database_address]
        and path.get("authorization_state") == "granted"
        and path.get("policy_complete") is True
        and path.get("iam_manager_ambiguity_state") == "not_detected"
        and path.get("matched_permissions") == [_DELETE_DATABASE]
        and path.get("lifecycle_compatibility_state") == "compatible"
    )


def _authorization_relationship_matches(
    cached_path: Mapping[str, object],
    current_path: Mapping[str, object],
) -> bool:
    return all(cached_path.get(field) == current_path.get(field) for field in _AUTHORIZATION_RELATIONSHIP_FIELDS)


def _authorization_relationship_key(path: Mapping[str, object]) -> tuple[str, ...]:
    return tuple(repr(path.get(field)) for field in _AUTHORIZATION_RELATIONSHIP_FIELDS)


def _path_string_values(paths: Sequence[Mapping[str, object]], key: str) -> list[str]:
    values: set[str] = set()
    for path in paths:
        value = path.get(key)
        if key == "iam_source_addresses":
            if isinstance(value, list):
                values.update(item for item in value if isinstance(item, str) and item)
        elif isinstance(value, str) and value:
            values.add(value)
    return sorted(values)


def _runtime_identity_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"service_account={path.get('service_account_email')}",
                    f"member={path.get('service_account_member')}",
                    f"role={path.get('role')}",
                    "identity_kind=cloud_run_service_account",
                    "credential_context=workload_runtime",
                )
            )
            for path in paths
        }
    )


def _topology_path_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"database_address={path.get('firestore_database_address')}",
                    f"database_resource_name={path.get('firestore_database_resource_name')}",
                    f"database_name={path.get('firestore_database_name')}",
                    f"database_project={path.get('firestore_database_project')}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_scope={path.get('target_scope')}",
                    f"scope_type={path.get('scope_type')}",
                    f"scope={path.get('scope')}",
                    f"resource_scope={path.get('resource_scope')}",
                    f"iam_resource={path.get('iam_resource_address')}",
                    f"iam_sources={','.join(_string_values(path.get('iam_source_addresses'))) or 'none'}",
                    f"role={path.get('role')}",
                    f"role_kind={_role_kind(path.get('role_evidence'))}",
                    f"custom_role_permissions={','.join(_custom_role_permissions(path.get('role_evidence'))) or 'none'}",
                    f"matched_permissions={','.join(_string_values(path.get('matched_permissions')))}",
                    "authorization_state=granted",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _constraint_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        constraint = path.get("deletion_constraint_evidence")
        if not isinstance(constraint, Mapping):
            continue
        constraint_map = cast(Mapping[str, object], constraint)
        values.add(
            "; ".join(
                (
                    f"database_address={path.get('firestore_database_address')}",
                    f"delete_protection_state={_display(constraint_map.get('delete_protection_state'))}",
                    f"delete_protection_enablement={_display(constraint_map.get('delete_protection_enablement'))}",
                    f"delete_protection_enabled={_display(constraint_map.get('delete_protection_enabled'))}",
                    f"provider_default_applied={_display(constraint_map.get('provider_default_applied'))}",
                    f"deletion_compatibility_state={_display(constraint_map.get('deletion_compatibility_state'))}",
                    f"uncertainties={','.join(_string_values(constraint_map.get('uncertainties'))) or 'none'}",
                )
            )
        )
    return sorted(values)


def _terraform_deletion_policy_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        policy = path.get("terraform_deletion_policy_evidence")
        if not isinstance(policy, Mapping):
            continue
        policy_map = cast(Mapping[str, object], policy)
        values.add(
            "; ".join(
                (
                    f"database_address={path.get('firestore_database_address')}",
                    f"policy_state={_display(policy_map.get('policy_state'))}",
                    f"policy={_display(policy_map.get('policy'))}",
                    f"runtime_api_authorization_effect={_display(policy_map.get('runtime_api_authorization_effect'))}",
                    f"uncertainties={','.join(_string_values(policy_map.get('uncertainties'))) or 'none'}",
                )
            )
        )
    return sorted(values)


def _recovery_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        recovery = path.get("recovery_evidence")
        if not isinstance(recovery, Mapping):
            continue
        recovery_map = cast(Mapping[str, object], recovery)
        values.add(
            "; ".join(
                (
                    f"database_address={path.get('firestore_database_address')}",
                    f"pitr_state={_display(recovery_map.get('pitr_state'))}",
                    f"pitr_enabled={_display(recovery_map.get('pitr_enabled'))}",
                    f"historical_version_retention_state={_display(recovery_map.get('historical_version_retention_state'))}",
                    f"database_recovery_state={_display(recovery_map.get('database_recovery_state'))}",
                    f"database_content_prerequisites_evaluated={_display(recovery_map.get('database_content_prerequisites_evaluated'))}",
                    f"app_engine_search_and_blob_entity_prerequisite_state={_display(recovery_map.get('app_engine_search_and_blob_entity_prerequisite_state'))}",
                    f"eventarc_trigger_impact_evaluated={_display(recovery_map.get('eventarc_trigger_impact_evaluated'))}",
                    f"out_of_plan_topology_evaluated={_display(recovery_map.get('out_of_plan_topology_evaluated'))}",
                    f"successful_deletion_observed={_display(recovery_map.get('successful_deletion_observed'))}",
                    f"restoration_observed={_display(recovery_map.get('restoration_observed'))}",
                    f"uncertainties={','.join(_string_values(recovery_map.get('uncertainties'))) or 'none'}",
                )
            )
        )
    return sorted(values)


def _current_path_uncertainties(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted({uncertainty for path in paths for uncertainty in _string_values(path.get("posture_uncertainties"))})


def _assessment_scope() -> list[str]:
    return [
        (
            "establishes=deterministic datastore.databases.delete authority over exact modeled "
            "Firestore database topology with Denial of Service effect"
        ),
        (
            "does_not_establish=database content prerequisites, successful deletion, recovery, "
            "Eventarc trigger impact, or authority over out-of-plan Firestore topology"
        ),
    ]


def _rationale(
    workload: NormalizedResource,
    database_count: int,
    *,
    has_project_scope: bool,
    paths: Sequence[Mapping[str, object]],
) -> str:
    database_text = "database" if database_count == 1 else "databases"
    rationale = (
        f"{workload.display_name} is publicly invokable and its Cloud Run runtime service account has "
        f"deterministic Firestore database-topology deletion authority ({_DELETE_DATABASE}) across "
        f"{database_count} exact modeled Firestore {database_text}. A compromise of the public workload "
        "could request deletion of those database topologies through the service-account-authenticated "
        "server/API path. "
    )
    if has_project_scope:
        rationale += (
            "At least one grant is project-applicable and can reach Firestore databases across the project, "
            "so its blast radius is broader than an exact database-scoped grant. "
        )
    else:
        rationale += "The modeled grants are limited by exact Firestore database-name conditions. "
    if any(_recovery_state(path) == "pitr_enabled" for path in paths):
        rationale += "Point-in-time recovery evidence preserves a historical-recovery posture, but not restoration. "
    if any(_recovery_state(path) == "recovery_posture_unknown" for path in paths):
        rationale += "Recovery posture is partly unknown, but that uncertainty does not remove deterministic deletion authority. "
    return rationale + (
        "Firestore Security Rules are not evaluated for server/API access authenticated through the Cloud Run "
        "runtime service account. This plan-local evidence does not establish database content prerequisites, "
        "successful deletion, recovery, Eventarc trigger impact, or out-of-plan Firestore topology."
    )


def _recovery_state(path: Mapping[str, object]) -> str:
    recovery = path.get("recovery_evidence")
    if not isinstance(recovery, Mapping):
        return "recovery_posture_unknown"
    recovery_map = cast(Mapping[str, object], recovery)
    if recovery_map.get("pitr_state") == "enabled":
        return "pitr_enabled"
    if recovery_map.get("pitr_state") == "unknown":
        return "recovery_posture_unknown"
    return "pitr_not_enabled"


def _role_kind(value: object) -> str:
    if isinstance(value, Mapping):
        role_kind = cast(Mapping[str, object], value).get("role_kind")
        if isinstance(role_kind, str):
            return role_kind
    return "unknown"


def _custom_role_permissions(value: object) -> list[str]:
    if not isinstance(value, Mapping):
        return []
    return _string_values(cast(Mapping[str, object], value).get("custom_role_permissions"))


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in cast(list[object], value) if isinstance(item, str) and item]


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _display(value: object) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)

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
from tfstride.providers.gcp.audit_telemetry_disruption_evidence import (
    GcpCloudRunLoggingSinkAuditTelemetryDisruptionPath,
)
from tfstride.providers.gcp.cloud_run_public_invocation import (
    cloud_run_public_exposure_configuration,
    cloud_run_public_invoker_evidence,
    current_cloud_run_public_exposure_reasons,
    current_cloud_run_public_invokers,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_logging_sink_audit_telemetry_disruption_paths import (
    current_cloud_run_logging_sink_audit_telemetry_disruption_paths,
)
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext, GcpResourceIndexBuilder
from tfstride.providers.gcp.resource_types import GCP_CLOUD_RUN_RESOURCE_TYPES, GcpResourceType

_DELETE_SINK = "logging.sinks.delete"
# These fields identify the stable workload -> exact sink authorization
# relationship. The current model path remains authoritative for destination,
# filter/relevance, lifecycle, custom-role, and other descriptive evidence.
_AUTHORIZATION_RELATIONSHIP_FIELDS = (
    "workload_address",
    "workload_type",
    "service_account_email",
    "service_account_member",
    "identity_kind",
    "credential_context",
    "logging_sink_address",
    "logging_sink_resource_type",
    "logging_sink_name",
    "logging_sink_resource_name",
    "logging_sink_project",
    "operation",
    "operation_class",
    "internal_operation",
    "management_effect",
    "target_granularity",
    "target_scope",
    "target_model_evidence_addresses",
    "iam_resource_address",
    "iam_resource_type",
    "role",
    "scope_type",
    "scope",
    "resource_scope",
    "grant_basis",
)


class GcpCloudRunLoggingSinkDisruptionRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_cloud_run_logging_sink_disruption(
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
            public_invokers = current_cloud_run_public_invokers(workload, resources)
            invoker_iam_check_disabled = gcp_facts(workload).cloud_run_invoker_iam_disabled is True
            if not workload.public_access_configured or (not public_invokers and not invoker_iam_check_disabled):
                continue

            paths: list[GcpCloudRunLoggingSinkAuditTelemetryDisruptionPath] = []
            seen_keys: set[tuple[str, ...]] = set()
            for cached_path in gcp_facts(workload).cloud_run_logging_sink_audit_telemetry_disruption_paths:
                current_path = _current_logging_sink_path(
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

            sink_addresses = _path_string_values(paths, "logging_sink_address")
            iam_source_addresses = _path_string_values(paths, "iam_source_addresses")
            public_source_addresses = sorted({binding["source"] for binding in public_invokers})
            has_project_scope = any(path.get("scope_type") == "project" for path in paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2 if has_project_scope else 1,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if has_project_scope or len(sink_addresses) > 1 else 1,
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
                            *sink_addresses,
                            *iam_source_addresses,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_rationale(workload, paths),
                    evidence=collect_evidence(
                        evidence_item(
                            "public_invoker_bindings",
                            cloud_run_public_invoker_evidence(public_invokers),
                        ),
                        evidence_item(
                            "public_exposure_reasons",
                            current_cloud_run_public_exposure_reasons(
                                workload,
                                public_invokers,
                                invoker_iam_check_disabled=invoker_iam_check_disabled,
                            ),
                        ),
                        evidence_item(
                            "public_exposure_configuration",
                            cloud_run_public_exposure_configuration(workload),
                        ),
                        evidence_item("runtime_identity", _runtime_identity_evidence(paths)),
                        evidence_item(
                            "logging_sink_audit_telemetry_disruption_paths",
                            _path_evidence(paths),
                        ),
                        evidence_item("logging_sink_lifecycle_evidence", _lifecycle_evidence(paths)),
                        evidence_item("logging_sink_deletion_constraint_evidence", _constraint_evidence(paths)),
                        evidence_item(
                            "logging_sink_audit_telemetry_relevance_evidence",
                            _relevance_evidence(paths),
                        ),
                        evidence_item("logging_sink_outcome_evidence", _outcome_evidence(paths)),
                        evidence_item("assessment_scope", _assessment_scope()),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _current_logging_sink_path(
    cached_path: Mapping[str, object],
    workload: NormalizedResource,
    context: RuleEvaluationContext,
    decoration_context: GcpDecorationContext,
) -> GcpCloudRunLoggingSinkAuditTelemetryDisruptionPath | None:
    if not _cached_path_is_coherent(cached_path, workload):
        return None

    sink_address = _known_string(cached_path.get("logging_sink_address"))
    if sink_address is None:
        return None
    logging_sink = context.inventory.get_by_address(sink_address)
    if (
        logging_sink is None
        or logging_sink.provider != "gcp"
        or logging_sink.resource_type != GcpResourceType.LOGGING_PROJECT_SINK
    ):
        return None

    current_paths = current_cloud_run_logging_sink_audit_telemetry_disruption_paths(
        workload,
        logging_sink,
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
    sink_address = _known_string(path.get("logging_sink_address"))
    return bool(
        sink_address
        and path.get("workload_address") == workload.address
        and path.get("workload_type") == workload.resource_type
        and path.get("identity_kind") == "cloud_run_service_account"
        and path.get("credential_context") == "workload_runtime"
        and path.get("operation") == _DELETE_SINK
        and path.get("operation_class") == "project_sink_deletion"
        and path.get("internal_operation") == "delete_project_logging_sink"
        and path.get("management_effect") == "audit_telemetry_disruption"
        and path.get("target_granularity") == "project_logging_sink"
        and path.get("target_scope") == "exact_project_logging_sink"
        and path.get("target_model_evidence_addresses") == [sink_address]
        and path.get("scope_type") == "project"
        and path.get("resource_scope") == "logging_project"
        and path.get("grant_basis") == "logging_project_iam"
        and path.get("authorization_state") == "granted"
        and path.get("policy_complete") is True
        and path.get("iam_manager_ambiguity_state") == "not_detected"
        and path.get("condition") is None
        and path.get("condition_state") == "not_configured"
        and path.get("condition_evaluation") == "not_configured"
        and path.get("matched_permissions") == [_DELETE_SINK]
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


def _path_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"sink_address={path.get('logging_sink_address')}",
                    f"sink_resource_name={path.get('logging_sink_resource_name')}",
                    f"sink_project={path.get('logging_sink_project')}",
                    f"destination={path.get('logging_sink_destination')}",
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


def _lifecycle_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        evidence = path.get("lifecycle_evidence")
        if not isinstance(evidence, Mapping):
            continue
        evidence_map = cast(Mapping[str, object], evidence)
        values.add(
            "; ".join(
                (
                    f"sink_address={path.get('logging_sink_address')}",
                    f"sink_lifecycle_state={_display(evidence_map.get('sink_lifecycle_state'))}",
                    f"sink_disabled={_display(evidence_map.get('sink_disabled'))}",
                    f"disabled_configuration_state={_display(evidence_map.get('disabled_configuration_state'))}",
                    f"provider_default_applied={_display(evidence_map.get('provider_default_applied'))}",
                    f"lifecycle_compatibility_state={_display(evidence_map.get('lifecycle_compatibility_state'))}",
                    f"uncertainties={','.join(_string_values(evidence_map.get('uncertainties'))) or 'none'}",
                )
            )
        )
    return sorted(values)


def _constraint_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        evidence = path.get("deletion_constraint_evidence")
        if not isinstance(evidence, Mapping):
            continue
        evidence_map = cast(Mapping[str, object], evidence)
        values.add(
            "; ".join(
                (
                    f"sink_address={path.get('logging_sink_address')}",
                    f"sink_kind={_display(evidence_map.get('sink_kind'))}",
                    f"system_sink_name={_display(evidence_map.get('system_sink_name'))}",
                    f"api_deletion_supported={_display(evidence_map.get('api_deletion_supported'))}",
                    f"deletion_compatibility_state={_display(evidence_map.get('deletion_compatibility_state'))}",
                    f"uncertainties={','.join(_string_values(evidence_map.get('uncertainties'))) or 'none'}",
                )
            )
        )
    return sorted(values)


def _relevance_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        evidence = path.get("audit_telemetry_relevance_evidence")
        if not isinstance(evidence, Mapping):
            continue
        evidence_map = cast(Mapping[str, object], evidence)
        values.add(
            "; ".join(
                (
                    f"sink_address={path.get('logging_sink_address')}",
                    f"filter_state={_display(evidence_map.get('filter_state'))}",
                    f"sink_filter={_display(evidence_map.get('sink_filter'))}",
                    f"relevance_basis={_display(evidence_map.get('relevance_basis'))}",
                    f"matched_signals={','.join(_string_values(evidence_map.get('matched_audit_security_filter_signals'))) or 'none'}",
                    f"audit_telemetry_relevance_state={_display(evidence_map.get('audit_telemetry_relevance_state'))}",
                    f"uncertainties={','.join(_string_values(evidence_map.get('uncertainties'))) or 'none'}",
                )
            )
        )
    return sorted(values)


def _outcome_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        evidence = path.get("outcome_evidence")
        if not isinstance(evidence, Mapping):
            continue
        evidence_map = cast(Mapping[str, object], evidence)
        values.add(
            "; ".join(
                (
                    f"sink_address={path.get('logging_sink_address')}",
                    f"successful_operation_observed={_display(evidence_map.get('successful_operation_observed'))}",
                    f"historical_log_entry_deletion_observed={_display(evidence_map.get('historical_log_entry_deletion_observed'))}",
                    f"destination_resource_deletion_observed={_display(evidence_map.get('destination_resource_deletion_observed'))}",
                    f"all_project_audit_sinks_evaluated={_display(evidence_map.get('all_project_audit_sinks_evaluated'))}",
                    f"out_of_plan_sinks_evaluated={_display(evidence_map.get('out_of_plan_sinks_evaluated'))}",
                    f"telemetry_recovery_state={_display(evidence_map.get('telemetry_recovery_state'))}",
                    f"restoration_observed={_display(evidence_map.get('restoration_observed'))}",
                )
            )
        )
    return sorted(values)


def _assessment_scope() -> list[str]:
    return [
        (
            "establishes=Repudiation risk from deterministic logging.sinks.delete authority over exact "
            "active project logging sinks that export modeled audit/security telemetry"
        ),
        (
            "effect=compromise of the public workload could disrupt future export or recording of the modeled "
            "audit/security telemetry to the modeled destination, weakening auditability/accountability"
        ),
        (
            "does_not_establish=successful API operation, sink deletion, retained or delivered log deletion, "
            "destination deletion, disruption of every or out-of-plan sink, historical audit-log erasure, "
            "or recovery/restoration"
        ),
    ]


def _rationale(
    workload: NormalizedResource,
    paths: Sequence[Mapping[str, object]],
) -> str:
    sink_count = len({path.get("logging_sink_address") for path in paths})
    sink_label = "sink" if sink_count == 1 else "sinks"
    destinations = sorted(
        {
            destination
            for path in paths
            if isinstance(destination := path.get("logging_sink_destination"), str) and destination
        }
    )
    destination_text = ", ".join(destinations) or "the modeled destination"
    return (
        f"{workload.display_name} is publicly invokable and its Cloud Run runtime service account has "
        f"current deterministic {_DELETE_SINK} authority over {sink_count} exact active project logging "
        f"{sink_label} that export modeled audit/security telemetry to {destination_text}. A compromise of "
        "the public workload could request deletion of those modeled sink targets, disrupting future "
        "export or recording of the modeled audit/security telemetry and weakening auditability/accountability. "
        "This plan-local evidence does not establish a successful API call, sink deletion, deletion of retained "
        "source logs or logs already delivered to the destination, deletion of the destination resource, "
        "disruption of every project or out-of-plan sink, historical audit-log erasure, or recovery/restoration."
    )


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

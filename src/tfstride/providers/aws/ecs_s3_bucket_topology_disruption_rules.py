from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.aws.ecs_path_rule_helpers import (
    internet_boundary_id,
    path_string_values,
    public_service_network_path,
    resolved_public_load_balancers,
)
from tfstride.providers.aws.object_storage_topology_destruction_evidence import (
    AwsEcsS3BucketTopologyDestructionPath,
)
from tfstride.providers.aws.resource_decoration.ecs_s3_bucket_topology_destruction_paths import (
    current_s3_bucket_topology_destruction_path,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import (
    AwsDecorationContext,
    AwsResourceIndexBuilder,
)

_AWS_ECS_SERVICE = "aws_ecs_service"
_AWS_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_AWS_IAM_ROLE = "aws_iam_role"
_AWS_S3_BUCKET = "aws_s3_bucket"
_DELETE_BUCKET = "s3:DeleteBucket"
_EXCLUDED_PROJECTION_FIELDS = frozenset(
    {
        "workload_address",
        "workload_type",
        "internet_facing_load_balancers",
    }
)


class AwsEcsS3BucketTopologyDisruptionRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_service_topology_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        decoration_context = AwsDecorationContext(
            AwsResourceIndexBuilder().build(list(context.inventory.resources)),
        )
        findings: list[Finding] = []
        for service in context.inventory.by_type(_AWS_ECS_SERVICE):
            service_facts = aws_facts(service)
            paths = [
                path
                for path in service_facts.ecs_s3_bucket_topology_destruction_paths
                if _is_current_deterministic_path(
                    path,
                    service,
                    context,
                    decoration_context,
                )
            ]
            if not paths:
                continue

            load_balancer_addresses = resolved_public_load_balancers(paths, context)
            if not load_balancer_addresses:
                continue

            task_definition_addresses = path_string_values(paths, "task_definition_address")
            role_addresses = path_string_values(paths, "role_address")
            bucket_addresses = path_string_values(paths, "bucket_address")
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if len(bucket_addresses) > 1 else 1,
            )
            affected_resources = [
                *load_balancer_addresses,
                service.address,
                *task_definition_addresses,
                *role_addresses,
                *bucket_addresses,
            ]
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=list(dict.fromkeys(affected_resources)),
                    trust_boundary_id=internet_boundary_id(load_balancer_addresses, context),
                    rationale=_rationale(service, len(bucket_addresses)),
                    evidence=collect_evidence(
                        evidence_item(
                            "network_path",
                            public_service_network_path(load_balancer_addresses, service.address),
                        ),
                        evidence_item(
                            "task_definitions",
                            [f"address={address}" for address in task_definition_addresses],
                        ),
                        evidence_item("task_roles", _task_role_evidence(paths)),
                        evidence_item(
                            "s3_bucket_topology_destruction_paths",
                            _topology_path_evidence(paths),
                        ),
                        evidence_item(
                            "bucket_deletion_recovery_evidence",
                            _recovery_evidence(paths),
                        ),
                        evidence_item(
                            "s3_bucket_topology_destruction_path_uncertainties",
                            service_facts.ecs_s3_bucket_topology_destruction_path_uncertainties,
                        ),
                        evidence_item("assessment_scope", _assessment_scope()),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_current_deterministic_path(
    path: AwsEcsS3BucketTopologyDestructionPath,
    service: NormalizedResource,
    context: RuleEvaluationContext,
    decoration_context: AwsDecorationContext,
) -> bool:
    task_definition = _resource_for_path(
        path,
        "task_definition_address",
        _AWS_ECS_TASK_DEFINITION,
        context,
    )
    role = _resource_for_path(path, "role_address", _AWS_IAM_ROLE, context)
    bucket = _resource_for_path(path, "bucket_address", _AWS_S3_BUCKET, context)
    if task_definition is None or role is None or bucket is None:
        return False

    role_arn = role.arn
    bucket_arn = bucket.arn
    if not isinstance(role_arn, str) or not isinstance(bucket_arn, str):
        return False

    service_facts = aws_facts(service)
    current_task_path = current_s3_bucket_topology_destruction_path(
        task_definition,
        bucket,
        decoration_context,
    )
    if current_task_path is None:
        return False

    if (
        task_definition.address not in service_facts.resolved_task_definition_addresses
        or path.get("workload_address") != service.address
        or path.get("workload_type") != service.resource_type
        or path.get("task_definition_address") != task_definition.address
        or path.get("task_definition_arn") != task_definition.arn
        or path.get("role_kind") != "ecs_task_role"
        or path.get("credential_context") != "workload_runtime"
        or path.get("role_address") != role.address
        or path.get("role_arn") != role_arn
        or path.get("same_account") is not True
        or path.get("bucket_address") != bucket.address
        or path.get("bucket_arn") != bucket_arn
        or not _is_exact_iam_role_arn(role_arn)
        or not _is_exact_bucket_arn(bucket_arn)
        or path.get("operation") != _DELETE_BUCKET
        or path.get("operation_class") != "bucket_deletion"
        or path.get("internal_operation") != "delete_bucket"
        or path.get("management_effect") != "disruption"
        or path.get("target_granularity") != "bucket_topology"
        or path.get("target_scope") != "exact_s3_bucket"
        or path.get("authorization_state") != "allowed"
        or path.get("evaluation_basis") != "modeled_identity_and_bucket_policies"
        or path.get("matched_actions") != [_DELETE_BUCKET]
        or path.get("identity_policy_complete") is not True
        or path.get("bucket_policy_complete") is not True
        or path.get("explicit_deny") is not False
        or path.get("conditional_evaluation_required") is not False
        or path.get("lifecycle_compatibility_state") != "bucket_emptiness_not_established"
        or not _current_load_balancers(
            path,
            service_facts.internet_facing_load_balancer_addresses,
        )
        or not _matches_current_task_path(path, (current_task_path,))
    ):
        return False

    return True


def _resource_for_path(
    path: Mapping[str, object],
    key: str,
    expected_type: str,
    context: RuleEvaluationContext,
) -> NormalizedResource | None:
    address = path.get(key)
    resource = context.inventory.get_by_address(address) if isinstance(address, str) else None
    if resource is None or resource.provider != "aws" or resource.resource_type != expected_type:
        return None
    return resource


def _current_load_balancers(
    path: Mapping[str, object],
    current: Sequence[str],
) -> bool:
    values = path.get("internet_facing_load_balancers")
    return isinstance(values, list) and set(values) == set(current)


def _matches_current_task_path(
    projected_path: Mapping[str, object],
    current_paths: Sequence[Mapping[str, object]],
) -> bool:
    projected_keys = set(projected_path) - _EXCLUDED_PROJECTION_FIELDS
    for current_path in current_paths:
        current_keys = set(current_path) - _EXCLUDED_PROJECTION_FIELDS
        if projected_keys != current_keys:
            continue
        if all(projected_path[key] == current_path[key] for key in projected_keys):
            return True
    return False


def _is_exact_iam_role_arn(value: str) -> bool:
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[1]
        and parts[2] == "iam"
        and not parts[3]
        and parts[4]
        and parts[5].startswith("role/")
        and len(parts[5]) > len("role/")
        and "*" not in value
        and "?" not in value
    )


def _is_exact_bucket_arn(value: str) -> bool:
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[1]
        and parts[2] == "s3"
        and not parts[3]
        and not parts[4]
        and parts[5]
        and "/" not in parts[5]
        and "*" not in value
        and "?" not in value
    )


def _task_role_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"address={path.get('role_address')}",
                    f"arn={path.get('role_arn')}",
                    "role_kind=ecs_task_role",
                    "credential_context=workload_runtime",
                    "authorization_state=allowed",
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
                    f"bucket_address={path.get('bucket_address')}",
                    f"bucket_name={path.get('bucket_name')}",
                    f"bucket_arn={path.get('bucket_arn')}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_scope={path.get('target_scope')}",
                    f"task_definition={path.get('task_definition_address')}",
                    f"task_role={path.get('role_address')}",
                    f"authorization_bases={','.join(_string_values(path.get('authorization_bases'))) or 'none'}",
                    f"authorization_sources={','.join(_string_values(path.get('authorization_source_addresses'))) or 'none'}",
                    "same_account=true",
                    "authorization_state=allowed",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _recovery_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        evidence = path.get("recovery_evidence")
        if not isinstance(evidence, Mapping):
            continue
        evidence_map = cast(Mapping[str, object], evidence)
        values.add(
            "; ".join(
                (
                    f"bucket_address={path.get('bucket_address')}",
                    f"operation={path.get('operation')}",
                    f"bucket_emptiness_required={_display(evidence_map.get('bucket_emptiness_required'))}",
                    f"bucket_emptiness_state={_display(evidence_map.get('bucket_emptiness_state'))}",
                    f"versioning_status={_display(evidence_map.get('versioning_status'))}",
                    f"object_lock_enabled={_display(evidence_map.get('object_lock_enabled'))}",
                    f"attached_access_point_state={_display(evidence_map.get('attached_access_point_state'))}",
                    f"out_of_plan_object_inventory_evaluated={_display(evidence_map.get('out_of_plan_object_inventory_evaluated'))}",
                    f"bucket_recovery_state={_display(evidence_map.get('bucket_recovery_state'))}",
                    f"successful_deletion_observed={_display(evidence_map.get('successful_deletion_observed'))}",
                    f"recovery_observed={_display(evidence_map.get('recovery_observed'))}",
                )
            )
        )
    return sorted(values)


def _assessment_scope() -> list[str]:
    return [
        (
            "establishes=deterministic s3:DeleteBucket authority for an ECS task role over exact modeled "
            "S3 bucket topology with Denial of Service effect"
        ),
        (
            "does_not_establish=bucket emptiness, successful deletion, access-point compatibility, recovery, "
            "descendant impact, or authority over out-of-plan objects"
        ),
    ]


def _rationale(service: NormalizedResource, bucket_count: int) -> str:
    bucket_text = "bucket" if bucket_count == 1 else "buckets"
    return (
        f"{service.display_name} is reachable through an internet-facing load balancer and its ECS task role "
        f"has deterministic S3 bucket-topology deletion authority (s3:DeleteBucket) across {bucket_count} exact "
        f"modeled S3 {bucket_text}. A compromise of the public workload could request deletion of those bucket "
        "topologies, subject to provider-side bucket deletion prerequisites. This plan-local evidence does not "
        "establish bucket emptiness, successful deletion, access-point compatibility, recovery, or out-of-plan objects."
    )


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in cast(list[object], value) if isinstance(item, str)]


def _display(value: object) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)

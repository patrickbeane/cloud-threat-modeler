from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, SeverityReasoning
from tfstride.providers.aws.ecs_path_rule_helpers import (
    internet_boundary_id,
    path_string_values,
    public_service_network_path,
    resolved_public_load_balancers,
)
from tfstride.providers.aws.resource_facts import aws_facts

_AWS_DYNAMODB_TABLE = "aws_dynamodb_table"
_AWS_ECS_SERVICE = "aws_ecs_service"
_MUTATION_CLASS_ORDER = (
    "entity_write",
    "entity_delete",
    "destructive_administration",
    "configuration_administration",
)
_MUTATION_ACCESS_CLASSES = frozenset(_MUTATION_CLASS_ORDER)
_CLASS_PRIVILEGE_BREADTH = {
    "entity_write": 1,
    "entity_delete": 2,
    "configuration_administration": 2,
    "destructive_administration": 3,
}
_CLASS_CAPABILITIES = {
    "entity_write": "create or update items in the modeled table",
    "entity_delete": "delete items from the modeled table",
    "destructive_administration": ("delete complete DynamoDB tables or replicas and their stored data"),
    "configuration_administration": (
        "change DynamoDB table configuration or controls without directly modifying item contents"
    ),
}


class AwsEcsDynamoDbAccessRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_service_mutation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for service in context.inventory.by_type(_AWS_ECS_SERVICE):
            mutation_paths = [
                path
                for path in aws_facts(service).ecs_dynamodb_access_paths
                if _is_deterministic_mutation_path(
                    path,
                    service.address,
                    context,
                )
            ]
            if not mutation_paths:
                continue

            load_balancer_addresses = resolved_public_load_balancers(
                mutation_paths,
                context,
            )
            if not load_balancer_addresses:
                continue

            task_definition_addresses = path_string_values(
                mutation_paths,
                "task_definition_address",
            )
            role_addresses = path_string_values(mutation_paths, "role_address")
            table_addresses = path_string_values(
                mutation_paths,
                "dynamodb_table_address",
            )
            mutation_classes = _mutation_classes(mutation_paths)
            severity_reasoning = _mutation_severity(
                mutation_classes,
                table_count=len(table_addresses),
            )
            affected_resources = [
                *load_balancer_addresses,
                service.address,
                *task_definition_addresses,
                *role_addresses,
                *table_addresses,
            ]
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=list(dict.fromkeys(affected_resources)),
                    trust_boundary_id=internet_boundary_id(
                        load_balancer_addresses,
                        context,
                    ),
                    rationale=(
                        f"{service.display_name} is reachable through an "
                        "internet-facing load balancer and its ECS task role has "
                        "an unconditional identity-policy allow for DynamoDB mutation "
                        f"on {len(table_addresses)} exact modeled table(s). A compromise "
                        "of the public workload could attempt to "
                        f"{_capability_summary(mutation_classes)}."
                        f"{_impact_context(mutation_classes)} This establishes a modeled "
                        "identity-policy path, not guaranteed effective authorization "
                        "through every AWS policy layer. The DynamoDB table itself is "
                        "not public."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "network_path",
                            public_service_network_path(
                                load_balancer_addresses,
                                service.address,
                            ),
                        ),
                        evidence_item(
                            "task_definitions",
                            [f"address={address}" for address in task_definition_addresses],
                        ),
                        evidence_item(
                            "task_roles",
                            _task_role_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "dynamodb_mutation_paths",
                            _mutation_path_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "impact_profile",
                            _impact_profile(mutation_classes),
                        ),
                        evidence_item(
                            "assessment_scope",
                            [
                                ("establishes=unconditional identity-policy allow for exact DynamoDB mutation actions"),
                                (
                                    "does_not_establish=effective authorization after "
                                    "DynamoDB resource policies, permissions boundaries, "
                                    "service control policies, or deletion protection"
                                ),
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_deterministic_mutation_path(
    path: Mapping[str, Any],
    service_address: str,
    context: RuleEvaluationContext,
) -> bool:
    target_address = path.get("dynamodb_table_address")
    target = context.inventory.get_by_address(target_address) if isinstance(target_address, str) else None
    target_arn = aws_facts(target).dynamodb_table_arn or target.arn if target is not None else None
    return (
        path.get("workload_type") == _AWS_ECS_SERVICE
        and path.get("workload_address") == service_address
        and all(
            isinstance(path.get(key), str) and bool(path.get(key))
            for key in (
                "task_definition_address",
                "role_address",
                "dynamodb_table_address",
                "dynamodb_table_arn",
            )
        )
        and target is not None
        and target.resource_type == _AWS_DYNAMODB_TABLE
        and target_arn == path.get("dynamodb_table_arn")
        and path.get("role_kind") == "ecs_task_role"
        and path.get("credential_context") == "workload_runtime"
        and path.get("access_state") == "allowed"
        and path.get("modeled_access_state") == "allowed"
        and path.get("role_policy_complete") is True
        and "exact_table" in _string_values(path.get("resource_scopes"))
        and bool(_path_mutation_classes(path))
        and bool(_mutation_actions(path))
    )


def _mutation_classes(paths: list[dict[str, Any]]) -> list[str]:
    classes = {access_class for path in paths for access_class in _path_mutation_classes(path)}
    return [access_class for access_class in _MUTATION_CLASS_ORDER if access_class in classes]


def _path_mutation_classes(path: Mapping[str, Any]) -> list[str]:
    classes = {value for value in _string_values(path.get("access_classes")) if value in _MUTATION_ACCESS_CLASSES}
    return [access_class for access_class in _MUTATION_CLASS_ORDER if access_class in classes]


def _mutation_actions(path: Mapping[str, Any]) -> list[str]:
    return [action for action in _string_values(path.get("matched_actions")) if action.lower().startswith("dynamodb:")]


def _mutation_severity(
    mutation_classes: list[str],
    *,
    table_count: int,
) -> SeverityReasoning:
    privilege_breadth = max(_CLASS_PRIVILEGE_BREADTH[access_class] for access_class in mutation_classes)
    destructive = "destructive_administration" in mutation_classes
    return build_severity_reasoning(
        internet_exposure=True,
        privilege_breadth=privilege_breadth,
        data_sensitivity=2,
        lateral_movement=1,
        blast_radius=2 if destructive or table_count > 1 else 1,
    )


def _capability_summary(mutation_classes: list[str]) -> str:
    capabilities = [_CLASS_CAPABILITIES[access_class] for access_class in mutation_classes]
    if len(capabilities) == 1:
        return capabilities[0]
    if len(capabilities) == 2:
        return " and ".join(capabilities)
    return ", ".join(capabilities[:-1]) + f", and {capabilities[-1]}"


def _impact_context(mutation_classes: list[str]) -> str:
    if "destructive_administration" in mutation_classes:
        return (
            " Destructive table administration is weighted more heavily than "
            "item-level mutation because it can affect a complete table or replica."
        )
    if "configuration_administration" in mutation_classes:
        return (
            " This is configuration or control mutation rather than a claim that "
            "the action directly modifies item contents."
        )
    return ""


def _impact_profile(mutation_classes: list[str]) -> list[str]:
    return [
        f"class={access_class}; capability={_CLASS_CAPABILITIES[access_class]}; "
        f"privilege_breadth={_CLASS_PRIVILEGE_BREADTH[access_class]}"
        for access_class in mutation_classes
    ]


def _task_role_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"address={path['role_address']}",
                    f"arn={path.get('role_arn') or 'unknown'}",
                    "role_kind=ecs_task_role",
                    "credential_context=workload_runtime",
                    "role_policy_complete=true",
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
                    f"table_address={path['dynamodb_table_address']}",
                    f"table_arn={path['dynamodb_table_arn']}",
                    f"task_definition={path['task_definition_address']}",
                    f"task_role={path['role_address']}",
                    (f"mutation_classes={','.join(_path_mutation_classes(path))}"),
                    f"actions={','.join(_mutation_actions(path))}",
                    (f"resource_scopes={','.join(_string_values(path.get('resource_scopes')))}"),
                    (f"policy_resources={','.join(_string_values(path.get('policy_resources')))}"),
                    (f"denied_actions={','.join(_string_values(path.get('denied_actions'))) or 'none'}"),
                    "access_state=allowed",
                    "mutation_evaluation=unconditional_identity_policy_allow",
                )
            )
            for path in paths
        }
    )


def _string_values(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]

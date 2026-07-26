from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, Literal

from tfstride.models import IAMPolicyCondition, IAMPolicyStatement, NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.coercion import dedupe

AccessClass = Literal[
    "entity_write",
    "entity_delete",
    "destructive_administration",
    "configuration_administration",
]
ResourceScope = Literal["exact_table", "exact_index", "index_pattern"]

_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_ECS_SERVICE = "aws_ecs_service"
_ACCESS_CLASS_ORDER: tuple[AccessClass, ...] = (
    "entity_write",
    "entity_delete",
    "destructive_administration",
    "configuration_administration",
)


@dataclass(frozen=True, slots=True)
class _DynamoDbAction:
    name: str
    access_classes: tuple[AccessClass, ...]


@dataclass(frozen=True, slots=True)
class _DynamoDbResourceReference:
    resource_arn: str
    table_arn: str
    scope: ResourceScope


# TransactWriteItems is an API operation, not an IAM policy action. AWS
# authorizes its components through PutItem, UpdateItem, DeleteItem, and
# ConditionCheckItem.
_DYNAMODB_ACTIONS = (
    _DynamoDbAction("dynamodb:PutItem", ("entity_write",)),
    _DynamoDbAction("dynamodb:UpdateItem", ("entity_write",)),
    _DynamoDbAction(
        "dynamodb:BatchWriteItem",
        ("entity_write", "entity_delete"),
    ),
    _DynamoDbAction("dynamodb:PartiQLInsert", ("entity_write",)),
    _DynamoDbAction("dynamodb:PartiQLUpdate", ("entity_write",)),
    _DynamoDbAction("dynamodb:DeleteItem", ("entity_delete",)),
    _DynamoDbAction("dynamodb:PartiQLDelete", ("entity_delete",)),
    _DynamoDbAction("dynamodb:DeleteTable", ("destructive_administration",)),
    _DynamoDbAction(
        "dynamodb:DeleteTableReplica",
        ("destructive_administration",),
    ),
    _DynamoDbAction(
        "dynamodb:DeleteResourcePolicy",
        ("configuration_administration",),
    ),
    _DynamoDbAction(
        "dynamodb:DisableKinesisStreamingDestination",
        ("configuration_administration",),
    ),
    _DynamoDbAction(
        "dynamodb:EnableKinesisStreamingDestination",
        ("configuration_administration",),
    ),
    _DynamoDbAction(
        "dynamodb:PutResourcePolicy",
        ("configuration_administration",),
    ),
    _DynamoDbAction(
        "dynamodb:UpdateContinuousBackups",
        ("configuration_administration",),
    ),
    _DynamoDbAction(
        "dynamodb:UpdateContributorInsights",
        ("configuration_administration",),
    ),
    _DynamoDbAction(
        "dynamodb:UpdateKinesisStreamingDestination",
        ("configuration_administration",),
    ),
    _DynamoDbAction("dynamodb:UpdateTable", ("configuration_administration",)),
    _DynamoDbAction(
        "dynamodb:UpdateTableReplicaAutoScaling",
        ("configuration_administration",),
    ),
    _DynamoDbAction(
        "dynamodb:UpdateTimeToLive",
        ("configuration_administration",),
    ),
)
_ACTION_BY_NAME = {action.name: action for action in _DYNAMODB_ACTIONS}


class ModelEcsDynamoDbAccessPathsStage:
    name = "model_ecs_dynamodb_access_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        for task_definition in resources:
            if task_definition.resource_type != _ECS_TASK_DEFINITION:
                continue
            paths, index_relationships, uncertainties = _ecs_dynamodb_access(
                task_definition,
                context,
            )
            facts = aws_facts(task_definition)
            facts.set_ecs_dynamodb_access_paths(paths)
            facts.set_ecs_dynamodb_index_relationships(index_relationships)
            facts.extend_ecs_dynamodb_access_path_uncertainties(uncertainties)


class ProjectEcsDynamoDbAccessPathsOntoServicesStage:
    name = "project_ecs_dynamodb_access_paths_onto_services"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        for service in resources:
            if service.resource_type != _ECS_SERVICE:
                continue

            facts = aws_facts(service)
            paths: list[dict[str, Any]] = []
            index_relationships: list[dict[str, Any]] = []
            uncertainties = [
                f"{service.address}: task definition reference {reference} is "
                "unresolved for DynamoDB access-path projection"
                for reference in facts.unresolved_task_definition_references
            ]
            for task_definition_address in facts.resolved_task_definition_addresses:
                task_definition = context.index.ecs_task_definitions.get(task_definition_address)
                if task_definition is None:
                    uncertainties.append(
                        f"{service.address}: resolved task definition "
                        f"{task_definition_address} is unavailable for DynamoDB "
                        "access-path projection"
                    )
                    continue
                task_facts = aws_facts(task_definition)
                uncertainties.extend(task_facts.ecs_dynamodb_access_path_uncertainties)
                paths.extend(
                    _service_record(service, task_definition, path) for path in task_facts.ecs_dynamodb_access_paths
                )
                index_relationships.extend(
                    _service_record(service, task_definition, relationship)
                    for relationship in task_facts.ecs_dynamodb_index_relationships
                )

            facts.set_ecs_dynamodb_access_paths(paths)
            facts.set_ecs_dynamodb_index_relationships(index_relationships)
            facts.extend_ecs_dynamodb_access_path_uncertainties(dedupe(uncertainties))


def _service_record(
    service: NormalizedResource,
    task_definition: NormalizedResource,
    record: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        **record,
        "workload_address": service.address,
        "workload_type": service.resource_type,
        "task_definition_address": task_definition.address,
        "task_definition_arn": task_definition.arn,
        "internet_facing_load_balancers": (aws_facts(service).internet_facing_load_balancer_addresses),
    }


def _ecs_dynamodb_access(
    task_definition: NormalizedResource,
    context: AwsDecorationContext,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    task_role_reference = aws_facts(task_definition).task_role_arn
    if not task_role_reference:
        return [], [], []

    task_role = context.index.role_index.get(task_role_reference)
    if task_role is None:
        return (
            [],
            [],
            [f"{task_definition.address}: ECS task role {task_role_reference} is not modeled in the plan"],
        )

    role_facts = aws_facts(task_role)
    uncertainties = [
        f"{task_definition.address}: {task_role.address} has unresolved attached policy {policy_arn}"
        for policy_arn in role_facts.unresolved_attached_policy_arns
    ]
    tables, table_uncertainties = _target_tables(task_role, context)
    index_relationships, index_uncertainties = _index_relationships(
        task_definition,
        task_role,
        context,
        role_policy_complete=not role_facts.unresolved_attached_policy_arns,
    )
    uncertainties.extend(f"{task_definition.address}: {message}" for message in table_uncertainties)
    uncertainties.extend(f"{task_definition.address}: {message}" for message in index_uncertainties)

    paths: list[dict[str, Any]] = []
    for table in tables:
        table_arn = aws_facts(table).dynamodb_table_arn or table.arn
        if not table_arn:
            uncertainties.append(
                f"{task_definition.address}: DynamoDB table {table.address} has no resolved ARN for IAM scope matching"
            )
            continue
        statement_records = _matching_statement_records(
            task_role.policy_statements,
            table_arn,
        )
        if not statement_records:
            continue
        assessment = _assess_actions(statement_records)
        if assessment["conditional_actions"]:
            uncertainties.append(
                f"{task_definition.address}: {task_role.address} targeting "
                f"{table.address} has conditional identity-policy evidence for "
                "actions: " + ", ".join(assessment["conditional_actions"])
            )
        paths.append(
            _access_path_record(
                task_definition,
                table,
                task_role,
                statement_records,
                assessment,
                role_policy_complete=not role_facts.unresolved_attached_policy_arns,
            )
        )

    return paths, index_relationships, dedupe(uncertainties)


def _target_tables(
    role: NormalizedResource,
    context: AwsDecorationContext,
) -> tuple[list[NormalizedResource], list[str]]:
    tables: dict[str, NormalizedResource] = {}
    uncertainties: list[str] = []
    for statement in role.policy_statements:
        if not _has_mutation_action_pattern(statement):
            continue
        for resource in statement.resources:
            reference = _dynamodb_resource_reference(resource)
            if reference is not None:
                if reference.scope != "exact_table":
                    continue
                table = context.index.dynamodb_tables.get(reference.table_arn)
                if table is None:
                    uncertainties.append(
                        f"{role.address} DynamoDB policy targets "
                        f"{reference.table_arn}, which is not modeled in the plan"
                    )
                    continue
                tables[table.address] = table
                continue
            if _could_target_dynamodb(resource):
                uncertainties.append(
                    f"{role.address} DynamoDB policy resource {resource!r} does not identify an exact table"
                )
    return [tables[address] for address in sorted(tables)], dedupe(uncertainties)


def _index_relationships(
    task_definition: NormalizedResource,
    role: NormalizedResource,
    context: AwsDecorationContext,
    *,
    role_policy_complete: bool,
) -> tuple[list[dict[str, Any]], list[str]]:
    relationships: list[dict[str, Any]] = []
    uncertainties: list[str] = []
    for statement in role.policy_statements:
        if not _has_dynamodb_action_pattern(statement):
            continue
        for resource in statement.resources:
            reference = _dynamodb_resource_reference(resource)
            if reference is None or reference.scope == "exact_table":
                continue
            table = context.index.dynamodb_tables.get(reference.table_arn)
            if table is None:
                uncertainties.append(
                    f"{role.address} DynamoDB index policy targets "
                    f"{reference.resource_arn}, but parent table "
                    f"{reference.table_arn} is not modeled in the plan"
                )
                continue
            relationship = _index_relationship_record(
                task_definition,
                table,
                role,
                statement,
                reference,
                role_policy_complete=role_policy_complete,
            )
            if relationship not in relationships:
                relationships.append(relationship)
    return relationships, dedupe(uncertainties)


def _has_mutation_action_pattern(statement: IAMPolicyStatement) -> bool:
    return any(
        fnmatchcase(action.name.lower(), pattern.lower())
        for action in _DYNAMODB_ACTIONS
        for pattern in statement.actions
    )


def _has_dynamodb_action_pattern(statement: IAMPolicyStatement) -> bool:
    return any(pattern == "*" or pattern.lower().startswith("dynamodb:") for pattern in statement.actions)


def _dynamodb_resource_reference(
    value: object,
) -> _DynamoDbResourceReference | None:
    if not isinstance(value, str):
        return None
    parts = value.split(":", 5)
    if (
        len(parts) != 6
        or parts[0] != "arn"
        or parts[2] != "dynamodb"
        or not parts[3]
        or not parts[4]
        or any(_has_wildcard(part) for part in parts[:5])
    ):
        return None
    resource_parts = parts[5].split("/")
    if (
        len(resource_parts) == 2
        and resource_parts[0] == "table"
        and resource_parts[1]
        and not _has_wildcard(resource_parts[1])
    ):
        return _DynamoDbResourceReference(
            resource_arn=value,
            table_arn=value,
            scope="exact_table",
        )
    if (
        len(resource_parts) == 4
        and resource_parts[0] == "table"
        and resource_parts[1]
        and not _has_wildcard(resource_parts[1])
        and resource_parts[2] == "index"
        and resource_parts[3]
    ):
        table_arn = ":".join(parts[:5]) + f":table/{resource_parts[1]}"
        scope: ResourceScope = "index_pattern" if _has_wildcard(resource_parts[3]) else "exact_index"
        return _DynamoDbResourceReference(
            resource_arn=value,
            table_arn=table_arn,
            scope=scope,
        )
    return None


def _could_target_dynamodb(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return value == "*" or ":dynamodb:" in value.lower() or value.lower().startswith("aws_dynamodb_table.")


def _matching_statement_records(
    statements: tuple[IAMPolicyStatement, ...],
    table_arn: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for statement in statements:
        effect = statement.effect.strip().lower()
        if effect not in {"allow", "deny"}:
            continue

        matched_actions: list[str] = []
        matching_patterns: set[str] = set()
        for action in _DYNAMODB_ACTIONS:
            action_patterns = _matching_action_patterns(statement, action.name)
            if not action_patterns:
                continue
            matched_actions.append(action.name)
            matching_patterns.update(action_patterns)

        matching_resources = _matching_table_resources(
            statement,
            table_arn,
            effect=effect,
        )
        if not matched_actions or not matching_resources:
            continue
        records.append(
            {
                "effect": effect,
                "actions": list(statement.actions),
                "matched_actions": matched_actions,
                "matching_action_patterns": sorted(
                    matching_patterns,
                    key=str.lower,
                ),
                "resources": list(statement.resources),
                "matching_resources": sorted(matching_resources),
                "resource_scopes": _resource_scopes(
                    matching_resources,
                    table_arn,
                ),
                "access_classes": _access_classes(matched_actions),
                "conditions": [_condition_record(condition) for condition in statement.conditions],
                "conditional": bool(statement.conditions),
            }
        )
    return records


def _matching_action_patterns(
    statement: IAMPolicyStatement,
    action: str,
) -> set[str]:
    return {pattern for pattern in statement.actions if fnmatchcase(action.lower(), pattern.lower())}


def _matching_table_resources(
    statement: IAMPolicyStatement,
    table_arn: str,
    *,
    effect: str,
) -> set[str]:
    if effect == "allow":
        return {resource for resource in statement.resources if isinstance(resource, str) and resource == table_arn}
    return {
        resource for resource in statement.resources if isinstance(resource, str) and fnmatchcase(table_arn, resource)
    }


def _condition_record(condition: IAMPolicyCondition) -> dict[str, Any]:
    return {
        "operator": condition.operator,
        "key": condition.key,
        "values": list(condition.values),
    }


def _assess_actions(
    records: list[dict[str, Any]],
) -> dict[str, list[str]]:
    allowed: list[str] = []
    denied: list[str] = []
    unknown: list[str] = []
    conditional: list[str] = []
    for action in _DYNAMODB_ACTIONS:
        matching = [record for record in records if action.name in record["matched_actions"]]
        if not matching:
            continue
        unconditional_deny = any(record["effect"] == "deny" and not record["conditional"] for record in matching)
        conditional_deny = any(record["effect"] == "deny" and record["conditional"] for record in matching)
        unconditional_allow = any(record["effect"] == "allow" and not record["conditional"] for record in matching)
        conditional_allow = any(record["effect"] == "allow" and record["conditional"] for record in matching)
        if conditional_deny or conditional_allow:
            conditional.append(action.name)
        if unconditional_deny:
            denied.append(action.name)
        elif conditional_deny:
            unknown.append(action.name)
        elif unconditional_allow:
            allowed.append(action.name)
        elif conditional_allow:
            unknown.append(action.name)
    return {
        "allowed_actions": allowed,
        "denied_actions": denied,
        "unknown_actions": unknown,
        "conditional_actions": conditional,
    }


def _access_path_record(
    task_definition: NormalizedResource,
    table: NormalizedResource,
    task_role: NormalizedResource,
    statement_records: list[dict[str, Any]],
    assessment: dict[str, list[str]],
    *,
    role_policy_complete: bool,
) -> dict[str, Any]:
    allow_records = [record for record in statement_records if record["effect"] == "allow"]
    deny_records = [record for record in statement_records if record["effect"] == "deny"]
    modeled_access_state = _modeled_access_state(assessment)
    access_state = modeled_access_state if role_policy_complete else "unknown"
    table_arn = aws_facts(table).dynamodb_table_arn or table.arn
    return {
        "workload_address": task_definition.address,
        "workload_type": task_definition.resource_type,
        "dynamodb_table_address": table.address,
        "dynamodb_table_name": table.identifier or table.name,
        "dynamodb_table_arn": table_arn,
        "role_kind": "ecs_task_role",
        "credential_context": "workload_runtime",
        "role_address": task_role.address,
        "role_arn": task_role.arn or aws_facts(task_definition).task_role_arn,
        "role_policy_complete": role_policy_complete,
        "evaluation_basis": "modeled_identity_policy",
        "modeled_access_state": modeled_access_state,
        "access_state": access_state,
        "access_classes": _access_classes(assessment["allowed_actions"]),
        "denied_access_classes": _access_classes(assessment["denied_actions"]),
        "unknown_access_classes": _access_classes(assessment["unknown_actions"]),
        "matched_actions": assessment["allowed_actions"],
        "denied_actions": assessment["denied_actions"],
        "unknown_actions": assessment["unknown_actions"],
        "explicit_deny": bool(deny_records),
        "conditional_evaluation_required": bool(assessment["conditional_actions"]),
        "policy_action_patterns": _statement_values(
            allow_records,
            "matching_action_patterns",
        ),
        "policy_resources": _statement_values(
            allow_records,
            "matching_resources",
        ),
        "deny_action_patterns": _statement_values(
            deny_records,
            "matching_action_patterns",
        ),
        "deny_policy_resources": _statement_values(
            deny_records,
            "matching_resources",
        ),
        "resource_scopes": _statement_values(
            allow_records,
            "resource_scopes",
        ),
        "policy_statements": statement_records,
    }


def _index_relationship_record(
    task_definition: NormalizedResource,
    table: NormalizedResource,
    task_role: NormalizedResource,
    statement: IAMPolicyStatement,
    reference: _DynamoDbResourceReference,
    *,
    role_policy_complete: bool,
) -> dict[str, Any]:
    return {
        "workload_address": task_definition.address,
        "workload_type": task_definition.resource_type,
        "dynamodb_table_address": table.address,
        "dynamodb_table_name": table.identifier or table.name,
        "dynamodb_table_arn": reference.table_arn,
        "dynamodb_index_resource_arn": reference.resource_arn,
        "resource_scope": reference.scope,
        "role_kind": "ecs_task_role",
        "credential_context": "workload_runtime",
        "role_address": task_role.address,
        "role_arn": task_role.arn or aws_facts(task_definition).task_role_arn,
        "role_policy_complete": role_policy_complete,
        "evaluation_basis": "modeled_identity_policy_resource_relationship",
        "effect": statement.effect.strip().lower(),
        "policy_actions": list(statement.actions),
        "conditions": [_condition_record(condition) for condition in statement.conditions],
        "conditional": bool(statement.conditions),
    }


def _modeled_access_state(assessment: Mapping[str, list[str]]) -> str:
    if assessment["allowed_actions"]:
        return "allowed"
    if assessment["unknown_actions"]:
        return "unknown"
    if assessment["denied_actions"]:
        return "denied"
    return "not_modeled"


def _access_classes(actions: list[str]) -> list[str]:
    classes = {access_class for action in actions for access_class in _ACTION_BY_NAME[action].access_classes}
    return [access_class for access_class in _ACCESS_CLASS_ORDER if access_class in classes]


def _statement_values(
    statements: list[dict[str, Any]],
    key: str,
) -> list[str]:
    return sorted(
        {value for statement in statements for value in statement[key] if isinstance(value, str)},
        key=str.lower,
    )


def _resource_scopes(
    resources: set[str],
    table_arn: str,
) -> list[str]:
    scopes = {_resource_scope(resource, table_arn) for resource in resources}
    order = ("exact_table", "table_pattern", "all_resources")
    return [scope for scope in order if scope in scopes]


def _resource_scope(resource: str, table_arn: str) -> str:
    if resource == table_arn:
        return "exact_table"
    if resource == "*":
        return "all_resources"
    return "table_pattern"


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.coercion import dedupe

_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_ECS_SERVICE = "aws_ecs_service"
_KMS_KEY = "aws_kms_key"

_OPERATION_BY_KEY_USAGE: dict[str, str] = {
    "ENCRYPT_DECRYPT": "kms:Decrypt",
    "SIGN_VERIFY": "kms:Sign",
    "GENERATE_VERIFY_MAC": "kms:GenerateMac",
}
_AUTHORIZATION_BASIS_NAMES = {
    "direct_key_policy": "key_policy_direct",
    "iam_via_account_principal": "iam_via_key_policy",
    "kms_grant": "grant",
}


class ModelEcsKmsOperationPathsStage:
    name = "model_ecs_kms_operation_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        keys = tuple(resource for resource in resources if resource.resource_type == _KMS_KEY)
        for task_definition in resources:
            if task_definition.resource_type != _ECS_TASK_DEFINITION:
                continue
            paths, uncertainties = _ecs_kms_operation_paths(
                task_definition,
                keys,
                context,
            )
            facts = aws_facts(task_definition)
            facts.set_ecs_kms_operation_paths(paths)
            facts.extend_ecs_kms_operation_path_uncertainties(uncertainties)


class ProjectEcsKmsOperationPathsOntoServicesStage:
    name = "project_ecs_kms_operation_paths_onto_services"

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
            uncertainties = [
                f"{service.address}: task definition reference {reference} is unresolved for "
                "KMS operation-path projection"
                for reference in facts.unresolved_task_definition_references
            ]
            for task_definition_address in facts.resolved_task_definition_addresses:
                task_definition = context.index.ecs_task_definitions.get(task_definition_address)
                if task_definition is None:
                    uncertainties.append(
                        f"{service.address}: resolved task definition {task_definition_address} is unavailable "
                        "for KMS operation-path projection"
                    )
                    continue
                task_facts = aws_facts(task_definition)
                uncertainties.extend(task_facts.ecs_kms_operation_path_uncertainties)
                paths.extend(
                    _service_record(service, task_definition, path) for path in task_facts.ecs_kms_operation_paths
                )

            facts.set_ecs_kms_operation_paths(paths)
            facts.extend_ecs_kms_operation_path_uncertainties(dedupe(uncertainties))


def _ecs_kms_operation_paths(
    task_definition: NormalizedResource,
    keys: Sequence[NormalizedResource],
    context: AwsDecorationContext,
) -> tuple[list[dict[str, Any]], list[str]]:
    task_facts = aws_facts(task_definition)
    task_role_reference = task_facts.task_role_arn
    if not task_role_reference:
        return [], []

    task_role = context.index.role_index.get(task_role_reference)
    if task_role is None:
        return (
            [],
            [f"{task_definition.address}: ECS task role {task_role_reference} is not modeled in the plan"],
        )

    paths: list[dict[str, Any]] = []
    uncertainties: list[str] = []
    seen_key_addresses: set[str] = set()
    for key in keys:
        if key.address in seen_key_addresses:
            continue
        seen_key_addresses.add(key.address)
        key_facts = aws_facts(key)
        key_arn = key_facts.kms_key_arn or key.arn
        if not isinstance(key_arn, str) or not _is_exact_key_arn(key_arn):
            uncertainties.append(
                f"{task_definition.address}: KMS key {key.address} has no exact ARN for operation-path matching"
            )
            continue

        known_key_usage = _normalized_key_usage(key_facts.kms_key_usage)
        expected_operation = _OPERATION_BY_KEY_USAGE.get(known_key_usage or "")
        for uncertainty in key_facts.kms_operation_authorization_uncertainties:
            if _authorization_uncertainty_applies_to_role(
                uncertainty, task_role
            ) and _authorization_uncertainty_applies_to_operation(uncertainty, expected_operation):
                uncertainties.append(f"{task_definition.address}: {uncertainty}")

        for authorization in key_facts.kms_operation_authorizations:
            if not _authorization_matches_role(authorization, task_role):
                continue
            operation = authorization.get("operation")
            if not isinstance(operation, str):
                continue
            key_usage = _normalized_key_usage(key_facts.kms_key_usage or authorization.get("key_usage"))
            if key_usage is None:
                uncertainties.append(
                    f"{task_definition.address}: KMS key {key.address} key usage is unresolved for {operation}"
                )
                continue
            expected_operation = _OPERATION_BY_KEY_USAGE.get(key_usage)
            if expected_operation is None or operation != expected_operation:
                continue

            authorization_state = authorization.get("authorization_state")
            if authorization_state != "allowed":
                if authorization_state == "unknown":
                    uncertainties.append(
                        f"{task_definition.address}: {task_role.address} has unresolved "
                        f"{operation} authorization to KMS key {key.address}"
                    )
                continue

            paths.append(
                _operation_path_record(
                    task_definition,
                    task_role,
                    key,
                    authorization,
                    key_arn,
                )
            )

    paths.sort(
        key=lambda path: (
            str(path["key_address"]),
            str(path["operation"]),
            str(path["role_address"]),
        )
    )
    return paths, dedupe(uncertainties)


def _operation_path_record(
    task_definition: NormalizedResource,
    task_role: NormalizedResource,
    key: NormalizedResource,
    authorization: Mapping[str, Any],
    key_arn: str,
) -> dict[str, Any]:
    authorization_bases = _mapped_bases(authorization.get("authorization_bases"))
    candidate_bases = _mapped_bases(authorization.get("candidate_authorization_bases"))
    identity_statements = _mapping_records(authorization.get("identity_policy_statements"))
    key_statements = _mapping_records(authorization.get("key_policy_statements"))
    grants = _mapping_records(authorization.get("kms_grants"))
    allow_statements = [
        statement for statement in (*identity_statements, *key_statements) if statement.get("effect") == "allow"
    ]
    deny_statements = [
        statement for statement in (*identity_statements, *key_statements) if statement.get("effect") == "deny"
    ]
    return {
        "workload_address": task_definition.address,
        "workload_type": task_definition.resource_type,
        "task_definition_address": task_definition.address,
        "task_definition_arn": task_definition.arn,
        "key_address": key.address,
        "key_arn": key_arn,
        "key_id": aws_facts(key).kms_key_id or key.identifier,
        "key_usage": aws_facts(key).kms_key_usage,
        "key_spec": aws_facts(key).kms_key_spec,
        "operation": authorization.get("operation"),
        "role_kind": "ecs_task_role",
        "credential_context": "workload_runtime",
        "role_address": task_role.address,
        "role_arn": task_role.arn or aws_facts(task_definition).task_role_arn,
        "role_policy_complete": authorization.get("identity_policy_complete"),
        "authorization_state": authorization.get("authorization_state"),
        "authorization_basis": authorization_bases[0] if len(authorization_bases) == 1 else None,
        "authorization_bases": authorization_bases,
        "candidate_authorization_bases": candidate_bases,
        "evaluation_basis": "modeled_kms_authorization",
        "same_account": authorization.get("same_account"),
        "explicit_deny": authorization.get("explicit_deny"),
        "conditional_evaluation_required": authorization.get("conditional_evaluation_required"),
        "constraint_state": authorization.get("constraint_state"),
        "policy_action_patterns": _statement_values(
            allow_statements,
            "matching_action_patterns",
        ),
        "policy_resources": _statement_values(
            allow_statements,
            "matching_resources",
        ),
        "deny_action_patterns": _statement_values(
            deny_statements,
            "matching_action_patterns",
        ),
        "deny_policy_resources": _statement_values(
            deny_statements,
            "matching_resources",
        ),
        "key_policy_complete": authorization.get("key_policy_complete"),
        "key_policy_source_addresses": list(authorization.get("key_policy_source_addresses", [])),
        "identity_policy_source_addresses": list(authorization.get("identity_policy_source_addresses", [])),
        "key_policy_uncertainties": list(authorization.get("key_policy_uncertainties", [])),
        "identity_policy_uncertainties": list(authorization.get("identity_policy_uncertainties", [])),
        "identity_policy_statements": identity_statements,
        "key_policy_statements": key_statements,
        "kms_grants": grants,
        "grant_constraints": [
            grant.get("constraints") for grant in grants if isinstance(grant.get("constraints"), Mapping)
        ],
        "authorization_record": dict(authorization),
    }


def _service_record(
    service: NormalizedResource,
    task_definition: NormalizedResource,
    path: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        **path,
        "workload_address": service.address,
        "workload_type": service.resource_type,
        "task_definition_address": task_definition.address,
        "task_definition_arn": task_definition.arn,
        "internet_facing_load_balancers": aws_facts(service).internet_facing_load_balancer_addresses,
    }


def _authorization_matches_role(
    authorization: Mapping[str, Any],
    role: NormalizedResource,
) -> bool:
    principal_address = authorization.get("principal_address")
    principal_arn = authorization.get("principal_arn")
    return bool(principal_address == role.address or (role.arn is not None and principal_arn == role.arn))


def _authorization_uncertainty_applies_to_operation(
    uncertainty: str,
    expected_operation: str | None,
) -> bool:
    if expected_operation is None:
        return True
    mentioned_operations = set(re.findall(r"\bkms:[A-Za-z0-9]+\b", uncertainty))
    return not mentioned_operations or expected_operation in mentioned_operations


def _authorization_uncertainty_applies_to_role(
    uncertainty: str,
    task_role: NormalizedResource,
) -> bool:
    return (
        task_role.address in uncertainty
        or "effective KMS key policy" in uncertainty
        or "authorization evidence is unresolved" in uncertainty
        or "unresolved KMS grant operations" in uncertainty
    )


def _mapping_records(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _mapped_bases(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_AUTHORIZATION_BASIS_NAMES.get(str(item), str(item)) for item in value if isinstance(item, str)]


def _statement_values(
    statements: Sequence[Mapping[str, Any]],
    key: str,
) -> list[str]:
    return sorted(
        {value for statement in statements for value in statement.get(key, []) if isinstance(value, str)},
        key=str.casefold,
    )


def _normalized_key_usage(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().upper()
    return normalized or None


def _is_exact_key_arn(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("arn:"):
        return False
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[2] == "kms"
        and parts[3]
        and parts[4].isdigit()
        and len(parts[4]) == 12
        and parts[5].startswith("key/")
        and len(parts[5]) > len("key/")
        and "*" not in value
        and "?" not in value
    )

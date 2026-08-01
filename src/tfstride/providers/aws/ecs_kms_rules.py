from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource, SeverityReasoning
from tfstride.providers.aws.ecs_path_rule_helpers import (
    internet_boundary_id,
    path_string_values,
    public_service_network_path,
    resolved_public_load_balancers,
)
from tfstride.providers.aws.kms_evidence import AwsEcsKmsOperationPath
from tfstride.providers.aws.resource_facts import aws_facts

_AWS_ECS_SERVICE = "aws_ecs_service"
_AWS_KMS_KEY = "aws_kms_key"
_DECRYPT_OPERATION = "kms:Decrypt"
_SIGN_OPERATION = "kms:Sign"
_MAC_GENERATION_OPERATION = "kms:GenerateMac"
_SIGNING_OPERATIONS = frozenset({_SIGN_OPERATION, _MAC_GENERATION_OPERATION})
_OPERATION_KEY_USAGE = {
    _DECRYPT_OPERATION: "ENCRYPT_DECRYPT",
    _SIGN_OPERATION: "SIGN_VERIFY",
    _MAC_GENERATION_OPERATION: "GENERATE_VERIFY_MAC",
}
_AUTHORIZATION_BASES = frozenset({"key_policy_direct", "iam_via_key_policy", "grant"})


class AwsEcsKmsOperationRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_service_decrypt_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_operation_access(
            context,
            rule_id,
            frozenset({_DECRYPT_OPERATION}),
            disclosure=True,
        )

    def detect_public_service_signing_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_operation_access(
            context,
            rule_id,
            _SIGNING_OPERATIONS,
            disclosure=False,
        )

    def _detect_public_operation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
        operations: frozenset[str],
        *,
        disclosure: bool,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for service in context.inventory.by_type(_AWS_ECS_SERVICE):
            paths = [
                path
                for path in aws_facts(service).ecs_kms_operation_paths
                if _is_deterministic_operation_path(
                    path,
                    service.address,
                    context,
                    operations,
                )
            ]
            if not paths:
                continue

            load_balancer_addresses = resolved_public_load_balancers(paths, context)
            if not load_balancer_addresses:
                continue

            task_definition_addresses = path_string_values(paths, "task_definition_address")
            role_addresses = path_string_values(paths, "role_address")
            key_addresses = path_string_values(paths, "key_address")
            authorization_bases = _authorization_bases(paths)
            matched_operations = _path_operations(paths)
            severity_reasoning = _operation_severity(
                disclosure=disclosure,
                key_count=len(key_addresses),
            )
            affected_resources = [
                *load_balancer_addresses,
                service.address,
                *task_definition_addresses,
                *role_addresses,
                *key_addresses,
            ]
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=list(dict.fromkeys(affected_resources)),
                    trust_boundary_id=internet_boundary_id(load_balancer_addresses, context),
                    rationale=_rationale(
                        service,
                        matched_operations,
                        len(key_addresses),
                        authorization_bases,
                        disclosure=disclosure,
                    ),
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
                        evidence_item("kms_operation_paths", _operation_path_evidence(paths)),
                        evidence_item(
                            "assessment_scope",
                            _assessment_scope(matched_operations),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_deterministic_operation_path(
    path: AwsEcsKmsOperationPath,
    service_address: str,
    context: RuleEvaluationContext,
    operations: frozenset[str],
) -> bool:
    key_address = path.get("key_address")
    key = context.inventory.get_by_address(key_address) if isinstance(key_address, str) else None
    if key is None or key.resource_type != _AWS_KMS_KEY:
        return False

    operation = path.get("operation")
    if not isinstance(operation, str) or operation not in operations:
        return False

    key_facts = aws_facts(key)
    key_arn = key_facts.kms_key_arn or key.arn
    expected_usage = _OPERATION_KEY_USAGE[operation]
    authorization_bases = path.get("authorization_bases")
    return (
        path.get("workload_type") == _AWS_ECS_SERVICE
        and path.get("workload_address") == service_address
        and all(
            isinstance(path.get(key_name), str) and bool(path.get(key_name))
            for key_name in (
                "task_definition_address",
                "role_address",
                "key_address",
                "key_arn",
                "operation",
            )
        )
        and path.get("operation") == operation
        and path.get("key_arn") == key_arn
        and _is_exact_kms_key_arn(key_arn)
        and path.get("key_usage") == expected_usage
        and key_facts.kms_key_usage == expected_usage
        and path.get("role_kind") == "ecs_task_role"
        and path.get("credential_context") == "workload_runtime"
        and path.get("authorization_state") == "allowed"
        and path.get("role_policy_complete") is True
        and path.get("explicit_deny") is False
        and path.get("conditional_evaluation_required") is False
        and isinstance(authorization_bases, list)
        and bool(authorization_bases)
        and all(isinstance(value, str) and value in _AUTHORIZATION_BASES for value in authorization_bases)
    )


def _is_exact_kms_key_arn(value: object) -> bool:
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


def _authorization_bases(paths: Sequence[AwsEcsKmsOperationPath]) -> list[str]:
    return sorted({value for path in paths for value in _string_values(path.get("authorization_bases"))})


def _operation_severity(*, disclosure: bool, key_count: int) -> SeverityReasoning:
    return build_severity_reasoning(
        internet_exposure=True,
        privilege_breadth=1,
        data_sensitivity=2 if disclosure else 1,
        lateral_movement=1,
        blast_radius=2 if key_count > 1 else 1,
    )


def _rationale(
    service: NormalizedResource,
    operations: list[str],
    key_count: int,
    authorization_bases: list[str],
    *,
    disclosure: bool,
) -> str:
    basis = ", ".join(authorization_bases)
    operation_text = _operation_text(operations)
    if disclosure:
        capability = "could attempt KMS decrypt operations, creating information-disclosure potential"
        qualification = (
            "This establishes cryptographic-operation authority, not proof that the workload possesses useful "
            "ciphertext or can disclose plaintext."
        )
    elif operations == [_SIGN_OPERATION]:
        capability = "could generate KMS signatures, creating spoofing potential"
        qualification = (
            "This establishes cryptographic-operation authority, not proof that the workload can produce a valid "
            "application-level signature accepted by a relying system."
        )
    elif operations == [_MAC_GENERATION_OPERATION]:
        capability = "could generate KMS message authentication codes, creating spoofing potential"
        qualification = (
            "This establishes cryptographic-operation authority, not proof that the workload can produce a valid "
            "message authentication code accepted by a relying system."
        )
    else:
        capability = "could generate KMS signatures or message authentication codes, creating spoofing potential"
        qualification = (
            "This establishes cryptographic-operation authority, not proof that the workload can produce a valid "
            "signature or message authentication code accepted by a relying system."
        )
    return (
        f"{service.display_name} is reachable through an internet-facing load balancer and its ECS task role has "
        f"deterministic {operation_text} authority on {key_count} exact modeled KMS key(s) through {basis}. "
        f"A compromise of the public workload {capability}. {qualification} The KMS key itself is not public."
    )


def _assessment_scope(operations: list[str]) -> list[str]:
    return [
        (
            f"establishes=deterministic {_operation_text(operations)} authority for an ECS task role "
            "on exact modeled KMS keys"
        ),
        (
            "does_not_establish=useful ciphertext, plaintext disclosure, accepted application signatures or MACs, "
            "or runtime success outside the modeled AWS policy and grant evidence"
        ),
    ]


def _path_operations(paths: Sequence[AwsEcsKmsOperationPath]) -> list[str]:
    return [
        operation
        for operation in (
            _DECRYPT_OPERATION,
            _SIGN_OPERATION,
            _MAC_GENERATION_OPERATION,
        )
        if any(path.get("operation") == operation for path in paths)
    ]


def _operation_text(operations: list[str]) -> str:
    if len(operations) == 1:
        return operations[0]
    return " and ".join(operations)


def _task_role_evidence(paths: Sequence[AwsEcsKmsOperationPath]) -> list[str]:
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


def _operation_path_evidence(paths: Sequence[AwsEcsKmsOperationPath]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"key_address={path['key_address']}",
                    f"key_arn={path['key_arn']}",
                    f"key_id={path.get('key_id') or 'unknown'}",
                    f"key_usage={path.get('key_usage') or 'unknown'}",
                    f"key_spec={path.get('key_spec') or 'unknown'}",
                    f"operation={path['operation']}",
                    f"task_definition={path['task_definition_address']}",
                    f"task_role={path['role_address']}",
                    f"authorization_state={path['authorization_state']}",
                    f"authorization_bases={','.join(_string_values(path.get('authorization_bases')))}",
                    f"candidate_authorization_bases={','.join(_string_values(path.get('candidate_authorization_bases')))}",
                    f"policy_action_patterns={','.join(_string_values(path.get('policy_action_patterns')))}",
                    f"policy_resources={','.join(_string_values(path.get('policy_resources')))}",
                    f"deny_action_patterns={','.join(_string_values(path.get('deny_action_patterns')) or ['none'])}",
                    f"key_policy_sources={','.join(_string_values(path.get('key_policy_source_addresses')) or ['none'])}",
                    f"identity_policy_sources={','.join(_string_values(path.get('identity_policy_source_addresses')) or ['none'])}",
                    f"grant_sources={','.join(_grant_sources(path))}",
                    f"grant_constraints={';'.join(_structured_values(path.get('grant_constraints')) or ['none'])}",
                    f"constraint_state={path.get('constraint_state') or 'not_configured'}",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _grant_sources(path: AwsEcsKmsOperationPath) -> list[str]:
    sources: set[str] = set()
    for grant in path["kms_grants"]:
        source = grant["source"]
        if source:
            sources.add(source)
    return sorted(sources) or ["none"]


def _structured_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [json.dumps(item, sort_keys=True) for item in value if isinstance(item, Mapping)]


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]

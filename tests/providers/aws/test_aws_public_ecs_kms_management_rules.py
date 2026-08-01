from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_ecs_kms_management_paths import _with_lifecycle
from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _EXECUTION_ROLE_ARN,
    _KEY_ARNS,
    _ROOT_ARN,
    _TASK_ROLE_ARN,
    _key,
    _policy,
    _role,
    _statement,
    _task_definition,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _public_edge,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _service as _public_service,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_DISRUPTION_RULE_ID = "aws-public-ecs-kms-key-disruption"
_DELEGATION_RULE_ID = "aws-public-ecs-kms-authorization-delegation"
_RULE_IDS = frozenset({_DISRUPTION_RULE_ID, _DELEGATION_RULE_ID})
_MANAGEMENT_OPERATIONS = (
    "kms:CreateGrant",
    "kms:PutKeyPolicy",
    "kms:DisableKey",
    "kms:ScheduleKeyDeletion",
)


def _evaluate(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=_RULE_IDS),
    )
    return inventory, boundaries, findings


def _public_management_resources(*, internal: bool = False) -> list[TerraformResource]:
    key = _with_lifecycle(
        _key(
            "data",
            "ENCRYPT_DECRYPT",
            _policy(
                _statement(
                    "Allow",
                    list(_MANAGEMENT_OPERATIONS),
                    "*",
                    principal=_TASK_ROLE_ARN,
                ),
                _statement(
                    "Allow",
                    list(_MANAGEMENT_OPERATIONS),
                    "*",
                    principal=_ROOT_ARN,
                ),
            ),
        ),
        origin="AWS_KMS",
    )
    return [
        *_public_edge(internal=internal),
        key,
        _role(
            "orders_task",
            _TASK_ROLE_ARN,
            [
                _statement(
                    "Allow",
                    list(_MANAGEMENT_OPERATIONS),
                    _KEY_ARNS["data"],
                    principal=_TASK_ROLE_ARN,
                )
            ],
        ),
        _task_definition(),
        _public_service(),
    ]


class AwsPublicEcsKmsManagementRuleTests(unittest.TestCase):
    def test_rule_ids_are_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}

        self.assertTrue(_RULE_IDS <= registered)

    def test_public_service_emits_distinct_disruption_and_delegation_findings(self) -> None:
        _, _, findings = _evaluate(_public_management_resources())

        self.assertEqual({finding.rule_id for finding in findings}, _RULE_IDS)
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        disruption = findings_by_rule[_DISRUPTION_RULE_ID]
        delegation = findings_by_rule[_DELEGATION_RULE_ID]

        self.assertEqual(disruption.category, StrideCategory.DENIAL_OF_SERVICE)
        self.assertEqual(delegation.category, StrideCategory.ELEVATION_OF_PRIVILEGE)
        self.assertEqual(disruption.severity.value, "high")
        self.assertEqual(delegation.severity.value, "high")
        self.assertEqual(
            disruption.affected_resources,
            [
                "aws_lb.public",
                "aws_ecs_service.orders",
                "aws_ecs_task_definition.orders",
                "aws_iam_role.orders_task",
                "aws_kms_key.data",
            ],
        )
        self.assertEqual(delegation.affected_resources, disruption.affected_resources)

        disruption_evidence = {item.key: item.values for item in disruption.evidence}
        delegation_evidence = {item.key: item.values for item in delegation.evidence}
        self.assertEqual(
            disruption_evidence["network_path"],
            [
                "internet reaches aws_lb.public",
                "aws_lb.public fronts aws_ecs_service.orders",
            ],
        )
        self.assertEqual(
            disruption_evidence["task_definitions"],
            ["address=aws_ecs_task_definition.orders"],
        )
        self.assertIn("role_kind=ecs_task_role", disruption_evidence["task_roles"][0])
        self.assertEqual(len(disruption_evidence["kms_management_paths"]), 2)
        self.assertTrue(
            all("management_effect=disruption" in value for value in disruption_evidence["kms_management_paths"])
        )
        self.assertTrue(
            all("authorization_state=allowed" in value for value in disruption_evidence["kms_management_paths"])
        )
        self.assertTrue(
            all("management_effect=delegation" in value for value in delegation_evidence["kms_management_paths"])
        )
        self.assertTrue(
            any("operation=kms:DisableKey" in value for value in disruption_evidence["kms_management_paths"])
        )
        self.assertTrue(
            any("operation=kms:ScheduleKeyDeletion" in value for value in disruption_evidence["kms_management_paths"])
        )
        self.assertTrue(
            any("operation=kms:CreateGrant" in value for value in delegation_evidence["kms_management_paths"])
        )
        self.assertTrue(
            any("operation=kms:PutKeyPolicy" in value for value in delegation_evidence["kms_management_paths"])
        )
        self.assertIn("key-disruption authority", disruption.rationale)
        self.assertIn("authorization-delegation authority", delegation.rationale)
        self.assertIn("exact modeled KMS key", disruption.rationale)
        self.assertIn("key itself is not public", delegation.rationale)
        self.assertIn("key disruption effect", disruption_evidence["assessment_scope"][0])
        self.assertIn("authorization delegation effect", delegation_evidence["assessment_scope"][0])

    def test_incidental_conditional_evidence_does_not_suppress_disruption(self) -> None:
        conditional_statement = _statement(
            "Allow",
            "kms:DeleteImportedKeyMaterial",
            "*",
            principal=_TASK_ROLE_ARN,
        )
        conditional_statement["Condition"] = {
            "StringEquals": {
                "aws:PrincipalTag/environment": "production",
            }
        }
        key = _with_lifecycle(
            _key(
                "data",
                "ENCRYPT_DECRYPT",
                _policy(
                    _statement(
                        "Allow",
                        "kms:DeleteImportedKeyMaterial",
                        "*",
                        principal=_TASK_ROLE_ARN,
                    ),
                    conditional_statement,
                ),
            ),
            origin="EXTERNAL",
        )
        _, _, findings = _evaluate(
            [
                *_public_edge(),
                key,
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "kms:DeleteImportedKeyMaterial",
                            _KEY_ARNS["data"],
                            principal=_TASK_ROLE_ARN,
                        )
                    ],
                ),
                _task_definition(),
                _public_service(),
            ]
        )

        self.assertEqual({finding.rule_id for finding in findings}, {_DISRUPTION_RULE_ID})
        evidence = {item.key: item.values for item in findings[0].evidence}
        management_path = evidence["kms_management_paths"][0]
        self.assertIn("conditional_policy_evidence_present=true", management_path)
        self.assertIn("authorization_requires_condition_evaluation=false", management_path)

    def test_private_service_remains_quiet(self) -> None:
        _, _, findings = _evaluate(_public_management_resources(internal=True))

        self.assertEqual(findings, [])

    def test_execution_role_management_authority_does_not_form_public_task_path(self) -> None:
        key = _with_lifecycle(
            _key(
                "data",
                "ENCRYPT_DECRYPT",
                _policy(
                    _statement(
                        "Allow",
                        list(_MANAGEMENT_OPERATIONS),
                        "*",
                        principal=_ROOT_ARN,
                    )
                ),
            ),
            origin="AWS_KMS",
        )
        _, _, findings = _evaluate(
            [
                *_public_edge(),
                key,
                _role("orders_task", _TASK_ROLE_ARN, []),
                _role(
                    "orders_execution",
                    _EXECUTION_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            list(_MANAGEMENT_OPERATIONS),
                            _KEY_ARNS["data"],
                            principal=_EXECUTION_ROLE_ARN,
                        )
                    ],
                ),
                _task_definition(),
                _public_service(),
            ]
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()

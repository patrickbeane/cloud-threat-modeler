from __future__ import annotations

import unittest

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
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_DECRYPT_RULE_ID = "aws-public-ecs-kms-decrypt-access"
_SIGNING_RULE_ID = "aws-public-ecs-kms-signing-access"
_RULE_IDS = frozenset({_DECRYPT_RULE_ID, _SIGNING_RULE_ID})


def _evaluate(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=_RULE_IDS),
    )
    return inventory, boundaries, findings


def _public_kms_resources(*, internal: bool = False) -> list[TerraformResource]:
    return [
        *_public_edge(internal=internal),
        _key(
            "data",
            "ENCRYPT_DECRYPT",
            _policy(
                _statement(
                    "Allow",
                    "kms:Decrypt",
                    "*",
                    principal=_TASK_ROLE_ARN,
                )
            ),
        ),
        _key(
            "signing",
            "SIGN_VERIFY",
            _policy(
                _statement(
                    "Allow",
                    "kms:*",
                    "*",
                    principal=_ROOT_ARN,
                )
            ),
        ),
        _role(
            "orders_task",
            _TASK_ROLE_ARN,
            [
                _statement(
                    "Allow",
                    "kms:Decrypt",
                    _KEY_ARNS["data"],
                    principal=_TASK_ROLE_ARN,
                ),
                _statement(
                    "Allow",
                    "kms:Sign",
                    _KEY_ARNS["signing"],
                    principal=_TASK_ROLE_ARN,
                ),
            ],
        ),
        _task_definition(),
        _public_service(),
    ]


class AwsPublicEcsKmsRuleTests(unittest.TestCase):
    def test_rule_ids_are_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}

        self.assertTrue(_RULE_IDS <= registered)

    def test_public_service_emits_distinct_decrypt_and_signing_findings(self) -> None:
        _, _, findings = _evaluate(_public_kms_resources())

        self.assertEqual(
            {finding.rule_id for finding in findings},
            _RULE_IDS,
        )
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        decrypt_finding = findings_by_rule[_DECRYPT_RULE_ID]
        signing_finding = findings_by_rule[_SIGNING_RULE_ID]

        self.assertEqual(decrypt_finding.severity.value, "high")
        self.assertEqual(signing_finding.severity.value, "high")
        self.assertEqual(
            decrypt_finding.affected_resources,
            [
                "aws_lb.public",
                "aws_ecs_service.orders",
                "aws_ecs_task_definition.orders",
                "aws_iam_role.orders_task",
                "aws_kms_key.data",
            ],
        )
        self.assertEqual(
            signing_finding.affected_resources,
            [
                "aws_lb.public",
                "aws_ecs_service.orders",
                "aws_ecs_task_definition.orders",
                "aws_iam_role.orders_task",
                "aws_kms_key.signing",
            ],
        )
        for finding in (decrypt_finding, signing_finding):
            self.assertEqual(
                finding.trust_boundary_id,
                "internet-to-service:internet->aws_lb.public",
            )
            evidence = {item.key: item.values for item in finding.evidence}
            self.assertEqual(
                evidence["network_path"],
                [
                    "internet reaches aws_lb.public",
                    "aws_lb.public fronts aws_ecs_service.orders",
                ],
            )
            self.assertEqual(
                evidence["task_definitions"],
                ["address=aws_ecs_task_definition.orders"],
            )
            self.assertIn("address=aws_iam_role.orders_task", evidence["task_roles"][0])
            self.assertIn("role_kind=ecs_task_role", evidence["task_roles"][0])
            self.assertIn("key_address=aws_kms_key.", evidence["kms_operation_paths"][0])
            self.assertIn("authorization_state=allowed", evidence["kms_operation_paths"][0])
            self.assertIn("operation_evaluation=deterministic_allowed", evidence["kms_operation_paths"][0])
            self.assertIn("The KMS key itself is not public", finding.rationale)

        decrypt_evidence = {item.key: item.values for item in decrypt_finding.evidence}
        self.assertIn("operation=kms:Decrypt", decrypt_evidence["kms_operation_paths"][0])
        self.assertIn("authorization_bases=key_policy_direct", decrypt_evidence["kms_operation_paths"][0])
        self.assertIn("information-disclosure potential", decrypt_finding.rationale)
        self.assertIn("useful ciphertext or can disclose plaintext", decrypt_finding.rationale)

        signing_evidence = {item.key: item.values for item in signing_finding.evidence}
        self.assertIn("operation=kms:Sign", signing_evidence["kms_operation_paths"][0])
        self.assertIn("authorization_bases=iam_via_key_policy", signing_evidence["kms_operation_paths"][0])
        self.assertIn("spoofing potential", signing_finding.rationale)
        self.assertIn("valid application-level signature", signing_finding.rationale)

    def test_private_service_remains_quiet(self) -> None:
        _, _, findings = _evaluate(_public_kms_resources(internal=True))

        self.assertEqual(findings, [])

    def test_denied_conditional_and_execution_role_operations_remain_quiet(self) -> None:
        conditional_allow = _statement(
            "Allow",
            "kms:Decrypt",
            "*",
            principal=_TASK_ROLE_ARN,
        )
        conditional_allow["Condition"] = {
            "StringEquals": {
                "kms:EncryptionContext:service": "orders",
            }
        }
        resources = [
            *_public_edge(),
            _key(
                "data",
                "ENCRYPT_DECRYPT",
                _policy(
                    conditional_allow,
                    _statement(
                        "Deny",
                        "kms:Sign",
                        "*",
                        principal=_TASK_ROLE_ARN,
                    ),
                ),
            ),
            _key(
                "signing",
                "SIGN_VERIFY",
                _policy(
                    _statement(
                        "Allow",
                        "kms:Sign",
                        "*",
                        principal=_EXECUTION_ROLE_ARN,
                    )
                ),
            ),
            _role(
                "orders_task",
                _TASK_ROLE_ARN,
                [
                    _statement(
                        "Allow",
                        "kms:Decrypt",
                        _KEY_ARNS["data"],
                        principal=_TASK_ROLE_ARN,
                    ),
                    _statement(
                        "Allow",
                        "kms:Sign",
                        _KEY_ARNS["signing"],
                        principal=_TASK_ROLE_ARN,
                    ),
                ],
            ),
            _role(
                "orders_execution",
                _EXECUTION_ROLE_ARN,
                [
                    _statement(
                        "Allow",
                        "kms:Sign",
                        _KEY_ARNS["signing"],
                        principal=_EXECUTION_ROLE_ARN,
                    )
                ],
            ),
            _task_definition(),
            _public_service(),
        ]

        _, _, findings = _evaluate(resources)

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()

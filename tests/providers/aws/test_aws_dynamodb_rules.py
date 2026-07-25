from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_CMK_RULE = "aws-dynamodb-customer-managed-kms-key-missing"
_PITR_RULE = "aws-dynamodb-point-in-time-recovery-disabled-or-unknown"
_DELETION_PROTECTION_RULE = "aws-dynamodb-deletion-protection-disabled-or-unknown"
_DYNAMODB_RULE_IDS = (_CMK_RULE, _PITR_RULE, _DELETION_PROTECTION_RULE)
_TABLE_ARN = "arn:aws:dynamodb:us-east-1:111122223333:table/orders"
_KMS_KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/dynamodb"
_MISSING = object()


def _table(
    *,
    name: str = "orders",
    server_side_encryption: object = _MISSING,
    point_in_time_recovery: object = _MISSING,
    deletion_protection_enabled: object = _MISSING,
    replica: object = _MISSING,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": name,
        "name": name,
        "arn": _TABLE_ARN.replace("/orders", f"/{name}"),
    }
    if server_side_encryption is not _MISSING:
        values["server_side_encryption"] = server_side_encryption
    if point_in_time_recovery is not _MISSING:
        values["point_in_time_recovery"] = point_in_time_recovery
    if deletion_protection_enabled is not _MISSING:
        values["deletion_protection_enabled"] = deletion_protection_enabled
    if replica is not _MISSING:
        values["replica"] = replica
    return TerraformResource(
        address=f"aws_dynamodb_table.{name}",
        mode="managed",
        resource_type="aws_dynamodb_table",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _safe_table(*, name: str = "orders", **overrides: object) -> TerraformResource:
    values: dict[str, object] = {
        "name": name,
        "server_side_encryption": [
            {
                "enabled": True,
                "kms_key_arn": _KMS_KEY_ARN,
            }
        ],
        "point_in_time_recovery": [
            {
                "enabled": True,
                "recovery_period_in_days": 35,
            }
        ],
        "deletion_protection_enabled": True,
    }
    values.update(overrides)
    return _table(**values)


def _findings(resources: list[TerraformResource], *rule_ids: str):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or _DYNAMODB_RULE_IDS)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsDynamoDbRuleTests(unittest.TestCase):
    def test_dynamodb_rules_are_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}
        self.assertTrue(set(_DYNAMODB_RULE_IDS).issubset(registered))

    def test_provider_managed_encryption_and_disabled_recovery_controls_are_detected(
        self,
    ) -> None:
        findings = _findings(
            [
                _table(
                    server_side_encryption=[{"enabled": False}],
                    point_in_time_recovery=[{"enabled": False}],
                    deletion_protection_enabled=False,
                )
            ]
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            list(_DYNAMODB_RULE_IDS),
        )
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual(findings_by_rule[_CMK_RULE].severity.value, "low")
        self.assertEqual(findings_by_rule[_PITR_RULE].severity.value, "medium")
        self.assertEqual(
            findings_by_rule[_DELETION_PROTECTION_RULE].severity.value,
            "medium",
        )

        cmk_finding = findings_by_rule[_CMK_RULE]
        self.assertNotIn("unencrypted", cmk_finding.rationale.lower())
        self.assertEqual(
            _evidence_by_key(cmk_finding)["encryption_ownership"],
            [
                "encryption_ownership_state=aws_owned",
                "encryption_configuration_state=disabled",
                "kms_key_arn=unset",
                "storage_encrypted=true",
                "finding_scope=customer-managed key ownership and control posture",
                "DynamoDB remains encrypted at rest when an AWS-owned or AWS-managed key is used",
            ],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule[_PITR_RULE])["recovery_posture"],
            [
                "point_in_time_recovery_state=disabled",
                "recovery_period_in_days=unset",
            ],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule[_DELETION_PROTECTION_RULE])["deletion_protection"],
            ["deletion_protection_state=disabled"],
        )

    def test_hardened_table_is_quiet(self) -> None:
        self.assertEqual(_findings([_safe_table()]), [])

    def test_omitted_controls_use_effective_provider_posture_without_overclaiming_encryption(
        self,
    ) -> None:
        findings = _findings([_table()])

        self.assertEqual(
            [finding.rule_id for finding in findings],
            list(_DYNAMODB_RULE_IDS),
        )
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        self.assertIn("uses an AWS-owned key", findings_by_rule[_CMK_RULE].rationale)
        self.assertNotIn("unencrypted", findings_by_rule[_CMK_RULE].rationale.lower())
        self.assertEqual(
            _evidence_by_key(findings_by_rule[_PITR_RULE])["recovery_posture"],
            [
                "point_in_time_recovery_state=not_configured",
                "recovery_period_in_days=unset",
            ],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule[_DELETION_PROTECTION_RULE])["deletion_protection"],
            ["deletion_protection_state=not_configured"],
        )

    def test_aws_managed_kms_key_is_reported_as_ownership_posture(self) -> None:
        findings = _findings(
            [
                _safe_table(
                    server_side_encryption=[{"enabled": True}],
                )
            ],
            _CMK_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_CMK_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertIn(
            "encryption_ownership_state=aws_managed_kms",
            evidence["encryption_ownership"],
        )
        self.assertIn("AWS-managed DynamoDB KMS key", findings[0].rationale)

    def test_unknown_posture_emits_lower_severity_without_disabled_claims(self) -> None:
        findings = _findings(
            [
                _table(
                    unknown_values={
                        "server_side_encryption": True,
                        "point_in_time_recovery": True,
                        "deletion_protection_enabled": True,
                    }
                )
            ]
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            list(_DYNAMODB_RULE_IDS),
        )
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        for finding in findings:
            self.assertEqual(finding.severity.value, "low")
            self.assertNotIn("explicitly disables", finding.rationale)

        self.assertEqual(
            _evidence_by_key(findings_by_rule[_CMK_RULE])["posture_uncertainty"],
            ["server_side_encryption is unknown after planning"],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule[_PITR_RULE])["posture_uncertainty"],
            ["point_in_time_recovery is unknown after planning"],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule[_DELETION_PROTECTION_RULE])["posture_uncertainty"],
            ["deletion_protection_enabled is unknown after planning"],
        )

    def test_replica_posture_does_not_emit_replica_specific_findings(self) -> None:
        findings = _findings(
            [
                _safe_table(
                    replica=[
                        {
                            "region_name": "us-west-2",
                            "point_in_time_recovery": False,
                            "deletion_protection_enabled": False,
                        }
                    ]
                )
            ]
        )

        self.assertEqual(findings, [])

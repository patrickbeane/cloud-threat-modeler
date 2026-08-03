from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.aws.dynamodb_normalizers import normalize_dynamodb_table
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES, AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

_TABLE_ARN = "arn:aws:dynamodb:us-east-1:111122223333:table/orders"
_KMS_KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/customer-dynamodb"


def _table(
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
    name: str = "orders",
) -> TerraformResource:
    return TerraformResource(
        address=f"aws_dynamodb_table.{name}",
        mode="managed",
        resource_type="aws_dynamodb_table",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


class AwsDynamoDbNormalizerTests(unittest.TestCase):
    def test_normalizes_encryption_recovery_and_replica_posture(self) -> None:
        normalized = normalize_dynamodb_table(
            _table(
                {
                    "id": "orders",
                    "name": "orders",
                    "arn": _TABLE_ARN,
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
                    "replica": [
                        {
                            "region_name": "us-west-2",
                            "kms_key_arn": "alias/aws/dynamodb",
                            "point_in_time_recovery": True,
                            "deletion_protection_enabled": False,
                            "consistency_mode": "EVENTUAL",
                        }
                    ],
                }
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.DATA)
        self.assertEqual(normalized.identifier, "orders")
        self.assertEqual(normalized.arn, _TABLE_ARN)
        self.assertTrue(normalized.storage_encrypted)
        self.assertEqual(facts.name, "orders")
        self.assertEqual(facts.dynamodb_table_arn, _TABLE_ARN)
        self.assertEqual(facts.dynamodb_kms_key_arn, _KMS_KEY_ARN)
        self.assertEqual(facts.dynamodb_encryption_ownership_state, "customer_managed")
        self.assertEqual(facts.dynamodb_encryption_configuration_state, "enabled")
        self.assertEqual(facts.dynamodb_pitr_state, "enabled")
        self.assertTrue(facts.dynamodb_pitr_enabled)
        self.assertEqual(facts.dynamodb_pitr_recovery_period_days, 35)
        self.assertEqual(facts.dynamodb_deletion_protection_state, "enabled")
        self.assertTrue(facts.dynamodb_deletion_protection_enabled)
        self.assertEqual(
            facts.dynamodb_replicas,
            [
                {
                    "region_name": "us-west-2",
                    "kms_key_arn": "alias/aws/dynamodb",
                    "point_in_time_recovery": True,
                    "deletion_protection_enabled": False,
                    "consistency_mode": "EVENTUAL",
                }
            ],
        )
        self.assertEqual(facts.dynamodb_posture_uncertainties, [])

    def test_normalizes_global_and_local_secondary_index_names(self) -> None:
        facts = aws_facts(
            normalize_dynamodb_table(
                _table(
                    {
                        "name": "orders",
                        "arn": _TABLE_ARN,
                        "global_secondary_index": [
                            {"name": "by-status"},
                            {"name": "by-customer"},
                        ],
                        "local_secondary_index": [
                            {"name": "by-created"},
                        ],
                    }
                )
            )
        )

        self.assertEqual(
            facts.dynamodb_index_names,
            ["by-created", "by-customer", "by-status"],
        )
        self.assertEqual(facts.dynamodb_index_inventory_state, "complete")
        self.assertEqual(facts.dynamodb_posture_uncertainties, [])

    def test_unknown_index_names_remain_unmodeled(self) -> None:
        facts = aws_facts(
            normalize_dynamodb_table(
                _table(
                    {
                        "name": "orders",
                        "arn": _TABLE_ARN,
                        "global_secondary_index": [
                            {},
                            {"name": "by-status"},
                        ],
                    },
                    unknown_values={
                        "global_secondary_index": [
                            {"name": True},
                            {},
                        ],
                        "local_secondary_index": True,
                    },
                )
            )
        )

        self.assertEqual(facts.dynamodb_index_names, ["by-status"])
        self.assertEqual(facts.dynamodb_index_inventory_state, "partial")
        self.assertEqual(
            facts.dynamodb_posture_uncertainties,
            [
                "global_secondary_index[0].name is unknown after planning",
                "local_secondary_index is unknown after planning",
            ],
        )

    def test_index_inventory_distinguishes_unknown_and_invalid(self) -> None:
        unknown = aws_facts(
            normalize_dynamodb_table(
                _table(
                    {"name": "unknown", "arn": _TABLE_ARN},
                    unknown_values={"global_secondary_index": True},
                )
            )
        )
        invalid = aws_facts(
            normalize_dynamodb_table(
                _table(
                    {
                        "name": "invalid",
                        "arn": _TABLE_ARN,
                        "local_secondary_index": [{}],
                    }
                )
            )
        )

        self.assertEqual(unknown.dynamodb_index_names, [])
        self.assertEqual(unknown.dynamodb_index_inventory_state, "unknown")
        self.assertEqual(invalid.dynamodb_index_names, [])
        self.assertEqual(invalid.dynamodb_index_inventory_state, "invalid")

    def test_distinguishes_aws_owned_aws_managed_and_customer_managed_encryption(self) -> None:
        cases = (
            ({}, "aws_owned", "not_configured", None),
            ({"server_side_encryption": [{"enabled": False}]}, "aws_owned", "disabled", None),
            ({"server_side_encryption": [{"enabled": True}]}, "aws_managed_kms", "enabled", None),
            (
                {
                    "server_side_encryption": [
                        {
                            "enabled": True,
                            "kms_key_arn": "alias/aws/dynamodb",
                        }
                    ]
                },
                "aws_managed_kms",
                "enabled",
                "alias/aws/dynamodb",
            ),
            (
                {"server_side_encryption": [{"enabled": True, "kms_key_arn": _KMS_KEY_ARN}]},
                "customer_managed",
                "enabled",
                _KMS_KEY_ARN,
            ),
        )

        for index, (values, ownership_state, configuration_state, key_arn) in enumerate(cases):
            with self.subTest(case=index):
                facts = aws_facts(normalize_dynamodb_table(_table(values, name=f"case_{index}")))
                self.assertEqual(facts.dynamodb_encryption_ownership_state, ownership_state)
                self.assertEqual(facts.dynamodb_encryption_configuration_state, configuration_state)
                self.assertEqual(facts.dynamodb_kms_key_arn, key_arn)

    def test_enabled_pitr_uses_default_recovery_period(self) -> None:
        facts = aws_facts(
            normalize_dynamodb_table(
                _table(
                    {
                        "name": "orders",
                        "point_in_time_recovery": [{"enabled": True}],
                    }
                )
            )
        )

        self.assertEqual(facts.dynamodb_pitr_state, "enabled")
        self.assertEqual(facts.dynamodb_pitr_recovery_period_days, 35)

    def test_missing_optional_recovery_blocks_are_not_safe_defaults(self) -> None:
        facts = aws_facts(
            normalize_dynamodb_table(
                _table(
                    {
                        "name": "minimal",
                        "deletion_protection_enabled": False,
                        "point_in_time_recovery": [{"enabled": False}],
                    },
                    name="minimal",
                )
            )
        )

        self.assertEqual(facts.dynamodb_encryption_ownership_state, "aws_owned")
        self.assertEqual(facts.dynamodb_pitr_state, "disabled")
        self.assertFalse(facts.dynamodb_pitr_enabled)
        self.assertEqual(facts.dynamodb_deletion_protection_state, "disabled")
        self.assertFalse(facts.dynamodb_deletion_protection_enabled)
        self.assertIsNone(facts.dynamodb_pitr_recovery_period_days)
        self.assertEqual(facts.dynamodb_posture_uncertainties, [])

        omitted = aws_facts(normalize_dynamodb_table(_table({"name": "omitted"}, name="omitted")))
        self.assertEqual(omitted.dynamodb_pitr_state, "not_configured")
        self.assertIsNone(omitted.dynamodb_pitr_enabled)
        self.assertEqual(omitted.dynamodb_deletion_protection_state, "not_configured")
        self.assertIsNone(omitted.dynamodb_deletion_protection_enabled)

    def test_unknown_values_remain_unknown_with_uncertainty_evidence(self) -> None:
        facts = aws_facts(
            normalize_dynamodb_table(
                _table(
                    {"name": "unknown"},
                    unknown_values={
                        "arn": True,
                        "server_side_encryption": True,
                        "point_in_time_recovery": True,
                        "deletion_protection_enabled": True,
                    },
                    name="unknown",
                )
            )
        )

        self.assertIsNone(facts.dynamodb_table_arn)
        self.assertEqual(facts.dynamodb_encryption_ownership_state, "unknown")
        self.assertEqual(facts.dynamodb_encryption_configuration_state, "unknown")
        self.assertEqual(facts.dynamodb_pitr_state, "unknown")
        self.assertIsNone(facts.dynamodb_pitr_enabled)
        self.assertEqual(facts.dynamodb_deletion_protection_state, "unknown")
        self.assertIsNone(facts.dynamodb_deletion_protection_enabled)
        self.assertEqual(
            facts.dynamodb_posture_uncertainties,
            [
                "arn is unknown after planning",
                "server_side_encryption is unknown after planning",
                "point_in_time_recovery is unknown after planning",
                "deletion_protection_enabled is unknown after planning",
            ],
        )

    def test_nested_unknown_replica_values_are_preserved_as_unknown_fields(self) -> None:
        facts = aws_facts(
            normalize_dynamodb_table(
                _table(
                    {
                        "name": "replicated",
                        "replica": [{"region_name": "us-west-2"}],
                    },
                    unknown_values={
                        "replica": [
                            {
                                "kms_key_arn": True,
                                "point_in_time_recovery": True,
                            }
                        ]
                    },
                    name="replicated",
                )
            )
        )

        self.assertEqual(
            facts.dynamodb_replicas,
            [
                {
                    "region_name": "us-west-2",
                    "unknown_fields": ["kms_key_arn", "point_in_time_recovery"],
                }
            ],
        )
        self.assertEqual(
            facts.dynamodb_posture_uncertainties,
            [
                "replica[0].kms_key_arn is unknown after planning",
                "replica[0].point_in_time_recovery is unknown after planning",
            ],
        )

    def test_aws_normalizer_registers_dynamodb_tables_as_data_stores(self) -> None:
        inventory = AwsNormalizer().normalize([_table({"name": "orders", "arn": _TABLE_ARN})])

        self.assertIn("aws_dynamodb_table", SUPPORTED_AWS_TYPES)
        self.assertEqual(inventory.metadata["supported_resource_types"], sorted(SUPPORTED_AWS_TYPES))
        self.assertEqual(inventory.resources[0].resource_type, "aws_dynamodb_table")
        self.assertTrue(inventory.resources[0].storage_encrypted)

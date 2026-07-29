from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

_ACCOUNT_ID = "111122223333"
_KEY_ID = "12345678-1234-1234-1234-123456789012"
_KEY_ARN = f"arn:aws:kms:us-east-1:{_ACCOUNT_ID}:key/{_KEY_ID}"
_ALIAS_ARN = f"arn:aws:kms:us-east-1:{_ACCOUNT_ID}:alias/orders"
_RUNTIME_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-runtime"


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _key(**values: Any) -> TerraformResource:
    base = {
        "id": _KEY_ID,
        "key_id": _KEY_ID,
        "arn": _KEY_ARN,
        "key_usage": "ENCRYPT_DECRYPT",
        "key_spec": "SYMMETRIC_DEFAULT",
    }
    base.update(values)
    return _resource("aws_kms_key", "orders", base)


def _policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": _RUNTIME_ROLE_ARN},
                "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
                "Resource": "*",
            },
        }
    )


class AwsKmsNormalizerTests(unittest.TestCase):
    def test_key_captures_origin_multi_region_key_store_xks_and_custom_rotation(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _key(
                    origin="AWS_KMS",
                    multi_region=True,
                    custom_key_store_id="cks-1234",
                    xks_key_id="xks-orders",
                    rotation_period_in_days=365,
                    enable_key_rotation=True,
                    policy=_policy(),
                )
            ]
        )
        key = inventory.get_by_address("aws_kms_key.orders")
        assert key is not None
        facts = aws_facts(key)

        self.assertEqual(key.identifier, _KEY_ID)
        self.assertEqual(facts.kms_key_id, _KEY_ID)
        self.assertEqual(facts.kms_key_origin, "AWS_KMS")
        self.assertEqual(facts.kms_multi_region_state, "enabled")
        self.assertTrue(facts.kms_multi_region)
        self.assertEqual(facts.kms_custom_key_store_id, "cks-1234")
        self.assertEqual(facts.kms_xks_key_id, "xks-orders")
        self.assertEqual(facts.kms_rotation_period_in_days, 365)
        self.assertEqual(facts.kms_policy_configuration_state, "configured")
        self.assertEqual(facts.kms_policy_completeness_state, "complete")
        self.assertEqual(facts.kms_policy_source_addresses, [key.address])
        self.assertEqual(len(key.policy_statements), 1)

    def test_unknown_key_posture_remains_unknown(self) -> None:
        key = _resource(
            "aws_kms_key",
            "orders",
            {"key_id": _KEY_ID},
            unknown_values={
                "origin": True,
                "multi_region": True,
                "custom_key_store_id": True,
                "xks_key_id": True,
                "rotation_period_in_days": True,
                "policy": True,
            },
        )
        inventory = AwsNormalizer().normalize([key])
        normalized = inventory.get_by_address("aws_kms_key.orders")
        assert normalized is not None
        facts = aws_facts(normalized)

        self.assertIsNone(facts.kms_key_origin)
        self.assertEqual(facts.kms_multi_region_state, "unknown")
        self.assertIsNone(facts.kms_multi_region)
        self.assertIsNone(facts.kms_custom_key_store_id)
        self.assertIsNone(facts.kms_xks_key_id)
        self.assertIsNone(facts.kms_rotation_period_in_days)
        self.assertEqual(facts.kms_policy_configuration_state, "unknown")
        self.assertEqual(facts.kms_policy_completeness_state, "unknown")
        self.assertIn("origin is unknown after planning", facts.kms_posture_uncertainties)
        self.assertIn("multi_region is unknown after planning", facts.kms_posture_uncertainties)
        self.assertIn("rotation_period_in_days is unknown after planning", facts.kms_posture_uncertainties)
        self.assertIn("policy is unknown after planning", facts.kms_posture_uncertainties)

    def test_alias_grant_and_standalone_policy_attach_to_exact_key(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _key(),
                _resource(
                    "aws_kms_alias",
                    "orders",
                    {
                        "id": "alias/orders",
                        "name": "alias/orders",
                        "arn": _ALIAS_ARN,
                        "target_key_id": "aws_kms_key.orders.key_id",
                        "target_key_arn": _KEY_ARN,
                    },
                ),
                _resource(
                    "aws_kms_grant",
                    "runtime",
                    {
                        "id": "grant-1234",
                        "grant_id": "grant-1234",
                        "name": "runtime",
                        "key_id": _KEY_ARN,
                        "grantee_principal": _RUNTIME_ROLE_ARN,
                        "operations": ["Decrypt", "GenerateDataKey"],
                        "retiring_principal": _RUNTIME_ROLE_ARN,
                        "constraints": [
                            {
                                "encryption_context_subset": {
                                    "application": "orders",
                                }
                            }
                        ],
                        "retire_on_delete": True,
                    },
                ),
                _resource(
                    "aws_kms_key_policy",
                    "orders",
                    {
                        "id": "aws_kms_key.orders",
                        "key_id": "aws_kms_key.orders.key_id",
                        "policy": _policy(),
                        "bypass_policy_lockout_safety_check": False,
                    },
                ),
            ]
        )
        key = inventory.get_by_address("aws_kms_key.orders")
        alias = inventory.get_by_address("aws_kms_alias.orders")
        grant = inventory.get_by_address("aws_kms_grant.runtime")
        policy = inventory.get_by_address("aws_kms_key_policy.orders")
        assert key is not None
        assert alias is not None
        assert grant is not None
        assert policy is not None

        key_facts = aws_facts(key)
        self.assertEqual(aws_facts(alias).kms_alias_resolved_key_address, key.address)
        self.assertEqual(aws_facts(grant).kms_grant_resolved_key_address, key.address)
        self.assertEqual(aws_facts(policy).kms_key_policy_resolved_key_address, key.address)
        self.assertEqual(
            aws_facts(policy).kms_key_policy_bypass_lockout_safety_check_state,
            "disabled",
        )
        self.assertEqual(len(key_facts.kms_aliases), 1)
        self.assertEqual(len(key_facts.kms_grants), 1)
        self.assertEqual(key_facts.kms_grants[0]["operations"], ["Decrypt", "GenerateDataKey"])
        self.assertEqual(
            key_facts.kms_grants[0]["constraints"], {"encryption_context_subset": {"application": "orders"}}
        )
        self.assertEqual(key_facts.kms_policy_source_addresses, [policy.address])
        self.assertEqual(key_facts.kms_policy_configuration_state, "configured")
        self.assertEqual(key_facts.kms_policy_completeness_state, "complete")
        self.assertEqual(len(key.policy_statements), 1)

    def test_structurally_invalid_policy_is_not_complete(self) -> None:
        inventory = AwsNormalizer().normalize(
            [_key(policy=json.dumps({"Version": "2012-10-17", "Statement": "unexpected"}))]
        )
        key = inventory.get_by_address("aws_kms_key.orders")
        assert key is not None
        facts = aws_facts(key)

        self.assertEqual(facts.kms_policy_configuration_state, "configured")
        self.assertEqual(facts.kms_policy_completeness_state, "unknown")
        self.assertEqual(key.policy_statements, ())
        self.assertIn("policy statements have an unrecognized value shape", facts.kms_policy_posture_uncertainties)

    def test_unknown_inline_and_complete_standalone_policy_remain_non_authoritative(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _resource(
                    "aws_kms_key",
                    "orders",
                    {"key_id": _KEY_ID, "arn": _KEY_ARN},
                    unknown_values={"policy": True},
                ),
                _resource(
                    "aws_kms_key_policy",
                    "orders",
                    {
                        "key_id": "aws_kms_key.orders.key_id",
                        "policy": _policy(),
                    },
                ),
            ]
        )
        key = inventory.get_by_address("aws_kms_key.orders")
        policy = inventory.get_by_address("aws_kms_key_policy.orders")
        assert key is not None
        assert policy is not None

        facts = aws_facts(key)
        self.assertEqual(facts.kms_policy_completeness_state, "unknown")
        self.assertEqual(key.policy_statements, ())
        self.assertEqual(len(facts.kms_key_policies), 2)
        self.assertEqual(len(policy.policy_statements), 1)

    def test_computed_identities_do_not_prevent_reference_resolution(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _resource(
                    "aws_kms_key",
                    "orders",
                    {},
                    unknown_values={"key_id": True, "id": True, "arn": True},
                ),
                _resource(
                    "aws_kms_alias",
                    "orders",
                    {
                        "name": "alias/orders",
                        "target_key_id": "aws_kms_key.orders.key_id",
                    },
                    unknown_values={"arn": True},
                ),
                _resource(
                    "aws_kms_grant",
                    "runtime",
                    {
                        "key_id": "aws_kms_key.orders.key_id",
                        "operations": ["Decrypt"],
                    },
                    unknown_values={"grant_id": True},
                ),
                _resource(
                    "aws_kms_key_policy",
                    "orders",
                    {
                        "key_id": "aws_kms_key.orders.key_id",
                        "policy": _policy(),
                    },
                ),
            ]
        )
        key = inventory.get_by_address("aws_kms_key.orders")
        alias = inventory.get_by_address("aws_kms_alias.orders")
        grant = inventory.get_by_address("aws_kms_grant.runtime")
        policy = inventory.get_by_address("aws_kms_key_policy.orders")
        assert key is not None
        assert alias is not None
        assert grant is not None
        assert policy is not None

        self.assertIsNone(key.identifier)
        self.assertEqual(aws_facts(alias).kms_alias_resolved_key_address, key.address)
        self.assertEqual(aws_facts(grant).kms_grant_resolved_key_address, key.address)
        self.assertEqual(aws_facts(policy).kms_key_policy_resolved_key_address, key.address)
        self.assertEqual(len(aws_facts(key).kms_aliases), 1)
        self.assertEqual(len(aws_facts(key).kms_grants), 1)
        self.assertIn("grant_id is unknown after planning", aws_facts(grant).kms_grant_posture_uncertainties)

    def test_inline_and_standalone_policy_sources_are_ambiguous(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _key(policy=_policy()),
                _resource(
                    "aws_kms_key_policy",
                    "orders",
                    {
                        "key_id": "aws_kms_key.orders.key_id",
                        "policy": _policy(),
                    },
                ),
            ]
        )
        key = inventory.get_by_address("aws_kms_key.orders")
        assert key is not None
        facts = aws_facts(key)

        self.assertEqual(facts.kms_policy_source_addresses, [key.address, "aws_kms_key_policy.orders"])
        self.assertEqual(facts.kms_policy_completeness_state, "unknown")
        self.assertTrue(
            any(
                "effective KMS key policy source is ambiguous" in value
                for value in facts.kms_policy_posture_uncertainties
            )
        )

    def test_unresolved_alias_grant_and_policy_targets_remain_unresolved(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _key(),
                _resource(
                    "aws_kms_alias",
                    "external",
                    {"name": "alias/external", "target_key_id": "aws_kms_key.external.key_id"},
                ),
                _resource(
                    "aws_kms_grant",
                    "external",
                    {"key_id": "aws_kms_key.external.key_id", "operations": ["Decrypt"]},
                ),
                _resource(
                    "aws_kms_key_policy",
                    "external",
                    {"key_id": "aws_kms_key.external.key_id", "policy": _policy()},
                ),
                _resource(
                    "aws_kms_alias",
                    "unknown",
                    {"name": "alias/unknown"},
                    unknown_values={"target_key_id": True},
                ),
            ]
        )
        key = inventory.get_by_address("aws_kms_key.orders")
        alias = inventory.get_by_address("aws_kms_alias.external")
        grant = inventory.get_by_address("aws_kms_grant.external")
        policy = inventory.get_by_address("aws_kms_key_policy.external")
        unknown_alias = inventory.get_by_address("aws_kms_alias.unknown")
        assert key is not None
        assert alias is not None
        assert grant is not None
        assert policy is not None
        assert unknown_alias is not None

        self.assertEqual(aws_facts(key).kms_aliases, [])
        self.assertEqual(aws_facts(key).kms_grants, [])
        self.assertEqual(aws_facts(alias).kms_unresolved_key_references, ["aws_kms_key.external.key_id"])
        self.assertEqual(aws_facts(grant).kms_unresolved_key_references, ["aws_kms_key.external.key_id"])
        self.assertEqual(aws_facts(policy).kms_unresolved_key_references, ["aws_kms_key.external.key_id"])
        self.assertIsNone(aws_facts(unknown_alias).kms_alias_target_key_reference)
        self.assertIn(
            "target_key_id is unknown after planning", aws_facts(unknown_alias).kms_alias_posture_uncertainties
        )


if __name__ == "__main__":
    unittest.main()

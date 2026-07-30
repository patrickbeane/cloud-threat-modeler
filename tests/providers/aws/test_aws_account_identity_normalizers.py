from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.aws.account_identity_normalizers import (
    normalize_caller_identity,
)
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES, AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

_ACCOUNT_ID = "111122223333"
_CALLER_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:user/terraform"


def _caller_identity(
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
    name: str = "current",
) -> TerraformResource:
    return TerraformResource(
        address=f"data.aws_caller_identity.{name}",
        mode="data",
        resource_type="aws_caller_identity",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _role(name: str, account_id: str) -> TerraformResource:
    return TerraformResource(
        address=f"aws_iam_role.{name}",
        mode="managed",
        resource_type="aws_iam_role",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values={
            "name": name,
            "arn": f"arn:aws:iam::{account_id}:role/{name}",
        },
    )


def _bucket(name: str = "assets") -> TerraformResource:
    return TerraformResource(
        address=f"aws_s3_bucket.{name}",
        mode="managed",
        resource_type="aws_s3_bucket",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values={
            "bucket": name,
            "arn": f"arn:aws:s3:::{name}",
        },
    )


class AwsCallerIdentityNormalizerTests(unittest.TestCase):
    def test_normalizes_caller_identity_and_sets_primary_account(self) -> None:
        caller = _caller_identity(
            {
                "account_id": _ACCOUNT_ID,
                "arn": _CALLER_ARN,
                "id": _ACCOUNT_ID,
                "user_id": "AIDAEXAMPLE",
            }
        )

        normalized = normalize_caller_identity(caller)
        facts = aws_facts(normalized)
        inventory = AwsNormalizer().normalize([caller])

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.identifier, _ACCOUNT_ID)
        self.assertEqual(normalized.arn, _CALLER_ARN)
        self.assertEqual(facts.caller_identity_account_id, _ACCOUNT_ID)
        self.assertEqual(facts.caller_identity_account_id_state, "resolved")
        self.assertEqual(facts.caller_identity_user_id, "AIDAEXAMPLE")
        self.assertEqual(facts.caller_identity_posture_uncertainties, [])
        self.assertEqual(inventory.primary_account_id, _ACCOUNT_ID)

    def test_account_id_alone_is_deterministic_caller_evidence(self) -> None:
        inventory = AwsNormalizer().normalize([_caller_identity({"account_id": _ACCOUNT_ID})])

        self.assertEqual(inventory.primary_account_id, _ACCOUNT_ID)

    def test_valid_account_id_with_malformed_duplicate_is_invalid(self) -> None:
        caller = _caller_identity(
            {
                "account_id": _ACCOUNT_ID,
                "id": "1234",
            }
        )

        inventory = AwsNormalizer().normalize([caller, _role("app", _ACCOUNT_ID)])
        facts = aws_facts(inventory.resources[0])

        self.assertIsNone(inventory.primary_account_id)
        self.assertIsNone(facts.caller_identity_account_id)
        self.assertEqual(facts.caller_identity_account_id_state, "invalid")
        self.assertIn(
            "id does not contain a valid 12-digit AWS account ID",
            facts.caller_identity_posture_uncertainties,
        )

    def test_unknown_caller_identity_preserves_unknown_primary_account(self) -> None:
        caller = _caller_identity(
            {
                "account_id": None,
                "arn": None,
                "id": None,
                "user_id": None,
            },
            unknown_values={
                "account_id": True,
                "arn": True,
                "id": True,
                "user_id": True,
            },
        )

        inventory = AwsNormalizer().normalize([caller])
        facts = aws_facts(inventory.resources[0])

        self.assertIsNone(inventory.primary_account_id)
        self.assertIsNone(facts.caller_identity_account_id)
        self.assertEqual(facts.caller_identity_account_id_state, "unknown")
        self.assertEqual(
            facts.caller_identity_posture_uncertainties,
            [
                "account_id is unknown after planning",
                "id is unknown after planning",
                "arn is unknown after planning",
                "user_id is unknown after planning",
            ],
        )

    def test_conflicting_caller_identity_evidence_fails_closed(self) -> None:
        caller = _caller_identity(
            {
                "account_id": _ACCOUNT_ID,
                "arn": "arn:aws:iam::444455556666:user/terraform",
                "id": _ACCOUNT_ID,
            }
        )

        inventory = AwsNormalizer().normalize([caller, _role("app", _ACCOUNT_ID)])
        facts = aws_facts(
            next(resource for resource in inventory.resources if resource.resource_type == "aws_caller_identity")
        )

        self.assertIsNone(inventory.primary_account_id)
        self.assertIsNone(facts.caller_identity_account_id)
        self.assertEqual(facts.caller_identity_account_id_state, "ambiguous")
        self.assertIn(
            "aws_caller_identity account_id, id, and arn contain conflicting AWS account IDs",
            facts.caller_identity_posture_uncertainties,
        )

    def test_one_unique_account_across_caller_and_resource_arns_resolves(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _caller_identity({"account_id": _ACCOUNT_ID}),
                _role("first", _ACCOUNT_ID),
                _role("second", _ACCOUNT_ID),
            ]
        )

        self.assertEqual(inventory.primary_account_id, _ACCOUNT_ID)

    def test_caller_identity_is_authoritative_over_foreign_resource_arns(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _caller_identity({"account_id": _ACCOUNT_ID}),
                _role("local", _ACCOUNT_ID),
                _role("foreign", "444455556666"),
            ]
        )

        self.assertEqual(inventory.primary_account_id, _ACCOUNT_ID)

    def test_resolved_and_unknown_caller_identities_fail_closed(self) -> None:
        unknown_caller = _caller_identity(
            {},
            name="pending",
            unknown_values={
                "account_id": True,
                "arn": True,
                "id": True,
            },
        )
        inventory = AwsNormalizer().normalize(
            [
                _caller_identity({"account_id": _ACCOUNT_ID}),
                unknown_caller,
                _role("app", _ACCOUNT_ID),
            ]
        )

        self.assertIsNone(inventory.primary_account_id)

    def test_matching_resolved_caller_identities_resolve(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _caller_identity({"account_id": _ACCOUNT_ID}),
                _caller_identity({"id": _ACCOUNT_ID}, name="alias"),
            ]
        )

        self.assertEqual(inventory.primary_account_id, _ACCOUNT_ID)

    def test_different_resolved_caller_identities_fail_closed(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _caller_identity({"account_id": _ACCOUNT_ID}),
                _caller_identity({"account_id": "444455556666"}, name="foreign"),
            ]
        )

        self.assertIsNone(inventory.primary_account_id)

    def test_conflicting_resource_arns_do_not_use_a_majority_vote(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _role("first", _ACCOUNT_ID),
                _role("second", _ACCOUNT_ID),
                _role("foreign", "444455556666"),
            ]
        )

        self.assertIsNone(inventory.primary_account_id)

    def test_malformed_account_bearing_resource_arn_blocks_fallback(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _role("valid", _ACCOUNT_ID),
                _role("malformed", "1234"),
            ]
        )

        self.assertIsNone(inventory.primary_account_id)

    def test_accountless_resource_arn_does_not_block_valid_fallback(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _role("valid", _ACCOUNT_ID),
                _bucket(),
            ]
        )

        self.assertEqual(inventory.primary_account_id, _ACCOUNT_ID)

    def test_malformed_account_evidence_does_not_establish_primary_account(
        self,
    ) -> None:
        caller = _caller_identity(
            {
                "account_id": "not-an-account",
                "arn": "arn:aws:iam::1234:user/terraform",
                "id": "1234",
            }
        )

        inventory = AwsNormalizer().normalize([caller, _role("app", _ACCOUNT_ID)])
        facts = aws_facts(inventory.resources[0])

        self.assertIsNone(inventory.primary_account_id)
        self.assertEqual(facts.caller_identity_account_id_state, "invalid")
        self.assertEqual(
            facts.caller_identity_posture_uncertainties,
            [
                "account_id does not contain a valid 12-digit AWS account ID",
                "id does not contain a valid 12-digit AWS account ID",
                "arn does not contain a valid 12-digit AWS account ID",
            ],
        )

    def test_caller_identity_is_registered_as_supported(self) -> None:
        self.assertIn("aws_caller_identity", SUPPORTED_AWS_TYPES)


if __name__ == "__main__":
    unittest.main()

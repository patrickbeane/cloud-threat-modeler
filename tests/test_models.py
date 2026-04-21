from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory, ResourceInventory


def _resource(
    *,
    address: str,
    resource_type: str,
    category: ResourceCategory = ResourceCategory.COMPUTE,
    identifier: str | None = None,
    arn: str | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="aws",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        arn=arn,
    )


class ResourceInventoryTests(unittest.TestCase):
    def test_by_type_preserves_original_resource_order_for_multiple_types(self) -> None:
        resources = [
            _resource(address="aws_instance.web", resource_type="aws_instance"),
            _resource(address="aws_db_instance.app", resource_type="aws_db_instance", category=ResourceCategory.DATA),
            _resource(address="aws_lambda_function.worker", resource_type="aws_lambda_function"),
            _resource(address="aws_instance.jobs", resource_type="aws_instance"),
        ]
        inventory = ResourceInventory(provider="aws", resources=resources)

        selected = inventory.by_type("aws_lambda_function", "aws_instance")

        self.assertEqual(
            [resource.address for resource in selected],
            [
                "aws_instance.web",
                "aws_lambda_function.worker",
                "aws_instance.jobs",
            ],
        )

    def test_get_by_identifier_preserves_first_match_across_identifier_arn_and_address_aliases(self) -> None:
        first = _resource(
            address="alias",
            resource_type="aws_instance",
            identifier="instance-1",
            arn="arn:aws:ec2:us-east-1:111122223333:instance/i-1234567890",
        )
        second = _resource(
            address="aws_s3_bucket.logs",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="alias",
            arn="arn:aws:s3:::logs",
        )
        third = _resource(
            address="aws_iam_role.app",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
            identifier="role-app",
            arn="alias",
        )
        inventory = ResourceInventory(provider="aws", resources=[first, second, third])

        self.assertIs(inventory.get_by_identifier("alias"), first)

    def test_get_by_address_uses_address_index(self) -> None:
        target = _resource(address="aws_instance.web", resource_type="aws_instance")
        inventory = ResourceInventory(
            provider="aws",
            resources=[
                target,
                _resource(address="aws_lambda_function.worker", resource_type="aws_lambda_function"),
            ],
        )

        self.assertIs(inventory.get_by_address("aws_instance.web"), target)
        self.assertIsNone(inventory.get_by_address("aws_instance.missing"))


if __name__ == "__main__":
    unittest.main()

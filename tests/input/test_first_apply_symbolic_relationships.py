from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

from tfstride.input.terraform_plan import load_terraform_plan

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_AWS_FIXTURE = _REPOSITORY_ROOT / "fixtures/aws/sample_aws_first_apply_symbolic_plan.json"
_GCP_FIXTURE = _REPOSITORY_ROOT / "fixtures/gcp/sample_gcp_first_apply_symbolic_plan.json"
_AZURE_FIXTURE = _REPOSITORY_ROOT / "fixtures/azure/sample_azure_first_apply_symbolic_plan.json"


class FirstApplySymbolicRelationshipFixtureTests(unittest.TestCase):
    """Characterize sanitized real Terraform show-json without resolving relationships.

    Fixtures were generated with Terraform 1.8.5 and AWS 5.55.0, Google
    5.34.0, and AzureRM 3.108.0. Offline credential expressions were removed.
    """

    def test_aws_first_apply_relationship_shapes(self) -> None:
        payload = _load_payload(_AWS_FIXTURE)
        resources = _loaded_resources(_AWS_FIXTURE)

        direct = resources["aws_ecs_service.direct"]
        direct_load_balancer = direct.values["load_balancer"][0]
        self.assertNotIn("target_group_arn", direct_load_balancer)
        self.assertIs(
            direct.unknown_values["load_balancer"][0]["target_group_arn"],
            True,
        )

        # Collection-valued unknowns follow the same omission plus after_unknown
        # contract, while an unconfigured optional collection remains explicit null.
        self.assertNotIn(
            "security_groups",
            direct.values["network_configuration"][0],
        )
        self.assertIs(
            direct.unknown_values["network_configuration"][0]["security_groups"],
            True,
        )
        self.assertIsNone(resources["aws_ecs_service.concrete"].values["network_configuration"][0]["security_groups"])

        root_config = payload["configuration"]["root_module"]
        direct_config = _configuration_resource(root_config, "aws_ecs_service.direct")
        self.assertEqual(
            direct_config["expressions"]["load_balancer"][0]["target_group_arn"]["references"],
            [
                "aws_lb_target_group.direct.arn",
                "aws_lb_target_group.direct",
            ],
        )

        ambiguous_config = _configuration_resource(
            root_config,
            "aws_ecs_service.ambiguous",
        )
        self.assertEqual(
            ambiguous_config["expressions"]["load_balancer"][0]["target_group_arn"]["references"],
            [
                "aws_lb_target_group.selector.arn",
                "aws_lb_target_group.selector",
                "aws_lb_target_group.direct.arn",
                "aws_lb_target_group.direct",
                "aws_lb_target_group.alternate.arn",
                "aws_lb_target_group.alternate",
            ],
        )

        concrete_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/existing/0123456789abcdef"
        concrete = resources["aws_ecs_service.concrete"]
        self.assertEqual(
            concrete.values["load_balancer"][0]["target_group_arn"],
            concrete_arn,
        )
        concrete_config = _configuration_resource(
            root_config,
            "aws_ecs_service.concrete",
        )
        self.assertEqual(
            concrete_config["expressions"]["load_balancer"][0]["target_group_arn"]["constant_value"],
            concrete_arn,
        )

        module_call = root_config["module_calls"]["passed"]
        self.assertEqual(
            module_call["expressions"]["target_group_arn"]["references"],
            [
                "aws_lb_target_group.passed.arn",
                "aws_lb_target_group.passed",
            ],
        )
        child_config = _configuration_resource(
            module_call["module"],
            "aws_ecs_service.this",
        )
        self.assertEqual(
            child_config["expressions"]["load_balancer"][0]["target_group_arn"]["references"],
            ["var.target_group_arn"],
        )
        module_resource = resources["module.passed.aws_ecs_service.this"]
        self.assertNotIn(
            "target_group_arn",
            module_resource.values["load_balancer"][0],
        )
        self.assertIs(
            module_resource.unknown_values["load_balancer"][0]["target_group_arn"],
            True,
        )

    def test_gcp_first_apply_relationship_shapes(self) -> None:
        payload = _load_payload(_GCP_FIXTURE)
        resources = _loaded_resources(_GCP_FIXTURE)

        direct = resources["google_pubsub_subscription.direct"]
        self.assertNotIn("topic", direct.values)
        self.assertIs(direct.unknown_values["topic"], True)

        iam_binding = resources["google_project_iam_binding.runtime"]
        self.assertNotIn("members", iam_binding.values)
        self.assertIs(iam_binding.unknown_values["members"], True)
        self.assertIsNone(resources["google_pubsub_subscription.concrete"].values["labels"])

        root_config = payload["configuration"]["root_module"]
        direct_config = _configuration_resource(
            root_config,
            "google_pubsub_subscription.direct",
        )
        self.assertEqual(
            direct_config["expressions"]["topic"]["references"],
            [
                "google_pubsub_topic.direct.id",
                "google_pubsub_topic.direct",
            ],
        )

        binding_config = _configuration_resource(
            root_config,
            "google_project_iam_binding.runtime",
        )
        self.assertEqual(
            binding_config["expressions"]["members"]["references"],
            [
                "google_service_account.runtime.email",
                "google_service_account.runtime",
            ],
        )

        ambiguous_config = _configuration_resource(
            root_config,
            "google_pubsub_subscription.ambiguous",
        )
        self.assertEqual(
            ambiguous_config["expressions"]["topic"]["references"],
            [
                "google_pubsub_topic.selector.id",
                "google_pubsub_topic.selector",
                "google_pubsub_topic.direct.id",
                "google_pubsub_topic.direct",
                "google_pubsub_topic.alternate.id",
                "google_pubsub_topic.alternate",
            ],
        )

        concrete_topic = "projects/tfstride-symbolic-fixture/topics/existing"
        concrete = resources["google_pubsub_subscription.concrete"]
        self.assertEqual(concrete.values["topic"], concrete_topic)
        concrete_config = _configuration_resource(
            root_config,
            "google_pubsub_subscription.concrete",
        )
        self.assertEqual(
            concrete_config["expressions"]["topic"]["constant_value"],
            concrete_topic,
        )

        module_call = root_config["module_calls"]["passed"]
        self.assertEqual(
            module_call["expressions"]["topic"]["references"],
            [
                "google_pubsub_topic.passed.id",
                "google_pubsub_topic.passed",
            ],
        )
        child_config = _configuration_resource(
            module_call["module"],
            "google_pubsub_subscription.this",
        )
        self.assertEqual(
            child_config["expressions"]["topic"]["references"],
            ["var.topic"],
        )
        module_resource = resources["module.passed.google_pubsub_subscription.this"]
        self.assertNotIn("topic", module_resource.values)
        self.assertIs(module_resource.unknown_values["topic"], True)

    def test_azure_first_apply_relationship_shapes(self) -> None:
        payload = _load_payload(_AZURE_FIXTURE)
        resources = _loaded_resources(_AZURE_FIXTURE)

        direct = resources["azurerm_role_assignment.direct"]
        self.assertNotIn("scope", direct.values)
        self.assertIs(direct.unknown_values["scope"], True)
        self.assertIsNone(direct.values["condition"])

        role_definition = resources["azurerm_role_definition.storage_reader"]
        self.assertNotIn("assignable_scopes", role_definition.values)
        self.assertIs(role_definition.unknown_values["assignable_scopes"], True)

        root_config = payload["configuration"]["root_module"]
        direct_config = _configuration_resource(
            root_config,
            "azurerm_role_assignment.direct",
        )
        self.assertEqual(
            direct_config["expressions"]["scope"]["references"],
            [
                "azurerm_storage_account.direct.id",
                "azurerm_storage_account.direct",
            ],
        )

        role_definition_config = _configuration_resource(
            root_config,
            "azurerm_role_definition.storage_reader",
        )
        self.assertEqual(
            role_definition_config["expressions"]["assignable_scopes"]["references"],
            [
                "azurerm_storage_account.direct.id",
                "azurerm_storage_account.direct",
            ],
        )

        ambiguous_config = _configuration_resource(
            root_config,
            "azurerm_role_assignment.ambiguous",
        )
        self.assertEqual(
            ambiguous_config["expressions"]["scope"]["references"],
            [
                "azurerm_storage_account.selector.id",
                "azurerm_storage_account.selector",
                "azurerm_storage_account.direct.id",
                "azurerm_storage_account.direct",
                "azurerm_storage_account.alternate.id",
                "azurerm_storage_account.alternate",
            ],
        )

        concrete_scope = (
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/tfstride-fixture/providers/Microsoft.Storage/"
            "storageAccounts/existing"
        )
        concrete = resources["azurerm_role_assignment.concrete"]
        self.assertEqual(concrete.values["scope"], concrete_scope)
        concrete_config = _configuration_resource(
            root_config,
            "azurerm_role_assignment.concrete",
        )
        self.assertEqual(
            concrete_config["expressions"]["scope"]["constant_value"],
            concrete_scope,
        )

        module_call = root_config["module_calls"]["passed"]
        self.assertEqual(
            module_call["expressions"]["scope"]["references"],
            [
                "azurerm_storage_account.passed.id",
                "azurerm_storage_account.passed",
            ],
        )
        child_config = _configuration_resource(
            module_call["module"],
            "azurerm_role_assignment.this",
        )
        self.assertEqual(
            child_config["expressions"]["scope"]["references"],
            ["var.scope"],
        )
        module_resource = resources["module.passed.azurerm_role_assignment.this"]
        self.assertNotIn("scope", module_resource.values)
        self.assertIs(module_resource.unknown_values["scope"], True)

    def test_fixtures_are_real_terraform_show_json_documents(self) -> None:
        for fixture in (_AWS_FIXTURE, _GCP_FIXTURE, _AZURE_FIXTURE):
            with self.subTest(fixture=fixture.name):
                payload = _load_payload(fixture)
                self.assertEqual(payload["terraform_version"], "1.8.5")
                self.assertEqual(payload["format_version"], "1.2")
                self.assertIn("planned_values", payload)
                self.assertIn("resource_changes", payload)
                self.assertIn("configuration", payload)
                self.assertIn("relevant_attributes", payload)


def _load_payload(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError(f"{path} must contain a Terraform plan object")
    return payload


def _loaded_resources(path: Path) -> dict[str, Any]:
    plan = load_terraform_plan(path)
    return {resource.address: resource for resource in plan.resources}


def _configuration_resource(
    module: dict[str, Any],
    address: str,
) -> dict[str, Any]:
    for resource in module.get("resources", []):
        if resource.get("address") == address:
            return resource
    raise AssertionError(f"configuration resource not found: {address}")


if __name__ == "__main__":
    unittest.main()

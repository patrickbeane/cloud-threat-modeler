from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import TerraformReferenceProvenance, TerraformReferenceResolutionState


class TerraformConfigurationReferenceResolutionTests(unittest.TestCase):
    def test_known_planned_value_takes_precedence_over_configuration_reference(self) -> None:
        payload = _root_plan(
            planned_resources=[
                _planned_resource("aws_target.exact", "aws_target", "exact", {"id": "target-123"}),
                _planned_resource("aws_consumer.known", "aws_consumer", "known", {"target": "target-123"}),
            ],
            configuration_resources=[
                _configuration_resource("aws_target.exact", "aws_target", "exact"),
                _configuration_resource(
                    "aws_consumer.known",
                    "aws_consumer",
                    "known",
                    expressions={
                        "target": {
                            "references": [
                                "aws_target.exact.id",
                                "aws_target.exact",
                                "aws_target.exact.arn",
                            ]
                        }
                    },
                ),
            ],
        )

        resource = _load_resources(payload)["aws_consumer.known"]
        resolution = resource.reference_resolution("target")

        self.assertEqual(resolution.state, TerraformReferenceResolutionState.RESOLVED)
        self.assertEqual(resolution.provenance, TerraformReferenceProvenance.PLANNED_VALUE)
        self.assertEqual(resolution.planned_value, "target-123")
        self.assertEqual(
            resolution.references,
            ("aws_target.exact.id", "aws_target.exact.arn"),
        )
        self.assertEqual(resolution.targets, ())

    def test_single_target_conditional_is_not_exactly_resolved(self) -> None:
        # `var.enabled ? aws_target.exact.id : null` has no expression AST in show-json.
        self._assert_single_target_reference_is_symbolic("conditional", "target")

    def test_single_target_collection_expression_is_not_exactly_resolved(self) -> None:
        # `var.enabled ? [aws_target.exact.id] : []` can expose the same references.
        self._assert_single_target_reference_is_symbolic("collection", "targets")

    def test_single_target_transformation_is_not_exactly_resolved(self) -> None:
        # `"${aws_target.exact.id}-suffix"` can expose the same references.
        self._assert_single_target_reference_is_symbolic("transformation", "target")

    def _assert_single_target_reference_is_symbolic(
        self,
        resource_name: str,
        attribute: str,
    ) -> None:
        address = f"aws_consumer.{resource_name}"
        payload = _root_plan(
            planned_resources=[
                _planned_resource("aws_target.exact", "aws_target", "exact", {}),
                _planned_resource(address, "aws_consumer", resource_name, {}),
            ],
            configuration_resources=[
                _configuration_resource("aws_target.exact", "aws_target", "exact"),
                _configuration_resource(
                    address,
                    "aws_consumer",
                    resource_name,
                    expressions={
                        attribute: {
                            "references": [
                                "aws_target.exact.id",
                                "aws_target.exact",
                            ]
                        }
                    },
                ),
            ],
            unknown_values={address: {attribute: True}},
        )

        resolution = _load_resources(payload)[address].reference_resolution(attribute)

        self.assertEqual(resolution.state, TerraformReferenceResolutionState.SYMBOLIC)
        self.assertEqual(
            resolution.provenance,
            TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        )
        self.assertEqual(resolution.references, ("aws_target.exact.id",))
        self.assertEqual(
            [(target.address, target.reference) for target in resolution.targets],
            [("aws_target.exact", "aws_target.exact.id")],
        )
        self.assertIn("value equivalence is unproven", resolution.reason or "")

    def test_unresolved_reference_and_unavailable_dynamic_expression_are_distinct(self) -> None:
        payload = _root_plan(
            planned_resources=[
                _planned_resource("aws_consumer.unresolved", "aws_consumer", "unresolved", {}),
                _planned_resource("aws_consumer.dynamic", "aws_consumer", "dynamic", {}),
            ],
            configuration_resources=[
                _configuration_resource(
                    "aws_consumer.unresolved",
                    "aws_consumer",
                    "unresolved",
                    expressions={"target": {"references": ["local.remote_target_id"]}},
                ),
                # Terraform omits dynamic-block expressions from configuration JSON.
                _configuration_resource(
                    "aws_consumer.dynamic",
                    "aws_consumer",
                    "dynamic",
                ),
            ],
            unknown_values={
                "aws_consumer.unresolved": {"target": True},
                "aws_consumer.dynamic": {"target": True},
            },
        )

        resources = _load_resources(payload)
        unresolved = resources["aws_consumer.unresolved"].reference_resolution("target")
        unsupported = resources["aws_consumer.dynamic"].reference_resolution("target")

        self.assertEqual(unresolved.state, TerraformReferenceResolutionState.UNRESOLVED)
        self.assertEqual(
            unresolved.provenance,
            TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        )
        self.assertEqual(unresolved.references, ("local.remote_target_id",))
        self.assertEqual(unsupported.state, TerraformReferenceResolutionState.UNSUPPORTED)
        self.assertIsNone(unsupported.provenance)
        self.assertIn("configuration expression is unavailable", unsupported.reason or "")

    def test_child_module_output_reference_remains_explicitly_unresolved(self) -> None:
        payload = _root_plan(
            planned_resources=[
                _planned_resource("aws_consumer.module_output", "aws_consumer", "module_output", {}),
            ],
            configuration_resources=[
                _configuration_resource(
                    "aws_consumer.module_output",
                    "aws_consumer",
                    "module_output",
                    expressions={"target": {"references": ["module.network.resource_id"]}},
                ),
            ],
            unknown_values={"aws_consumer.module_output": {"target": True}},
        )

        resolution = _load_resources(payload)["aws_consumer.module_output"].reference_resolution("target")

        self.assertEqual(resolution.state, TerraformReferenceResolutionState.UNRESOLVED)
        self.assertIn("child-module output references are not traversed", resolution.reason or "")

    def test_count_and_for_each_resource_expansions_are_unsupported(self) -> None:
        payload = _root_plan(
            planned_resources=[
                _planned_resource("aws_target.exact", "aws_target", "exact", {}),
                _planned_resource('aws_target.items["one"]', "aws_target", "items", {}),
                _planned_resource("aws_consumer.counted[0]", "aws_consumer", "counted", {}),
                _planned_resource("aws_consumer.expanded_target", "aws_consumer", "expanded_target", {}),
            ],
            configuration_resources=[
                _configuration_resource("aws_target.exact", "aws_target", "exact"),
                _configuration_resource(
                    "aws_target.items",
                    "aws_target",
                    "items",
                    for_each_expression={"constant_value": {"one": True}},
                ),
                _configuration_resource(
                    "aws_consumer.counted",
                    "aws_consumer",
                    "counted",
                    expressions={
                        "target": {
                            "references": [
                                "aws_target.exact.id",
                                "aws_target.exact",
                            ]
                        }
                    },
                    count_expression={"constant_value": 1},
                ),
                _configuration_resource(
                    "aws_consumer.expanded_target",
                    "aws_consumer",
                    "expanded_target",
                    expressions={
                        "target": {
                            "references": [
                                'aws_target.items["one"].id',
                                "aws_target.items",
                            ]
                        }
                    },
                ),
            ],
            unknown_values={
                "aws_consumer.counted[0]": {"target": True},
                "aws_consumer.expanded_target": {"target": True},
            },
        )

        resources = _load_resources(payload)
        counted = resources["aws_consumer.counted[0]"].reference_resolution("target")
        expanded_target = resources["aws_consumer.expanded_target"].reference_resolution("target")

        self.assertEqual(counted.state, TerraformReferenceResolutionState.UNSUPPORTED)
        self.assertEqual(
            [target.address for target in counted.targets],
            ["aws_target.exact"],
        )
        self.assertEqual(expanded_target.state, TerraformReferenceResolutionState.UNSUPPORTED)
        self.assertEqual(
            expanded_target.references,
            ('aws_target.items["one"].id',),
        )
        self.assertEqual(
            [target.address for target in expanded_target.targets],
            ['aws_target.items["one"]'],
        )

    def test_for_each_module_input_pass_through_is_unsupported(self) -> None:
        child_address = 'module.consumers["one"].aws_consumer.this'
        payload = _root_plan(
            planned_resources=[
                _planned_resource("aws_target.exact", "aws_target", "exact", {}),
            ],
            planned_child_modules=[
                {
                    "address": 'module.consumers["one"]',
                    "resources": [
                        _planned_resource(child_address, "aws_consumer", "this", {}),
                    ],
                }
            ],
            configuration_resources=[
                _configuration_resource("aws_target.exact", "aws_target", "exact"),
            ],
            module_calls={
                "consumers": {
                    "for_each_expression": {"constant_value": {"one": True}},
                    "expressions": {
                        "target": {
                            "references": [
                                "aws_target.exact.id",
                                "aws_target.exact",
                            ]
                        }
                    },
                    "module": {
                        "resources": [
                            _configuration_resource(
                                "aws_consumer.this",
                                "aws_consumer",
                                "this",
                                expressions={"target": {"references": ["var.target"]}},
                            )
                        ],
                        "variables": {"target": {}},
                    },
                }
            },
            unknown_values={child_address: {"target": True}},
        )

        resolution = _load_resources(payload)[child_address].reference_resolution("target")

        self.assertEqual(resolution.state, TerraformReferenceResolutionState.UNSUPPORTED)
        self.assertEqual(resolution.references, ("var.target",))
        self.assertEqual(
            [(target.address, target.reference) for target in resolution.targets],
            [("aws_target.exact", "aws_target.exact.id")],
        )


def _root_plan(
    *,
    planned_resources: list[dict[str, Any]],
    configuration_resources: list[dict[str, Any]],
    planned_child_modules: list[dict[str, Any]] | None = None,
    module_calls: dict[str, Any] | None = None,
    unknown_values: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    root_planned: dict[str, Any] = {"resources": planned_resources}
    if planned_child_modules:
        root_planned["child_modules"] = planned_child_modules
    root_configuration: dict[str, Any] = {"resources": configuration_resources}
    if module_calls:
        root_configuration["module_calls"] = module_calls

    return {
        "terraform_version": "1.8.5",
        "planned_values": {"root_module": root_planned},
        "resource_changes": [
            {
                "address": address,
                "change": {"after_unknown": values},
            }
            for address, values in (unknown_values or {}).items()
        ],
        "configuration": {"root_module": root_configuration},
    }


def _planned_resource(
    address: str,
    resource_type: str,
    name: str,
    values: dict[str, Any],
) -> dict[str, Any]:
    return {
        "address": address,
        "mode": "managed",
        "type": resource_type,
        "name": name,
        "provider_name": "registry.terraform.io/hashicorp/aws",
        "values": values,
    }


def _configuration_resource(
    address: str,
    resource_type: str,
    name: str,
    *,
    expressions: dict[str, Any] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "address": address,
        "mode": "managed",
        "type": resource_type,
        "name": name,
        "expressions": expressions or {},
        **extra,
    }


def _load_resources(payload: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = Path(tmp_dir) / "plan.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        plan = load_terraform_plan(path)
    return {resource.address: resource for resource in plan.resources}


if __name__ == "__main__":
    unittest.main()

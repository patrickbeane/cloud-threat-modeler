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

    def test_direct_collection_and_conditional_multi_target_references_are_indistinguishable(self) -> None:
        target_addresses = ("aws_target.blob", "aws_target.file")
        references = [
            "aws_target.blob.id",
            "aws_target.blob",
            "aws_target.file.id",
            "aws_target.file",
        ]
        payload = _root_plan(
            planned_resources=[
                _planned_resource(address, "aws_target", address.rsplit(".", 1)[-1], {}) for address in target_addresses
            ]
            + [
                _planned_resource("aws_consumer.collection", "aws_consumer", "collection", {}),
                _planned_resource("aws_consumer.conditional", "aws_consumer", "conditional", {}),
            ],
            configuration_resources=[
                *[
                    _configuration_resource(address, "aws_target", address.rsplit(".", 1)[-1])
                    for address in target_addresses
                ],
                _configuration_resource(
                    "aws_consumer.collection",
                    "aws_consumer",
                    "collection",
                    expressions={"target": {"references": references}},
                ),
                _configuration_resource(
                    "aws_consumer.conditional",
                    "aws_consumer",
                    "conditional",
                    expressions={"target": {"references": references}},
                ),
            ],
            unknown_values={
                "aws_consumer.collection": {"target": True},
                "aws_consumer.conditional": {"target": True},
            },
        )

        resources = _load_resources(payload)
        collection = resources["aws_consumer.collection"].reference_resolution("target")
        conditional = resources["aws_consumer.conditional"].reference_resolution("target")

        self.assertEqual(collection.state, TerraformReferenceResolutionState.AMBIGUOUS)
        self.assertEqual(conditional.state, TerraformReferenceResolutionState.AMBIGUOUS)
        self.assertEqual(
            [target.address for target in collection.targets],
            list(target_addresses),
        )
        self.assertEqual(
            [(target.address, target.reference) for target in conditional.targets],
            [(target, f"{target}.id") for target in target_addresses],
        )

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

    def test_expanded_resource_sources_preserve_relationship_candidates(self) -> None:
        source_addresses = (
            'aws_consumer.items["blue"]',
            'aws_consumer.items["green"]',
        )
        target_addresses = (
            'aws_target.items["blue"]',
            'aws_target.items["green"]',
        )
        payload = _root_plan(
            planned_resources=[
                _planned_resource("aws_target.shared", "aws_target", "shared", {}),
                *[_planned_resource(address, "aws_target", "items", {}) for address in target_addresses],
                *[_planned_resource(address, "aws_consumer", "items", {}) for address in source_addresses],
            ],
            configuration_resources=[
                _configuration_resource("aws_target.shared", "aws_target", "shared"),
                _configuration_resource(
                    "aws_target.items",
                    "aws_target",
                    "items",
                    for_each_expression={"references": ["var.environments"]},
                ),
                _configuration_resource(
                    "aws_consumer.items",
                    "aws_consumer",
                    "items",
                    expressions={
                        "shared_target": {
                            "references": [
                                "aws_target.shared.id",
                                "aws_target.shared",
                            ]
                        },
                        "expanded_target": {
                            "references": [
                                "aws_target.items.id",
                                "aws_target.items",
                            ]
                        },
                        "indexed_target": {
                            "references": [
                                "aws_target.items.id",
                                "aws_target.items",
                                "each.key",
                            ]
                        },
                        "selector_target": {
                            "references": [
                                "aws_target.shared.id",
                                "aws_target.shared",
                                "each.key",
                            ]
                        },
                    },
                    for_each_expression={"references": ["var.environments"]},
                ),
            ],
            unknown_values={
                address: {
                    "shared_target": True,
                    "expanded_target": True,
                    "indexed_target": True,
                    "selector_target": True,
                }
                for address in source_addresses
            },
        )

        resources = _load_resources(payload)
        for source_address in source_addresses:
            with self.subTest(source=source_address):
                shared = resources[source_address].reference_resolution("shared_target")
                expanded = resources[source_address].reference_resolution("expanded_target")
                indexed = resources[source_address].reference_resolution("indexed_target")
                selector = resources[source_address].reference_resolution("selector_target")

                self.assertEqual(
                    shared.state,
                    TerraformReferenceResolutionState.SYMBOLIC,
                )
                self.assertEqual(
                    shared.provenance,
                    TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
                )
                self.assertEqual(shared.references, ("aws_target.shared.id",))
                self.assertEqual(
                    [target.address for target in shared.targets],
                    ["aws_target.shared"],
                )
                self.assertIn("one modeled resource", shared.reason or "")
                self.assertEqual(
                    expanded.state,
                    TerraformReferenceResolutionState.AMBIGUOUS,
                )
                self.assertEqual(
                    expanded.provenance,
                    TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
                )
                self.assertEqual(expanded.references, ("aws_target.items.id",))
                self.assertEqual(
                    [target.address for target in expanded.targets],
                    list(target_addresses),
                )
                self.assertIn("multiple possible targets", expanded.reason or "")
                self.assertEqual(
                    indexed.state,
                    TerraformReferenceResolutionState.AMBIGUOUS,
                )
                self.assertEqual(
                    indexed.references,
                    ("aws_target.items.id", "each.key"),
                )
                self.assertEqual(
                    [target.address for target in indexed.targets],
                    list(target_addresses),
                )
                self.assertIn("multiple possible targets", indexed.reason or "")
                self.assertEqual(
                    selector.state,
                    TerraformReferenceResolutionState.AMBIGUOUS,
                )
                self.assertEqual(
                    selector.references,
                    ("aws_target.shared.id", "each.key"),
                )
                self.assertEqual(
                    [target.address for target in selector.targets],
                    ["aws_target.shared"],
                )
                self.assertIn("multiple possible targets", selector.reason or "")

    def test_expanded_module_sources_preserve_input_relationship_candidates(self) -> None:
        module_addresses = (
            'module.consumers["blue"]',
            'module.consumers["green"]',
        )
        source_addresses = tuple(f"{module_address}.aws_consumer.this" for module_address in module_addresses)
        target_addresses = (
            'aws_target.items["blue"]',
            'aws_target.items["green"]',
        )
        child_configuration = {
            "resources": [
                _configuration_resource(
                    "aws_consumer.this",
                    "aws_consumer",
                    "this",
                    expressions={
                        "shared_target": {"references": ["var.shared_target"]},
                        "expanded_target": {"references": ["var.expanded_target"]},
                    },
                )
            ],
            "variables": {
                "shared_target": {},
                "expanded_target": {},
            },
        }
        payload = _root_plan(
            planned_resources=[
                _planned_resource("aws_target.shared", "aws_target", "shared", {}),
                *[_planned_resource(address, "aws_target", "items", {}) for address in target_addresses],
            ],
            planned_child_modules=[
                {
                    "address": module_address,
                    "resources": [
                        _planned_resource(
                            source_address,
                            "aws_consumer",
                            "this",
                            {},
                        )
                    ],
                }
                for module_address, source_address in zip(
                    module_addresses,
                    source_addresses,
                    strict=True,
                )
            ],
            configuration_resources=[
                _configuration_resource("aws_target.shared", "aws_target", "shared"),
                _configuration_resource(
                    "aws_target.items",
                    "aws_target",
                    "items",
                    for_each_expression={"references": ["var.environments"]},
                ),
            ],
            module_calls={
                "consumers": {
                    "for_each_expression": {"references": ["var.environments"]},
                    "expressions": {
                        "shared_target": {
                            "references": [
                                "aws_target.shared.id",
                                "aws_target.shared",
                            ]
                        },
                        "expanded_target": {
                            "references": [
                                "aws_target.items.id",
                                "aws_target.items",
                            ]
                        },
                    },
                    "module": child_configuration,
                }
            },
            unknown_values={
                address: {
                    "shared_target": True,
                    "expanded_target": True,
                }
                for address in source_addresses
            },
        )

        resources = _load_resources(payload)
        for source_address in source_addresses:
            with self.subTest(source=source_address):
                shared = resources[source_address].reference_resolution("shared_target")
                expanded = resources[source_address].reference_resolution("expanded_target")

                self.assertEqual(
                    shared.state,
                    TerraformReferenceResolutionState.SYMBOLIC,
                )
                self.assertEqual(
                    shared.provenance,
                    TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
                )
                self.assertEqual(shared.references, ("var.shared_target",))
                self.assertEqual(
                    [target.address for target in shared.targets],
                    ["aws_target.shared"],
                )
                self.assertIn("module input var.shared_target", shared.reason or "")
                self.assertEqual(
                    expanded.state,
                    TerraformReferenceResolutionState.AMBIGUOUS,
                )
                self.assertEqual(
                    expanded.provenance,
                    TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
                )
                self.assertEqual(expanded.references, ("var.expanded_target",))
                self.assertEqual(
                    [target.address for target in expanded.targets],
                    list(target_addresses),
                )
                self.assertIn("multiple possible targets", expanded.reason or "")

    def test_count_source_and_single_expanded_target_resolve_symbolically(self) -> None:
        payload = _root_plan(
            planned_resources=[
                _planned_resource("aws_target.exact", "aws_target", "exact", {}),
                _planned_resource('aws_target.items["one"]', "aws_target", "items", {}),
                _planned_resource("aws_consumer.counted[0]", "aws_consumer", "counted", {}),
                _planned_resource("aws_consumer.counted[1]", "aws_consumer", "counted", {}),
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
                    count_expression={"constant_value": 2},
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
                "aws_consumer.counted[1]": {"target": True},
                "aws_consumer.expanded_target": {"target": True},
            },
        )

        resources = _load_resources(payload)
        for source_address in (
            "aws_consumer.counted[0]",
            "aws_consumer.counted[1]",
        ):
            with self.subTest(source=source_address):
                counted = resources[source_address].reference_resolution("target")
                self.assertEqual(
                    counted.state,
                    TerraformReferenceResolutionState.SYMBOLIC,
                )
                self.assertEqual(
                    [target.address for target in counted.targets],
                    ["aws_target.exact"],
                )
                self.assertIn("one modeled resource", counted.reason or "")

        expanded_target = resources["aws_consumer.expanded_target"].reference_resolution("target")
        self.assertEqual(
            expanded_target.state,
            TerraformReferenceResolutionState.SYMBOLIC,
        )
        self.assertEqual(
            expanded_target.references,
            ('aws_target.items["one"].id',),
        )
        self.assertEqual(
            [target.address for target in expanded_target.targets],
            ['aws_target.items["one"]'],
        )
        self.assertIn("one modeled resource", expanded_target.reason or "")

    def test_for_each_module_input_pass_through_resolves_symbolically(self) -> None:
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

        self.assertEqual(
            resolution.state,
            TerraformReferenceResolutionState.SYMBOLIC,
        )
        self.assertEqual(resolution.references, ("var.target",))
        self.assertEqual(
            [(target.address, target.reference) for target in resolution.targets],
            [("aws_target.exact", "aws_target.exact.id")],
        )
        self.assertIn("module input var.target", resolution.reason or "")


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

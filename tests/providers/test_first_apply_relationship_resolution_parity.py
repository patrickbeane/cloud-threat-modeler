from __future__ import annotations

import unittest
from dataclasses import dataclass
from pathlib import Path

from tfstride.app import TfStride
from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import (
    Finding,
    NormalizedResource,
    ResourceInventory,
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
    TerraformResource,
)
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True, slots=True)
class _ProviderCase:
    provider: str
    fixture: Path
    relationship_path: tuple[str | int, ...]
    target_suffix: str
    direct_source: str
    direct_target: str
    direct_native_target: str
    module_source: str
    module_target: str
    module_native_target: str
    concrete_source: str
    concrete_value: str
    ambiguous_source: str


_CASES = (
    _ProviderCase(
        provider="aws",
        fixture=_REPOSITORY_ROOT / "fixtures/aws/sample_aws_first_apply_symbolic_plan.json",
        relationship_path=("load_balancer", 0, "target_group_arn"),
        target_suffix=".arn",
        direct_source="aws_ecs_service.direct",
        direct_target="aws_lb_target_group.direct",
        direct_native_target="aws_lb_target_group.direct",
        module_source="module.passed.aws_ecs_service.this",
        module_target="aws_lb_target_group.passed",
        module_native_target="aws_lb_target_group.passed",
        concrete_source="aws_ecs_service.concrete",
        concrete_value=("arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/existing/0123456789abcdef"),
        ambiguous_source="aws_ecs_service.ambiguous",
    ),
    _ProviderCase(
        provider="gcp",
        fixture=_REPOSITORY_ROOT / "fixtures/gcp/sample_gcp_first_apply_symbolic_plan.json",
        relationship_path=("topic",),
        target_suffix=".id",
        direct_source="google_pubsub_subscription.direct",
        direct_target="google_pubsub_topic.direct",
        direct_native_target="projects/tfstride-symbolic-fixture/topics/direct",
        module_source="module.passed.google_pubsub_subscription.this",
        module_target="google_pubsub_topic.passed",
        module_native_target="projects/tfstride-symbolic-fixture/topics/passed",
        concrete_source="google_pubsub_subscription.concrete",
        concrete_value="projects/tfstride-symbolic-fixture/topics/existing",
        ambiguous_source="google_pubsub_subscription.ambiguous",
    ),
    _ProviderCase(
        provider="azure",
        fixture=_REPOSITORY_ROOT / "fixtures/azure/sample_azure_first_apply_symbolic_plan.json",
        relationship_path=("scope",),
        target_suffix=".id",
        direct_source="azurerm_role_assignment.direct",
        direct_target="azurerm_storage_account.direct",
        direct_native_target="azurerm_storage_account.direct",
        module_source="module.passed.azurerm_role_assignment.this",
        module_target="azurerm_storage_account.passed",
        module_native_target="azurerm_storage_account.passed",
        concrete_source="azurerm_role_assignment.concrete",
        concrete_value=(
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/tfstride-fixture/providers/Microsoft.Storage/"
            "storageAccounts/existing"
        ),
        ambiguous_source="azurerm_role_assignment.ambiguous",
    ),
)


class FirstApplyRelationshipResolutionParityTests(unittest.TestCase):
    def test_exact_and_module_references_adopt_provider_native_relationships(
        self,
    ) -> None:
        for case in _CASES:
            with self.subTest(provider=case.provider):
                resources = _loaded_resources(case.fixture)
                result = TfStride().analyze_plan(case.fixture)

                _assert_symbolic_target(
                    self,
                    resources[case.direct_source],
                    case.relationship_path,
                    case.direct_target,
                )
                _assert_symbolic_target(
                    self,
                    resources[case.module_source],
                    case.relationship_path,
                    case.module_target,
                )

                direct = _required_resource(result.inventory, case.direct_source)
                module = _required_resource(result.inventory, case.module_source)
                self.assertEqual(
                    _native_symbolic_target(case.provider, direct),
                    case.direct_native_target,
                )
                self.assertEqual(
                    _native_symbolic_target(case.provider, module),
                    case.module_native_target,
                )

    def test_concrete_planned_values_override_symbolic_candidates(self) -> None:
        for case in _CASES:
            with self.subTest(provider=case.provider):
                resources = _loaded_resources(case.fixture)
                concrete = resources[case.concrete_source]
                concrete_resolution = concrete.reference_resolution(
                    *case.relationship_path,
                )

                self.assertEqual(
                    concrete_resolution.state,
                    TerraformReferenceResolutionState.RESOLVED,
                )
                self.assertEqual(
                    concrete_resolution.provenance,
                    TerraformReferenceProvenance.PLANNED_VALUE,
                )
                self.assertEqual(
                    concrete_resolution.planned_value,
                    case.concrete_value,
                )

                # Provider adoption must remain defensive even if a conflicting
                # symbolic candidate reaches it alongside a concrete value.
                reference = f"{case.direct_target}{case.target_suffix}"
                concrete.reference_resolutions = (
                    TerraformReferenceResolution(
                        path=case.relationship_path,
                        state=TerraformReferenceResolutionState.SYMBOLIC,
                        provenance=(TerraformReferenceProvenance.CONFIGURATION_REFERENCE),
                        references=(reference,),
                        targets=(
                            TerraformReferenceTarget(
                                address=case.direct_target,
                                reference=reference,
                            ),
                        ),
                    ),
                )

                inventory = _normalize(case.provider, list(resources.values()))
                normalized = _required_resource(inventory, case.concrete_source)
                self.assertEqual(
                    _native_concrete_value(case.provider, normalized),
                    case.concrete_value,
                )
                self.assertNotEqual(
                    _native_symbolic_target(case.provider, normalized),
                    case.direct_native_target,
                )

    def test_ambiguous_references_fail_closed_without_inventing_public_paths(
        self,
    ) -> None:
        for case in _CASES:
            with self.subTest(provider=case.provider):
                resources = _loaded_resources(case.fixture)
                result = TfStride().analyze_plan(case.fixture)
                ambiguous_resolution = resources[case.ambiguous_source].reference_resolution(*case.relationship_path)
                candidates = {target.address for target in ambiguous_resolution.targets}

                self.assertEqual(
                    ambiguous_resolution.state,
                    TerraformReferenceResolutionState.AMBIGUOUS,
                )
                self.assertGreater(len(candidates), 1)

                ambiguous = _required_resource(
                    result.inventory,
                    case.ambiguous_source,
                )
                self.assertIsNone(
                    _native_symbolic_target(case.provider, ambiguous),
                )

                for source_address in (
                    case.direct_source,
                    case.module_source,
                    case.concrete_source,
                    case.ambiguous_source,
                ):
                    source = _required_resource(result.inventory, source_address)
                    self.assertFalse(source.public_exposure)

                relationship_findings = [
                    finding
                    for finding in result.findings
                    if case.ambiguous_source in finding.affected_resources
                    and _finding_mentions_any(finding, candidates)
                ]
                self.assertEqual(relationship_findings, [])
                self.assertFalse(
                    any(
                        case.ambiguous_source in finding.affected_resources and "-public-" in finding.rule_id
                        for finding in result.findings
                    )
                )

    def test_unknown_relationship_coverage_and_findings_remain_provider_local(
        self,
    ) -> None:
        for case in _CASES:
            with self.subTest(provider=case.provider):
                result = TfStride().analyze_plan(case.fixture)
                coverage = result.analysis_coverage

                self.assertEqual(result.inventory.provider, case.provider)
                self.assertGreater(
                    coverage.resources.plan_time_unknown_resources,
                    0,
                )
                self.assertGreaterEqual(
                    coverage.references.symbolically_resolved_relationships,
                    2,
                )
                self.assertGreaterEqual(
                    coverage.references.ambiguous_symbolic_relationships,
                    1,
                )
                self.assertTrue(
                    all(rule_id.startswith(f"{case.provider}-") for rule_id in coverage.rules.enabled_rules)
                )
                self.assertTrue(all(finding.rule_id.startswith(f"{case.provider}-") for finding in result.findings))


def _loaded_resources(path: Path) -> dict[str, TerraformResource]:
    return {resource.address: resource for resource in load_terraform_plan(path).resources}


def _normalize(
    provider: str,
    resources: list[TerraformResource],
) -> ResourceInventory:
    if provider == "aws":
        return AwsNormalizer().normalize(resources)
    if provider == "gcp":
        return GcpNormalizer().normalize(resources)
    if provider == "azure":
        return AzureNormalizer().normalize(resources)
    raise AssertionError(f"Unsupported parity provider: {provider}")


def _required_resource(
    inventory: ResourceInventory,
    address: str,
) -> NormalizedResource:
    resource = inventory.get_by_address(address)
    if resource is None:
        raise AssertionError(f"Missing normalized resource: {address}")
    return resource


def _assert_symbolic_target(
    test_case: unittest.TestCase,
    resource: TerraformResource,
    path: tuple[str | int, ...],
    expected_target: str,
) -> None:
    resolution = resource.reference_resolution(*path)
    test_case.assertEqual(
        resolution.state,
        TerraformReferenceResolutionState.SYMBOLIC,
    )
    test_case.assertEqual(
        resolution.provenance,
        TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
    )
    test_case.assertEqual(
        [target.address for target in resolution.targets],
        [expected_target],
    )


def _native_symbolic_target(
    provider: str,
    resource: NormalizedResource,
) -> str | None:
    if provider == "aws":
        load_balancers = aws_facts(resource).ecs_load_balancers
        if not load_balancers:
            return None
        return _known_string(load_balancers[0].get("target_group_arn"))
    if provider == "gcp":
        return gcp_facts(resource).pubsub_topic_reference
    if provider == "azure":
        return azure_facts(resource).role_assignment_target_resource_address
    raise AssertionError(f"Unsupported parity provider: {provider}")


def _native_concrete_value(
    provider: str,
    resource: NormalizedResource,
) -> str | None:
    if provider in {"aws", "gcp"}:
        return _native_symbolic_target(provider, resource)
    if provider == "azure":
        return azure_facts(resource).role_assignment_scope
    raise AssertionError(f"Unsupported parity provider: {provider}")


def _finding_mentions_any(
    finding: Finding,
    candidates: set[str],
) -> bool:
    return any(candidate in value for item in finding.evidence for value in item.values for candidate in candidates)


def _known_string(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


if __name__ == "__main__":
    unittest.main()

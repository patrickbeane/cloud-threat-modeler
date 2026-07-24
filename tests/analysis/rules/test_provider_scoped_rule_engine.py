from __future__ import annotations

import unittest
from unittest.mock import patch

from tfstride.analysis.rule_definitions import (
    RuleContribution,
    RuleDefinition,
    RuleEvaluationContext,
)
from tfstride.analysis.rule_registry import default_rule_metadata
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import Finding, ResourceInventory, Severity
from tfstride.providers.plugin import ProviderPluginError

_PROVIDER_RULE_IDS = {
    "aws": "aws-s3-public-access",
    "gcp": "gcp-gcs-uniform-bucket-level-access-disabled",
}


def _inventory(provider: str) -> ResourceInventory:
    return ResourceInventory(provider=provider, resources=[])


class ProviderScopedRuleEngineTests(unittest.TestCase):
    def test_rule_sets_are_cached_independently_across_provider_evaluations(self) -> None:
        detector_calls: list[tuple[str, str]] = []
        evaluation_registries = []

        def contribution_factory(finding_factory, *, provider=None):
            assert provider is not None
            rule_id = _PROVIDER_RULE_IDS[provider]
            metadata = default_rule_metadata(rule_id)

            def detector(context: RuleEvaluationContext, received_rule_id: str) -> list[Finding]:
                detector_calls.append((provider, context.inventory.provider))
                evaluation_registries.append(context.rule_registry)
                return [
                    finding_factory.build(
                        rule_id=received_rule_id,
                        severity=Severity.LOW,
                        affected_resources=[context.inventory.provider],
                        trust_boundary_id=None,
                        rationale=f"{provider} provider-scoped test finding.",
                        evidence=[],
                    )
                ]

            return RuleContribution(((RuleDefinition(metadata, detector),),))

        with patch(
            "tfstride.analysis.stride_rules.default_rule_contribution",
            side_effect=contribution_factory,
        ) as contribution_builder:
            engine = StrideRuleEngine()

            first_aws_findings = engine.evaluate(_inventory("aws"), [])
            aws_rule_set = engine.rule_set_for("aws")
            gcp_findings = engine.evaluate(_inventory("gcp"), [])
            gcp_rule_set = engine.rule_set_for("gcp")
            second_aws_findings = engine.evaluate(_inventory("aws"), [])

        self.assertIsNot(aws_rule_set, gcp_rule_set)
        self.assertIs(engine.rule_set_for(" AWS "), aws_rule_set)
        self.assertIs(engine.rule_set_for("gcp"), gcp_rule_set)
        self.assertEqual(
            [finding.rule_id for finding in first_aws_findings],
            [_PROVIDER_RULE_IDS["aws"]],
        )
        self.assertEqual(
            [finding.rule_id for finding in gcp_findings],
            [_PROVIDER_RULE_IDS["gcp"]],
        )
        self.assertEqual(
            [finding.rule_id for finding in second_aws_findings],
            [_PROVIDER_RULE_IDS["aws"]],
        )
        self.assertEqual(
            detector_calls,
            [("aws", "aws"), ("gcp", "gcp"), ("aws", "aws")],
        )
        self.assertEqual(contribution_builder.call_count, 2)
        self.assertIs(evaluation_registries[0], aws_rule_set.registry)
        self.assertIs(evaluation_registries[1], gcp_rule_set.registry)
        self.assertIs(evaluation_registries[2], aws_rule_set.registry)

    def test_explicit_contribution_remains_unscoped(self) -> None:
        contexts: list[RuleEvaluationContext] = []
        metadata = default_rule_metadata("aws-s3-public-access")

        def detector(context: RuleEvaluationContext, rule_id: str) -> list[Finding]:
            contexts.append(context)
            return []

        contribution = RuleContribution(((RuleDefinition(metadata, detector),),))
        engine = StrideRuleEngine(rule_contribution=contribution)

        with patch("tfstride.analysis.stride_rules.default_rule_contribution") as contribution_builder:
            engine.evaluate(_inventory("custom"), [])
            engine.evaluate(_inventory("gcp"), [])

        custom_rule_set = engine.rule_set_for("custom")
        self.assertIs(custom_rule_set, engine.rule_set_for("gcp"))
        self.assertIsNone(custom_rule_set.provider)
        self.assertEqual([context.inventory.provider for context in contexts], ["custom", "gcp"])
        self.assertTrue(all(context.rule_registry is custom_rule_set.registry for context in contexts))
        contribution_builder.assert_not_called()

    def test_default_engine_rejects_unknown_provider(self) -> None:
        engine = StrideRuleEngine()

        with self.assertRaisesRegex(ProviderPluginError, "No provider plugin registered"):
            engine.rule_set_for("unknown")

        self.assertNotIn("unknown", engine._provider_rule_sets)

    def test_engine_rejects_empty_provider_name(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-empty provider"):
            StrideRuleEngine().rule_set_for(" ")


if __name__ == "__main__":
    unittest.main()

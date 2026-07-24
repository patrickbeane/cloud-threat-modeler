from __future__ import annotations

from dataclasses import dataclass

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.indexes import AnalysisIndexes, build_analysis_indexes
from tfstride.analysis.rule_definitions import (
    BoundaryIndex,
    ExecutableRule,
    RuleContribution,
    RuleDefinition,
    RuleEvaluationContext,
    build_rule_registry_from_contribution,
)
from tfstride.analysis.rule_registry import RulePolicy, RuleRegistry, default_rule_registry
from tfstride.models import Finding, ResourceInventory, TrustBoundary
from tfstride.providers.catalog import default_rule_contribution
from tfstride.providers.names import normalize_provider_name


@dataclass(frozen=True, slots=True)
class ProviderRuleSet:
    provider: str | None
    contribution: RuleContribution
    registry: RuleRegistry


class StrideRuleEngine:
    def __init__(
        self,
        rule_registry: RuleRegistry | None = None,
        rule_contribution: RuleContribution | None = None,
    ) -> None:
        if rule_contribution is not None:
            resolved_registry = _complete_registry(
                build_rule_registry_from_contribution(rule_contribution),
                rule_registry,
            )
            self._explicit_rule_set = ProviderRuleSet(
                provider=None,
                contribution=rule_contribution,
                registry=_active_registry(rule_contribution, resolved_registry),
            )
        else:
            resolved_registry = _complete_registry(default_rule_registry(), rule_registry)
            self._explicit_rule_set = None

        self._rule_registry = resolved_registry
        self._provider_rule_sets: dict[str, ProviderRuleSet] = {}

    def rule_set_for(self, provider: str) -> ProviderRuleSet:
        provider_name = normalize_provider_name(provider)
        if not provider_name:
            raise ValueError("Rule evaluation requires a non-empty provider name.")
        if self._explicit_rule_set is not None:
            return self._explicit_rule_set

        cached = self._provider_rule_sets.get(provider_name)
        if cached is not None:
            return cached

        contribution = default_rule_contribution(
            FindingFactory(self._rule_registry),
            provider=provider_name,
        )
        rule_set = ProviderRuleSet(
            provider=provider_name,
            contribution=contribution,
            registry=_active_registry(contribution, self._rule_registry),
        )
        self._provider_rule_sets[provider_name] = rule_set
        return rule_set

    def evaluate(
        self,
        inventory: ResourceInventory,
        boundaries: list[TrustBoundary],
        *,
        analysis_indexes: AnalysisIndexes | None = None,
        rule_policy: RulePolicy | None = None,
    ) -> list[Finding]:
        rule_set = self.rule_set_for(inventory.provider)
        resolved_indexes = analysis_indexes if analysis_indexes is not None else build_analysis_indexes(inventory)
        boundary_index: BoundaryIndex = {
            (boundary.boundary_type, boundary.source, boundary.target): boundary for boundary in boundaries
        }
        context = RuleEvaluationContext(
            inventory=inventory,
            boundary_index=boundary_index,
            rule_registry=rule_set.registry,
            analysis_indexes=resolved_indexes,
            rule_policy=rule_policy,
        )

        return self._evaluate_contribution(rule_set.contribution, context)

    def _evaluate_contribution(
        self,
        contribution: RuleContribution,
        context: RuleEvaluationContext,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for rules in contribution.rule_groups:
            findings.extend(self._evaluate_rules(rules, context))
        return findings

    def _evaluate_rules(
        self,
        rules: tuple[RuleDefinition, ...],
        context: RuleEvaluationContext,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for definition in rules:
            executable_rule = ExecutableRule(definition.metadata.rule_id, definition.detector)
            findings.extend(executable_rule.evaluate(context))
        return findings

    def _rule_groups(self, provider: str) -> tuple[tuple[RuleDefinition, ...], ...]:
        return self.rule_set_for(provider).contribution.rule_groups


def _complete_registry(
    base_registry: RuleRegistry,
    overrides: RuleRegistry | None,
) -> RuleRegistry:
    if overrides is None:
        return base_registry

    remaining_overrides = {metadata.rule_id: metadata for metadata in overrides.rules()}
    metadata = [remaining_overrides.pop(base.rule_id, base) for base in base_registry.rules()]
    metadata.extend(remaining_overrides.values())
    return RuleRegistry(metadata)


def _active_registry(
    contribution: RuleContribution,
    metadata_registry: RuleRegistry,
) -> RuleRegistry:
    metadata_by_id = {metadata.rule_id: metadata for metadata in metadata_registry.rules()}
    return RuleRegistry(
        [
            metadata_by_id.get(definition.metadata.rule_id, definition.metadata)
            for rule_group in contribution.rule_groups
            for definition in rule_group
        ]
    )

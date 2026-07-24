"""Shared test helpers for tfSTRIDE tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tfstride.analysis.stride_rules import StrideRuleEngine


def engine_configured_rule_ids(
    engine: StrideRuleEngine,
    provider: str | None = None,
) -> set[str]:
    """Extract one provider or the complete built-in executable rule ID set."""
    from tfstride.providers.catalog import default_provider_plugins

    providers = (provider,) if provider is not None else tuple(plugin.provider for plugin in default_provider_plugins())
    return {
        rule.metadata.rule_id
        for provider_name in providers
        for rule_group in engine._rule_groups(provider_name)
        for rule in rule_group
    }

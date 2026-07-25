from __future__ import annotations

from tfstride.providers.azure.resource_facts import AzureResourceFacts
from tfstride.providers.coercion import STATE_CONFIGURED, STATE_UNKNOWN
from tfstride.providers.network_ranges import is_broad_public_range

COSMOSDB_NETWORK_RESTRICTION_RESTRICTED = "restricted"
COSMOSDB_NETWORK_RESTRICTION_UNKNOWN = "unknown"
COSMOSDB_NETWORK_RESTRICTION_UNRESTRICTED = "unrestricted"
_COSMOSDB_BROAD_IP_FILTER_VALUES = frozenset({"0.0.0.0"})


def cosmosdb_network_restriction_state(facts: AzureResourceFacts) -> str:
    ip_ranges = facts.cosmosdb_ip_range_filter
    if any(_is_broad_cosmosdb_ip_filter(ip_range) for ip_range in ip_ranges):
        return COSMOSDB_NETWORK_RESTRICTION_UNRESTRICTED
    if facts.cosmosdb_ip_range_filter_state == STATE_UNKNOWN:
        return COSMOSDB_NETWORK_RESTRICTION_UNKNOWN
    if facts.cosmosdb_ip_range_filter_state == STATE_CONFIGURED and ip_ranges:
        return COSMOSDB_NETWORK_RESTRICTION_RESTRICTED
    if facts.cosmosdb_virtual_network_filter_enabled is True:
        return COSMOSDB_NETWORK_RESTRICTION_RESTRICTED
    if STATE_UNKNOWN in {
        facts.cosmosdb_virtual_network_filter_state,
        facts.cosmosdb_virtual_network_rule_state,
    }:
        return COSMOSDB_NETWORK_RESTRICTION_UNKNOWN
    return COSMOSDB_NETWORK_RESTRICTION_UNRESTRICTED


def _is_broad_cosmosdb_ip_filter(value: object) -> bool:
    normalized = str(value or "").strip().lower()
    return normalized in _COSMOSDB_BROAD_IP_FILTER_VALUES or is_broad_public_range(value)


def cosmosdb_network_restriction_evidence(facts: AzureResourceFacts) -> list[str]:
    values = [f"network_restriction_state={cosmosdb_network_restriction_state(facts)}"]
    values.append(f"ip_range_filter_state={facts.cosmosdb_ip_range_filter_state or 'unknown'}")
    if facts.cosmosdb_ip_range_filter:
        values.append(f"ip_range_filter={', '.join(facts.cosmosdb_ip_range_filter)}")
    values.append(f"virtual_network_filter_state={facts.cosmosdb_virtual_network_filter_state or 'unknown'}")
    values.append(f"virtual_network_filter_enabled is {_bool_evidence(facts.cosmosdb_virtual_network_filter_enabled)}")
    values.append(f"virtual_network_rule_state={facts.cosmosdb_virtual_network_rule_state or 'unknown'}")
    for rule in facts.cosmosdb_virtual_network_rules:
        subnet_id = rule.get("subnet_id")
        if subnet_id:
            values.append(f"virtual_network_rule subnet_id={subnet_id}")
    values.append(f"network_acl_bypass_state={facts.cosmosdb_network_acl_bypass_state or 'unknown'}")
    values.append(
        f"network_acl_bypass_for_azure_services is {_bool_evidence(facts.cosmosdb_network_acl_bypass_enabled)}"
    )
    if facts.cosmosdb_network_acl_bypass_ids:
        values.append(f"network_acl_bypass_ids={', '.join(facts.cosmosdb_network_acl_bypass_ids)}")
    return values


def _bool_evidence(value: bool | None) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "unknown"

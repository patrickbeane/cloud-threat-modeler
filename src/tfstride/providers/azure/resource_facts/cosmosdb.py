from __future__ import annotations

from typing import Any

from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_facts.base import AzureBaseFacts
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
)


class AzureCosmosDbFacts(AzureBaseFacts):
    __slots__ = ()

    @property
    def cosmosdb_account_id(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_ACCOUNT_ID)

    @property
    def cosmosdb_kind(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_KIND)

    @property
    def cosmosdb_offer_type(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_OFFER_TYPE)

    @property
    def cosmosdb_customer_managed_key_state(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_CUSTOMER_MANAGED_KEY_STATE)

    @property
    def cosmosdb_customer_managed_encryption(self) -> bool | None:
        state = self.cosmosdb_customer_managed_key_state
        if state == STATE_CONFIGURED:
            return True
        if state == STATE_NOT_CONFIGURED:
            return False
        return None

    @property
    def cosmosdb_key_vault_key_id(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_KEY_VAULT_KEY_ID)

    @property
    def cosmosdb_default_identity_type(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_DEFAULT_IDENTITY_TYPE)

    @property
    def cosmosdb_backup_configuration_state(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_BACKUP_CONFIGURATION_STATE)

    @property
    def cosmosdb_backup_block_configured(self) -> bool | None:
        if self.cosmosdb_backup_configuration_state == STATE_CONFIGURED:
            return True
        if self.cosmosdb_backup_configuration_state == STATE_NOT_CONFIGURED:
            return False
        return None

    @property
    def cosmosdb_backup_type(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_BACKUP_TYPE)

    @property
    def cosmosdb_backup_tier(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_BACKUP_TIER)

    @property
    def cosmosdb_backup_interval_minutes(self) -> int | None:
        return self.get(AzureResourceMetadata.COSMOSDB_BACKUP_INTERVAL_MINUTES)

    @property
    def cosmosdb_backup_retention_hours(self) -> int | None:
        return self.get(AzureResourceMetadata.COSMOSDB_BACKUP_RETENTION_HOURS)

    @property
    def cosmosdb_backup_storage_redundancy(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_BACKUP_STORAGE_REDUNDANCY)

    @property
    def cosmosdb_public_network_access_enabled(self) -> bool | None:
        return self.public_network_access_enabled

    @property
    def cosmosdb_public_network_access_state(self) -> str:
        return self.public_network_fallback_state

    @property
    def cosmosdb_minimal_tls_version(self) -> str | None:
        return self.min_tls_version

    @property
    def cosmosdb_ip_range_filter_state(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_IP_RANGE_FILTER_STATE)

    @property
    def cosmosdb_ip_range_filter(self) -> list[str]:
        return self.get(AzureResourceMetadata.COSMOSDB_IP_RANGE_FILTER)

    @property
    def cosmosdb_virtual_network_filter_state(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_VIRTUAL_NETWORK_FILTER_STATE)

    @property
    def cosmosdb_virtual_network_filter_enabled(self) -> bool | None:
        return _bool_from_state(self.cosmosdb_virtual_network_filter_state)

    @property
    def cosmosdb_virtual_network_rule_state(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_VIRTUAL_NETWORK_RULE_STATE)

    @property
    def cosmosdb_virtual_network_rules(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.COSMOSDB_VIRTUAL_NETWORK_RULES)

    @property
    def cosmosdb_network_acl_bypass_state(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_NETWORK_ACL_BYPASS_STATE)

    @property
    def cosmosdb_network_acl_bypass_enabled(self) -> bool | None:
        return _bool_from_state(self.cosmosdb_network_acl_bypass_state)

    @property
    def cosmosdb_network_acl_bypass_ids_state(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_NETWORK_ACL_BYPASS_IDS_STATE)

    @property
    def cosmosdb_network_acl_bypass_ids(self) -> list[str]:
        return self.get(AzureResourceMetadata.COSMOSDB_NETWORK_ACL_BYPASS_IDS)

    @property
    def cosmosdb_local_authentication_state(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_LOCAL_AUTHENTICATION_STATE)

    @property
    def cosmosdb_local_authentication_enabled(self) -> bool | None:
        return _bool_from_state(self.cosmosdb_local_authentication_state)

    @property
    def cosmosdb_automatic_failover_state(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_AUTOMATIC_FAILOVER_STATE)

    @property
    def cosmosdb_automatic_failover_enabled(self) -> bool | None:
        return _bool_from_state(self.cosmosdb_automatic_failover_state)

    @property
    def cosmosdb_multiple_write_locations_state(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_MULTIPLE_WRITE_LOCATIONS_STATE)

    @property
    def cosmosdb_multiple_write_locations_enabled(self) -> bool | None:
        return _bool_from_state(self.cosmosdb_multiple_write_locations_state)

    @property
    def cosmosdb_geo_location_state(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_GEO_LOCATION_STATE)

    @property
    def cosmosdb_geo_locations(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.COSMOSDB_GEO_LOCATIONS)

    @property
    def cosmosdb_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.COSMOSDB_POSTURE_UNCERTAINTIES)


def _bool_from_state(state: str | None) -> bool | None:
    if state == STATE_ENABLED:
        return True
    if state == STATE_DISABLED:
        return False
    return None

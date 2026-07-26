from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.identity_normalizers import managed_identity_metadata
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.public_network import public_network_fallback_state
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_utils import (
    as_list,
    attribute_unknown,
    block_attribute_unknown,
    first_mapping,
    known_block_bool,
    known_block_int,
    known_bool,
    known_string,
    unknown_block_at,
    value_is_unknown,
)
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
    bool_state,
)

AZURE_PROVIDER = "azure"
_DEFAULT_BACKUP_INTERVAL_MINUTES = 240
_DEFAULT_BACKUP_RETENTION_HOURS = 8
_DEFAULT_BACKUP_STORAGE_REDUNDANCY = "Geo"
_DEFAULT_BACKUP_TYPE = "Periodic"
_DEFAULT_IDENTITY_TYPE = "FirstPartyIdentity"
_DEFAULT_KIND = "GlobalDocumentDB"
_DEFAULT_MINIMAL_TLS_VERSION = "Tls12"


def normalize_cosmosdb_account(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    account_id = known_string(values, resource.unknown_values, "id", uncertainties, require_string=True)
    name = known_string(values, resource.unknown_values, "name", uncertainties, require_string=True)
    resource_group_name = known_string(
        values,
        resource.unknown_values,
        "resource_group_name",
        uncertainties,
        require_string=True,
    )
    public_network_access_enabled = _known_bool_with_default(
        resource,
        "public_network_access_enabled",
        uncertainties,
        default=True,
    )
    key_vault_key_id, cmk_state = _customer_managed_key_posture(resource, uncertainties)
    backup = _backup_posture(resource, uncertainties)
    ip_ranges, ip_range_state = _string_list_posture(resource, "ip_range_filter", uncertainties)
    network_bypass_ids, network_bypass_ids_state = _string_list_posture(
        resource,
        "network_acl_bypass_ids",
        uncertainties,
    )
    virtual_network_rules, virtual_network_rule_state = _virtual_network_rules(resource, uncertainties)
    geo_locations, geo_location_state = _geo_locations(resource, uncertainties)

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: name or resource.name,
        AzureResourceMetadata.COSMOSDB_ACCOUNT_NAME: name,
        AzureResourceMetadata.COSMOSDB_RESOURCE_GROUP_NAME: resource_group_name,
        AzureResourceMetadata.LOCATION: known_string(
            values,
            resource.unknown_values,
            "location",
            uncertainties,
            require_string=True,
        ),
        AzureResourceMetadata.COSMOSDB_ACCOUNT_ID: account_id,
        AzureResourceMetadata.COSMOSDB_KIND: _known_string_with_default(
            resource,
            "kind",
            uncertainties,
            default=_DEFAULT_KIND,
        ),
        AzureResourceMetadata.COSMOSDB_OFFER_TYPE: known_string(
            values,
            resource.unknown_values,
            "offer_type",
            uncertainties,
            require_string=True,
        ),
        AzureResourceMetadata.COSMOSDB_CUSTOMER_MANAGED_KEY_STATE: cmk_state,
        AzureResourceMetadata.COSMOSDB_KEY_VAULT_KEY_ID: key_vault_key_id,
        AzureResourceMetadata.COSMOSDB_DEFAULT_IDENTITY_TYPE: _known_string_with_default(
            resource,
            "default_identity_type",
            uncertainties,
            default=_DEFAULT_IDENTITY_TYPE,
        ),
        AzureResourceMetadata.COSMOSDB_BACKUP_CONFIGURATION_STATE: backup["configuration_state"],
        AzureResourceMetadata.COSMOSDB_BACKUP_TYPE: backup["type"],
        AzureResourceMetadata.COSMOSDB_BACKUP_TIER: backup["tier"],
        AzureResourceMetadata.COSMOSDB_BACKUP_INTERVAL_MINUTES: backup["interval_in_minutes"],
        AzureResourceMetadata.COSMOSDB_BACKUP_RETENTION_HOURS: backup["retention_in_hours"],
        AzureResourceMetadata.COSMOSDB_BACKUP_STORAGE_REDUNDANCY: backup["storage_redundancy"],
        AzureResourceMetadata.PUBLIC_NETWORK_FALLBACK_STATE: public_network_fallback_state(
            public_network_access_enabled
        ),
        AzureResourceMetadata.COSMOSDB_IP_RANGE_FILTER_STATE: ip_range_state,
        AzureResourceMetadata.COSMOSDB_IP_RANGE_FILTER: ip_ranges,
        AzureResourceMetadata.COSMOSDB_VIRTUAL_NETWORK_FILTER_STATE: _optional_bool_state(
            resource,
            "is_virtual_network_filter_enabled",
            uncertainties,
        ),
        AzureResourceMetadata.COSMOSDB_VIRTUAL_NETWORK_RULE_STATE: virtual_network_rule_state,
        AzureResourceMetadata.COSMOSDB_VIRTUAL_NETWORK_RULES: virtual_network_rules,
        AzureResourceMetadata.COSMOSDB_NETWORK_ACL_BYPASS_STATE: _optional_bool_state(
            resource,
            "network_acl_bypass_for_azure_services",
            uncertainties,
            default=False,
        ),
        AzureResourceMetadata.COSMOSDB_NETWORK_ACL_BYPASS_IDS_STATE: network_bypass_ids_state,
        AzureResourceMetadata.COSMOSDB_NETWORK_ACL_BYPASS_IDS: network_bypass_ids,
        AzureResourceMetadata.COSMOSDB_LOCAL_AUTHENTICATION_STATE: _local_authentication_state(resource, uncertainties),
        AzureResourceMetadata.COSMOSDB_AUTOMATIC_FAILOVER_STATE: _optional_bool_state(
            resource,
            "automatic_failover_enabled",
            uncertainties,
        ),
        AzureResourceMetadata.COSMOSDB_MULTIPLE_WRITE_LOCATIONS_STATE: _optional_bool_state(
            resource,
            "multiple_write_locations_enabled",
            uncertainties,
        ),
        AzureResourceMetadata.COSMOSDB_GEO_LOCATION_STATE: geo_location_state,
        AzureResourceMetadata.COSMOSDB_GEO_LOCATIONS: geo_locations,
    }
    if public_network_access_enabled is not None:
        metadata[AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED] = public_network_access_enabled
    minimal_tls_version = _known_string_with_default(
        resource,
        "minimal_tls_version",
        uncertainties,
        default=_DEFAULT_MINIMAL_TLS_VERSION,
    )
    if minimal_tls_version is not None:
        metadata[AzureResourceMetadata.MIN_TLS_VERSION] = minimal_tls_version
    metadata.update(managed_identity_metadata(resource))
    if uncertainties:
        metadata[AzureResourceMetadata.COSMOSDB_POSTURE_UNCERTAINTIES] = uncertainties

    normalized = NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=account_id or name or resource.address,
        data_sensitivity="sensitive",
        metadata=metadata,
    )
    azure_facts(normalized).set_storage_encrypted(True)
    return normalized


def _customer_managed_key_posture(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[str | None, str]:
    before = len(uncertainties)
    key_vault_key_id = known_string(
        resource.values,
        resource.unknown_values,
        "key_vault_key_id",
        uncertainties,
        require_string=True,
    )
    if key_vault_key_id:
        return key_vault_key_id, STATE_CONFIGURED
    if len(uncertainties) > before:
        return None, STATE_UNKNOWN
    return None, STATE_NOT_CONFIGURED


def _backup_posture(resource: TerraformResource, uncertainties: list[str]) -> dict[str, Any]:
    raw_backup = resource.values.get("backup")
    unknown_backup = resource.unknown_values.get("backup")
    if unknown_backup is True:
        uncertainties.append("backup is unknown after planning")
        return _empty_backup(STATE_UNKNOWN)
    if raw_backup in (None, [], {}):
        if value_is_unknown(unknown_backup):
            uncertainties.append("backup is unknown after planning")
            return _empty_backup(STATE_UNKNOWN)
        return _default_periodic_backup(STATE_NOT_CONFIGURED)

    backup = first_mapping(raw_backup)
    if backup is None:
        uncertainties.append("backup has an unrecognized value shape")
        return _empty_backup(STATE_UNKNOWN)

    unknown_block = unknown_block_at(unknown_backup, 0)
    before = len(uncertainties)
    backup_type = _known_block_string(backup, unknown_block, "type", uncertainties, path="backup")
    if backup_type is None and len(uncertainties) == before:
        uncertainties.append("backup.type is not represented in planned values")
    tier = _known_block_string(backup, unknown_block, "tier", uncertainties, path="backup")
    if backup_type and backup_type.casefold() == _DEFAULT_BACKUP_TYPE.casefold():
        interval = _known_block_int_with_default(
            backup,
            unknown_block,
            "interval_in_minutes",
            uncertainties,
            path="backup",
            default=_DEFAULT_BACKUP_INTERVAL_MINUTES,
        )
        retention = _known_block_int_with_default(
            backup,
            unknown_block,
            "retention_in_hours",
            uncertainties,
            path="backup",
            default=_DEFAULT_BACKUP_RETENTION_HOURS,
        )
        redundancy = _known_block_string_with_default(
            backup,
            unknown_block,
            "storage_redundancy",
            uncertainties,
            path="backup",
            default=_DEFAULT_BACKUP_STORAGE_REDUNDANCY,
        )
    else:
        interval = known_block_int(
            backup,
            unknown_block,
            "interval_in_minutes",
            uncertainties,
            path="backup",
        )
        retention = known_block_int(
            backup,
            unknown_block,
            "retention_in_hours",
            uncertainties,
            path="backup",
        )
        redundancy = _known_block_string(
            backup,
            unknown_block,
            "storage_redundancy",
            uncertainties,
            path="backup",
        )
    return {
        "configuration_state": STATE_CONFIGURED,
        "type": backup_type,
        "tier": tier,
        "interval_in_minutes": interval,
        "retention_in_hours": retention,
        "storage_redundancy": redundancy,
    }


def _empty_backup(configuration_state: str) -> dict[str, Any]:
    return {
        "configuration_state": configuration_state,
        "type": None,
        "tier": None,
        "interval_in_minutes": None,
        "retention_in_hours": None,
        "storage_redundancy": None,
    }


def _default_periodic_backup(configuration_state: str) -> dict[str, Any]:
    return {
        "configuration_state": configuration_state,
        "type": _DEFAULT_BACKUP_TYPE,
        "tier": None,
        "interval_in_minutes": _DEFAULT_BACKUP_INTERVAL_MINUTES,
        "retention_in_hours": _DEFAULT_BACKUP_RETENTION_HOURS,
        "storage_redundancy": _DEFAULT_BACKUP_STORAGE_REDUNDANCY,
    }


def _string_list_posture(
    resource: TerraformResource,
    key: str,
    uncertainties: list[str],
) -> tuple[list[str], str]:
    if attribute_unknown(resource.unknown_values, key):
        uncertainties.append(f"{key} is unknown after planning")
        return [], STATE_UNKNOWN
    if key not in resource.values or resource.values[key] in (None, []):
        return [], STATE_NOT_CONFIGURED
    raw_values = resource.values[key]
    if not isinstance(raw_values, (list, tuple)):
        uncertainties.append(f"{key} has an unrecognized value shape")
        return [], STATE_UNKNOWN
    values: list[str] = []
    invalid = False
    for index, item in enumerate(raw_values):
        if not isinstance(item, str):
            uncertainties.append(f"{key}[{index}] has an unrecognized value shape")
            invalid = True
            continue
        value = item.strip()
        if value:
            values.append(value)
    return sorted(set(values)), STATE_UNKNOWN if invalid else (STATE_CONFIGURED if values else STATE_NOT_CONFIGURED)


def _virtual_network_rules(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[list[dict[str, Any]], str]:
    return _block_records(
        resource,
        "virtual_network_rule",
        uncertainties,
        _virtual_network_rule_record,
        sort_key=lambda record: str(record.get("subnet_id") or ""),
    )


def _virtual_network_rule_record(
    block: Mapping[str, Any],
    unknown_block: Any,
    index: int,
    uncertainties: list[str],
) -> dict[str, Any]:
    path = f"virtual_network_rule[{index}]"
    subnet_id = _known_block_string(block, unknown_block, "id", uncertainties, path=path)
    ignore_missing_endpoint = known_block_bool(
        block,
        unknown_block,
        "ignore_missing_vnet_service_endpoint",
        uncertainties,
        path=path,
    )
    record: dict[str, Any] = {}
    if subnet_id:
        record["subnet_id"] = subnet_id
    if ignore_missing_endpoint is not None:
        record["ignore_missing_vnet_service_endpoint"] = ignore_missing_endpoint
    if subnet_id is None and not any(f"{path}.id" in item for item in uncertainties):
        uncertainties.append(f"{path}.id is not represented in planned values")
    return record


def _geo_locations(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[list[dict[str, Any]], str]:
    return _block_records(
        resource,
        "geo_location",
        uncertainties,
        _geo_location_record,
        sort_key=lambda record: (
            record.get("failover_priority") if isinstance(record.get("failover_priority"), int) else 2**31,
            str(record.get("location") or ""),
        ),
    )


def _geo_location_record(
    block: Mapping[str, Any],
    unknown_block: Any,
    index: int,
    uncertainties: list[str],
) -> dict[str, Any]:
    path = f"geo_location[{index}]"
    location = _known_block_string(block, unknown_block, "location", uncertainties, path=path)
    failover_priority = known_block_int(
        block,
        unknown_block,
        "failover_priority",
        uncertainties,
        path=path,
    )
    zone_redundant = known_block_bool(
        block,
        unknown_block,
        "zone_redundant",
        uncertainties,
        path=path,
    )
    record: dict[str, Any] = {}
    if location:
        record["location"] = location
    if failover_priority is not None:
        record["failover_priority"] = failover_priority
    if zone_redundant is not None:
        record["zone_redundant"] = zone_redundant
    for field, value in (("location", location), ("failover_priority", failover_priority)):
        if value is None and not any(f"{path}.{field}" in item for item in uncertainties):
            uncertainties.append(f"{path}.{field} is not represented in planned values")
    return record


def _block_records(
    resource: TerraformResource,
    key: str,
    uncertainties: list[str],
    record_factory: Callable[[Mapping[str, Any], Any, int, list[str]], dict[str, Any]],
    *,
    sort_key: Callable[[dict[str, Any]], Any],
) -> tuple[list[dict[str, Any]], str]:
    raw_values = resource.values.get(key)
    unknown_values = resource.unknown_values.get(key)
    if unknown_values is True:
        uncertainties.append(f"{key} is unknown after planning")
        return [], STATE_UNKNOWN
    if key not in resource.values or raw_values in (None, []):
        return [], STATE_NOT_CONFIGURED

    before = len(uncertainties)
    records: list[dict[str, Any]] = []
    for index, item in enumerate(as_list(raw_values)):
        if not isinstance(item, Mapping):
            uncertainties.append(f"{key}[{index}] has an unrecognized value shape")
            continue
        record = record_factory(item, unknown_block_at(unknown_values, index), index, uncertainties)
        if record:
            records.append(record)
    records.sort(key=sort_key)
    if len(uncertainties) > before:
        return records, STATE_UNKNOWN
    return records, STATE_CONFIGURED if records else STATE_NOT_CONFIGURED


def _optional_bool_state(
    resource: TerraformResource,
    key: str,
    uncertainties: list[str],
    *,
    default: bool | None = None,
) -> str:
    before = len(uncertainties)
    value = known_bool(
        resource.values,
        resource.unknown_values,
        key,
        uncertainties,
        allow_string=False,
    )
    if value is not None:
        return bool_state(value)
    if len(uncertainties) > before:
        return STATE_UNKNOWN
    if default is not None:
        return bool_state(default)
    return STATE_NOT_CONFIGURED


def _local_authentication_state(
    resource: TerraformResource,
    uncertainties: list[str],
) -> str:
    if _attribute_represented(resource, "local_authentication_enabled"):
        return _optional_bool_state(
            resource,
            "local_authentication_enabled",
            uncertainties,
            default=True,
        )
    if _attribute_represented(resource, "local_authentication_disabled"):
        before = len(uncertainties)
        disabled = known_bool(
            resource.values,
            resource.unknown_values,
            "local_authentication_disabled",
            uncertainties,
            allow_string=False,
        )
        if disabled is not None:
            return bool_state(not disabled)
        if len(uncertainties) > before:
            return STATE_UNKNOWN
    return bool_state(True)


def _attribute_represented(resource: TerraformResource, key: str) -> bool:
    return key in resource.values or key in resource.unknown_values


def _known_bool_with_default(
    resource: TerraformResource,
    key: str,
    uncertainties: list[str],
    *,
    default: bool,
) -> bool | None:
    before = len(uncertainties)
    value = known_bool(
        resource.values,
        resource.unknown_values,
        key,
        uncertainties,
        allow_string=False,
    )
    if value is not None:
        return value
    if len(uncertainties) > before:
        return None
    return default


def _known_string_with_default(
    resource: TerraformResource,
    key: str,
    uncertainties: list[str],
    *,
    default: str,
) -> str | None:
    before = len(uncertainties)
    value = known_string(
        resource.values,
        resource.unknown_values,
        key,
        uncertainties,
        require_string=True,
    )
    if value is not None:
        return value
    if len(uncertainties) > before:
        return None
    return default


def _known_block_int_with_default(
    values: Mapping[str, Any],
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
    default: int,
) -> int | None:
    before = len(uncertainties)
    value = known_block_int(values, unknown_block, key, uncertainties, path=path)
    if value is not None:
        return value
    if len(uncertainties) > before:
        return None
    return default


def _known_block_string_with_default(
    values: Mapping[str, Any],
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
    default: str,
) -> str | None:
    before = len(uncertainties)
    value = _known_block_string(values, unknown_block, key, uncertainties, path=path)
    if value is not None:
        return value
    if len(uncertainties) > before:
        return None
    return default


def _known_block_string(
    values: Mapping[str, Any],
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
) -> str | None:
    if block_attribute_unknown(unknown_block, key):
        uncertainties.append(f"{path}.{key} is unknown after planning")
        return None
    raw_value = values.get(key)
    if raw_value is None:
        return None
    if not isinstance(raw_value, str):
        uncertainties.append(f"{path}.{key} has an unrecognized value shape")
        return None
    value = raw_value.strip()
    return value or None

from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_utils import (
    as_optional_int,
    attribute_unknown,
    bool_state,
    known_bool,
    known_string,
)

AZURE_PROVIDER = "azure"


def normalize_servicebus_queue(resource: TerraformResource) -> NormalizedResource:
    return _normalize_entity(resource, "queue")


def normalize_servicebus_topic(resource: TerraformResource) -> NormalizedResource:
    return _normalize_entity(resource, "topic")


def normalize_servicebus_subscription(resource: TerraformResource) -> NormalizedResource:
    return _normalize_entity(
        resource,
        "subscription",
        namespace_reference_key=None,
        topic_reference_key="topic_id",
    )


def _normalize_entity(
    resource: TerraformResource,
    entity_kind: str,
    *,
    namespace_reference_key: str | None = "namespace_id",
    topic_reference_key: str | None = None,
) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    entity_id = _required_string(resource, "id", uncertainties)
    entity_name = known_string(
        values,
        resource.unknown_values,
        "name",
        uncertainties,
        require_string=True,
    )
    entity_status = known_string(
        values,
        resource.unknown_values,
        "status",
        uncertainties,
        require_string=True,
    )
    if entity_status is None and not attribute_unknown(resource.unknown_values, "status"):
        if values.get("status") is None:
            entity_status = "Active"
        else:
            uncertainties.append("status has an unrecognized value shape")
    forward_to = known_string(
        values,
        resource.unknown_values,
        "forward_to",
        uncertainties,
        require_string=True,
    )
    if attribute_unknown(resource.unknown_values, "forward_to"):
        auto_forwarding_state = "unknown"
    elif forward_to is not None:
        auto_forwarding_state = "configured"
    elif values.get("forward_to") is None:
        auto_forwarding_state = "not_configured"
    else:
        uncertainties.append("forward_to has an unrecognized value shape")
        auto_forwarding_state = "unknown"
    namespace_reference = (
        _required_string(resource, namespace_reference_key, uncertainties)
        if namespace_reference_key is not None
        else None
    )
    topic_reference = (
        _required_string(resource, topic_reference_key, uncertainties) if topic_reference_key is not None else None
    )
    default_message_time_to_live = known_string(
        values,
        resource.unknown_values,
        "default_message_ttl",
        uncertainties,
        require_string=True,
    )
    lock_duration = known_string(
        values,
        resource.unknown_values,
        "lock_duration",
        uncertainties,
        require_string=True,
    )
    max_delivery_count = _optional_int(
        resource,
        "max_delivery_count",
        uncertainties,
    )
    dead_lettering_on_message_expiration = known_bool(
        values,
        resource.unknown_values,
        "dead_lettering_on_message_expiration",
        uncertainties,
        allow_string=False,
    )

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: entity_name or resource.name,
        AzureResourceMetadata.SERVICE_BUS_ENTITY_ID: entity_id,
        AzureResourceMetadata.SERVICE_BUS_ENTITY_NAME: entity_name,
        AzureResourceMetadata.SERVICE_BUS_ENTITY_KIND: entity_kind,
        AzureResourceMetadata.SERVICE_BUS_ENTITY_STATUS: entity_status,
        AzureResourceMetadata.SERVICE_BUS_AUTO_FORWARDING_STATE: auto_forwarding_state,
        AzureResourceMetadata.SERVICE_BUS_FORWARD_TO: forward_to,
        AzureResourceMetadata.SERVICE_BUS_DEFAULT_MESSAGE_TIME_TO_LIVE: (default_message_time_to_live),
        AzureResourceMetadata.SERVICE_BUS_LOCK_DURATION: lock_duration,
        AzureResourceMetadata.SERVICE_BUS_MAX_DELIVERY_COUNT: max_delivery_count,
        AzureResourceMetadata.SERVICE_BUS_DEAD_LETTERING_ON_MESSAGE_EXPIRATION_STATE: (
            bool_state(dead_lettering_on_message_expiration)
        ),
        AzureResourceMetadata.SERVICE_BUS_NAMESPACE_REFERENCE: namespace_reference,
        AzureResourceMetadata.SERVICE_BUS_TOPIC_REFERENCE: topic_reference,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.SERVICE_BUS_POSTURE_UNCERTAINTIES] = uncertainties

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=entity_id or resource.address,
        data_sensitivity="sensitive",
        metadata=metadata,
    )


def _required_string(resource: TerraformResource, key: str, uncertainties: list[str]) -> str | None:
    before = len(uncertainties)
    value = known_string(
        resource.values,
        resource.unknown_values,
        key,
        uncertainties,
        require_string=True,
    )
    if value is None and len(uncertainties) == before:
        uncertainties.append(f"{key} is not represented in planned values")
    return value


def _optional_int(
    resource: TerraformResource,
    key: str,
    uncertainties: list[str],
) -> int | None:
    if attribute_unknown(resource.unknown_values, key):
        uncertainties.append(f"{key} is unknown after planning")
        return None
    raw = resource.values.get(key)
    if raw is None:
        return None
    if isinstance(raw, bool):
        uncertainties.append(f"{key} has an unrecognized value shape")
        return None
    value = as_optional_int(raw)
    if value is None:
        uncertainties.append(f"{key} has an unrecognized value shape")
    return value

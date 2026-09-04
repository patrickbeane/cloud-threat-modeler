from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping
from typing import Any, cast

from tfstride.models import NormalizedResource, ResourceInventory, TerraformResource
from tfstride.resource_metadata import InventoryMetadata, MetadataField

ResourceNormalizer = Callable[[TerraformResource], NormalizedResource]
ResourceOwnershipPredicate = Callable[[TerraformResource], bool]
ResourceDecorationHook = Callable[[list[NormalizedResource]], None]
InventoryMetadataEnrichmentHook = Callable[[list[NormalizedResource], dict[str, Any]], None]


def normalize_provider_inventory(
    resources: list[TerraformResource],
    *,
    provider: str,
    owns_resource: ResourceOwnershipPredicate,
    resource_normalizers: Mapping[str, ResourceNormalizer],
    decorate_resources: ResourceDecorationHook,
    enrich_inventory_metadata: InventoryMetadataEnrichmentHook | None = None,
) -> ResourceInventory:
    """Run the provider-neutral resource-to-inventory normalization pipeline."""
    provider_resources = [resource for resource in resources if owns_resource(resource)]
    supported_resource_types = frozenset(resource_normalizers)
    unsupported_resource_types = Counter(
        resource.resource_type
        for resource in provider_resources
        if resource.resource_type not in supported_resource_types
    )
    unsupported_resources = sorted(
        resource.address for resource in provider_resources if resource.resource_type not in supported_resource_types
    )

    normalized_resources: list[NormalizedResource] = []
    for resource in provider_resources:
        resource_normalizer = resource_normalizers.get(resource.resource_type)
        if resource_normalizer is None:
            continue
        normalized_resource = resource_normalizer(resource)
        normalized_resource.provider_config_key = resource.provider_config_key
        normalized_resource.reference_resolutions = resource.reference_resolutions
        normalized_resources.append(normalized_resource)

    decorate_resources(normalized_resources)
    for resource in normalized_resources:
        resource.freeze_decoration_state()

    metadata: dict[str, Any] = {}
    if enrich_inventory_metadata is not None:
        enrich_inventory_metadata(normalized_resources, metadata)
    InventoryMetadata.SUPPORTED_RESOURCE_TYPES.set(metadata, sorted(supported_resource_types))
    InventoryMetadata.TOTAL_INPUT_RESOURCES.set(metadata, len(resources))
    InventoryMetadata.PROVIDER_RESOURCE_COUNT.set(metadata, len(provider_resources))
    InventoryMetadata.NORMALIZED_RESOURCE_COUNT.set(metadata, len(normalized_resources))
    InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.set(
        metadata,
        dict(sorted(unsupported_resource_types.items())),
    )

    return ResourceInventory(
        provider=provider,
        resources=normalized_resources,
        unsupported_resources=unsupported_resources,
        metadata=cast(Mapping[str | MetadataField[Any], Any], metadata),
    )

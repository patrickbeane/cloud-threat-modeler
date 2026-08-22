from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_utils import first_non_empty, known_string

AZURE_PROVIDER = "azure"


def normalize_management_lock(resource: TerraformResource) -> NormalizedResource:
    uncertainties: list[str] = []
    scope = known_string(
        resource.values,
        resource.unknown_values,
        "scope",
        uncertainties,
        require_string=True,
    )
    lock_level = known_string(
        resource.values,
        resource.unknown_values,
        "lock_level",
        uncertainties,
        require_string=True,
    )
    if scope is None and not any(uncertainty.startswith("scope ") for uncertainty in uncertainties):
        uncertainties.append("scope is not represented in planned values")
    if lock_level is None and not any(uncertainty.startswith("lock_level ") for uncertainty in uncertainties):
        uncertainties.append("lock_level is not represented in planned values")

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: first_non_empty(resource.values.get("name"), resource.name),
        AzureResourceMetadata.MANAGEMENT_LOCK_SCOPE: scope,
        AzureResourceMetadata.MANAGEMENT_LOCK_LEVEL: lock_level,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.MANAGEMENT_LOCK_UNCERTAINTIES] = uncertainties

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(resource.values.get("id"), resource.address),
        metadata=metadata,
    )

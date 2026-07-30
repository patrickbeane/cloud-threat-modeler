from __future__ import annotations

from collections.abc import Collection

from tfstride.models import NormalizedResource, TerraformReferenceProvenance, TerraformReferenceResolutionState
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType
from tfstride.providers.azure.resource_utils import azure_reference_key, azure_resource_references
from tfstride.providers.coercion import STATE_CONFIGURED
from tfstride.resource_metadata import StringListMetadataField

_PRIVATE_ENDPOINT_TARGET_TYPES = frozenset(
    {
        AzureResourceType.STORAGE_ACCOUNT,
        AzureResourceType.KEY_VAULT,
        AzureResourceType.MSSQL_SERVER,
        AzureResourceType.SERVICE_BUS_NAMESPACE,
        AzureResourceType.CONTAINER_REGISTRY,
        AzureResourceType.COSMOSDB_ACCOUNT,
    }
)

_PRIVATE_ENDPOINT_TARGET_PATH_PREFIX = ("private_service_connection",)
_PRIVATE_ENDPOINT_SUBNET_PATH = ("subnet_id",)
_PRIVATE_DNS_ZONE_LINK_ZONE_PATH = ("private_dns_zone_name",)
_PRIVATE_DNS_ZONE_LINK_VNET_PATH = ("virtual_network_id",)
_APP_SERVICE_SUBNET_PATH = ("virtual_network_subnet_id",)


class ResolveAzureNetworkSymbolicRelationshipsStage:
    """Adopt exact Azure network relationships from symbolic plan evidence."""

    name = "resolve_azure_network_symbolic_relationships"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        for resource in resources:
            if resource.resource_type == AzureResourceType.PRIVATE_ENDPOINT:
                self._resolve_private_endpoint(resource, context)
            elif resource.resource_type in AZURE_APP_SERVICE_RESOURCE_TYPES:
                self._resolve_app_service(resource, context)
            elif resource.resource_type == AzureResourceType.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_LINK:
                self._resolve_private_dns_zone_link(resource, context)

    def _resolve_private_endpoint(
        self,
        endpoint: NormalizedResource,
        context: AzureDecorationContext,
    ) -> None:
        facts = azure_facts(endpoint)
        connections = facts.private_service_connections
        for index, record in enumerate(connections):
            target_targets = _symbolic_targets(
                endpoint,
                context,
                allowed_paths={
                    (*_PRIVATE_ENDPOINT_TARGET_PATH_PREFIX, index, "private_connection_resource_id"),
                },
                expected_resource_types=_PRIVATE_ENDPOINT_TARGET_TYPES,
                expected_reference_suffixes=(".id",),
            )
            target = _adopt_single_target(
                endpoint,
                target_targets,
                concrete_references=_reference_values(record.get("private_connection_resource_id")),
                uncertainty_field=AzureResourceMetadata.PRIVATE_ENDPOINT_UNCERTAINTIES,
                relationship_name="private endpoint target",
            )
            if target is not None:
                updated_connections = [dict(item) for item in connections]
                updated_connections[index]["resolved_target_resource_address"] = target.address
                facts.set(AzureResourceMetadata.PRIVATE_SERVICE_CONNECTIONS, updated_connections)
                connections = updated_connections

        subnet_targets = _symbolic_targets(
            endpoint,
            context,
            allowed_paths={_PRIVATE_ENDPOINT_SUBNET_PATH},
            expected_resource_types={AzureResourceType.SUBNET},
            expected_reference_suffixes=(".id",),
        )
        subnet = _adopt_single_target(
            endpoint,
            subnet_targets,
            concrete_references=endpoint.subnet_ids,
            uncertainty_field=AzureResourceMetadata.PRIVATE_ENDPOINT_UNCERTAINTIES,
            relationship_name="private endpoint subnet",
        )
        if subnet is not None and subnet.address not in facts.resolved_subnet_addresses:
            facts.add_resolved_subnet_address(subnet.address)

        groups = facts.private_dns_zone_groups
        for index, _record in enumerate(groups):
            zone_targets = _symbolic_targets(
                endpoint,
                context,
                allowed_paths={("private_dns_zone_group", index, "private_dns_zone_ids")},
                expected_resource_types={AzureResourceType.PRIVATE_DNS_ZONE},
                expected_reference_suffixes=(".id",),
            )
            raw_ids = _string_values(groups[index].get("private_dns_zone_ids"))
            resolved_addresses = _string_values(groups[index].get("resolved_private_dns_zone_addresses"))
            zone_targets = _filter_targets_against_concrete(
                endpoint,
                zone_targets,
                concrete_references=[*raw_ids, *resolved_addresses],
                uncertainty_field=AzureResourceMetadata.PRIVATE_ENDPOINT_UNCERTAINTIES,
                relationship_name="private endpoint DNS zones (private_dns_zone_ids)",
            )
            if not zone_targets:
                continue
            updated_groups = [dict(record) for record in groups]
            updated_groups[index]["resolved_private_dns_zone_addresses"] = [target.address for target in zone_targets]
            facts.set(AzureResourceMetadata.PRIVATE_DNS_ZONE_GROUPS, updated_groups)
            groups = updated_groups

        if (
            facts.private_dns_zone_group_state == STATE_CONFIGURED
            and groups
            and all(_dns_zone_group_is_complete(group) for group in groups)
            and facts.private_dns_zone_ids_state != STATE_CONFIGURED
        ):
            facts.set(AzureResourceMetadata.PRIVATE_DNS_ZONE_IDS_STATE, STATE_CONFIGURED)

    def _resolve_app_service(
        self,
        app_service: NormalizedResource,
        context: AzureDecorationContext,
    ) -> None:
        facts = azure_facts(app_service)
        subnet_targets = _symbolic_targets(
            app_service,
            context,
            allowed_paths={_APP_SERVICE_SUBNET_PATH},
            expected_resource_types={AzureResourceType.SUBNET},
            expected_reference_suffixes=(".id",),
        )
        subnet = _adopt_single_target(
            app_service,
            subnet_targets,
            concrete_references=[
                value
                for value in (
                    facts.app_service_vnet_integration_subnet_id,
                    *facts.resolved_subnet_addresses,
                )
                if value
            ],
            uncertainty_field=AzureResourceMetadata.APP_SERVICE_POSTURE_UNCERTAINTIES,
            relationship_name="App Service VNet integration subnet",
        )
        if subnet is not None and subnet.address not in facts.resolved_subnet_addresses:
            facts.add_resolved_subnet_address(subnet.address)

    def _resolve_private_dns_zone_link(
        self,
        link: NormalizedResource,
        context: AzureDecorationContext,
    ) -> None:
        facts = azure_facts(link)
        zone_targets = _symbolic_targets(
            link,
            context,
            allowed_paths={_PRIVATE_DNS_ZONE_LINK_ZONE_PATH},
            expected_resource_types={AzureResourceType.PRIVATE_DNS_ZONE},
            expected_reference_suffixes=(".name",),
        )
        zone = _adopt_single_target(
            link,
            zone_targets,
            concrete_references=[facts.private_dns_zone_reference] if facts.private_dns_zone_reference else [],
            uncertainty_field=AzureResourceMetadata.PRIVATE_DNS_ZONE_UNCERTAINTIES,
            relationship_name="private DNS zone link zone",
        )
        if zone is not None and not facts.private_dns_zone_reference:
            facts.set(
                AzureResourceMetadata.PRIVATE_DNS_ZONE_REFERENCE,
                f"{zone.address}.name",
            )

        virtual_network_targets = _symbolic_targets(
            link,
            context,
            allowed_paths={_PRIVATE_DNS_ZONE_LINK_VNET_PATH},
            expected_resource_types={AzureResourceType.VIRTUAL_NETWORK},
            expected_reference_suffixes=(".id",),
        )
        virtual_network = _adopt_single_target(
            link,
            virtual_network_targets,
            concrete_references=[facts.private_dns_zone_virtual_network_reference]
            if facts.private_dns_zone_virtual_network_reference
            else [],
            uncertainty_field=AzureResourceMetadata.PRIVATE_DNS_ZONE_UNCERTAINTIES,
            relationship_name="private DNS zone link virtual network",
        )
        if virtual_network is not None and not facts.private_dns_zone_virtual_network_reference:
            facts.set(
                AzureResourceMetadata.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_REFERENCE,
                f"{virtual_network.address}.id",
            )


def _symbolic_targets(
    resource: NormalizedResource,
    context: AzureDecorationContext,
    *,
    allowed_paths: Collection[tuple[str | int, ...]],
    expected_reference_suffixes: Collection[str],
    expected_resource_types: Collection[str] | None = None,
) -> tuple[NormalizedResource, ...]:
    matches: dict[str, NormalizedResource] = {}
    expected_types = set(expected_resource_types) if expected_resource_types is not None else None
    suffixes = tuple(suffix.casefold() for suffix in expected_reference_suffixes)
    for resolution in resource.reference_resolutions:
        if resolution.state is not TerraformReferenceResolutionState.SYMBOLIC:
            continue
        if resolution.provenance is not TerraformReferenceProvenance.CONFIGURATION_REFERENCE:
            continue
        if resolution.path not in allowed_paths or not resolution.targets:
            continue
        # Terraform show-json exposes referenced targets, not enough expression
        # shape to distinguish an exact collection from conditional candidates.
        if len(resolution.targets) != 1:
            continue
        resolution_matches: list[NormalizedResource] = []
        for target in resolution.targets:
            if not any(target.reference.casefold().endswith(suffix) for suffix in suffixes):
                return ()
            candidate = context.index.resources_by_address.get(target.address)
            if candidate is None:
                return ()
            if expected_types is not None and candidate.resource_type not in expected_types:
                return ()
            resolution_matches.append(candidate)
        for candidate in resolution_matches:
            matches[candidate.address] = candidate
    return tuple(matches.values())


def _adopt_single_target(
    resource: NormalizedResource,
    targets: tuple[NormalizedResource, ...],
    *,
    concrete_references: Collection[str],
    uncertainty_field: StringListMetadataField,
    relationship_name: str,
) -> NormalizedResource | None:
    if not targets:
        return None
    if len(targets) > 1:
        _record_relationship_uncertainty(
            resource,
            uncertainty_field,
            f"{resource.address}: {relationship_name} has multiple symbolic targets",
        )
        return None
    filtered_targets = _filter_targets_against_concrete(
        resource,
        targets,
        concrete_references=concrete_references,
        uncertainty_field=uncertainty_field,
        relationship_name=relationship_name,
    )
    return filtered_targets[0] if filtered_targets else None


def _filter_targets_against_concrete(
    resource: NormalizedResource,
    targets: tuple[NormalizedResource, ...],
    *,
    concrete_references: Collection[str],
    uncertainty_field: StringListMetadataField,
    relationship_name: str,
) -> tuple[NormalizedResource, ...]:
    concrete = [reference for reference in concrete_references if reference]
    if not targets or not concrete:
        return targets
    matching_targets = tuple(target for target in targets if _targets_match_concrete((target,), concrete))
    if (
        len(matching_targets) == len(targets)
        and len(matching_targets) == len({target.address for target in targets})
        and _targets_match_concrete(targets, concrete)
    ):
        return matching_targets
    _record_relationship_uncertainty(
        resource,
        uncertainty_field,
        f"{resource.address}: symbolic {relationship_name} conflicts with concrete relationship evidence",
    )
    return ()


def _targets_match_concrete(
    targets: tuple[NormalizedResource, ...],
    references: Collection[str],
) -> bool:
    target_key_sets = [set(azure_resource_references(target)) for target in targets]
    concrete_keys = [azure_reference_key(reference) for reference in references if reference]
    if not target_key_sets or not concrete_keys:
        return False

    every_target_matches = all(any(key in concrete_keys for key in target_keys) for target_keys in target_key_sets)
    every_reference_matches = all(
        any(reference_key in target_keys for target_keys in target_key_sets) for reference_key in concrete_keys
    )
    return every_target_matches and every_reference_matches


def _dns_zone_group_is_complete(group: dict[str, object]) -> bool:
    return bool(
        _string_values(group.get("private_dns_zone_ids"))
        or _string_values(group.get("resolved_private_dns_zone_addresses"))
    )


def _string_values(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _reference_values(value: object) -> list[str]:
    if isinstance(value, str) and value:
        return [value]
    return _string_values(value)


def _record_relationship_uncertainty(
    resource: NormalizedResource,
    field: StringListMetadataField,
    message: str,
) -> None:
    azure_facts(resource).append(field, message)

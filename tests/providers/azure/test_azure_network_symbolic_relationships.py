from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import (
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
    TerraformResource,
)
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.private_endpoint_index import build_azure_private_endpoint_index
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_STORAGE_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/orders"
_SUBNET_ID = (
    "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Network/virtualNetworks/main/subnets/private"
)
_ZONE_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net"


def _resource(
    address: str,
    resource_type: str,
    values: dict[str, object],
    *,
    unknown_values: dict[str, object] | None = None,
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = (),
) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values=unknown_values or {},
        reference_resolutions=reference_resolutions,
    )


def _symbolic(
    path: tuple[str | int, ...],
    target_address: str,
    suffix: str,
) -> TerraformReferenceResolution:
    reference = f"{target_address}{suffix}"
    return TerraformReferenceResolution(
        path=path,
        state=TerraformReferenceResolutionState.SYMBOLIC,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=(reference,),
        targets=(TerraformReferenceTarget(address=target_address, reference=reference),),
    )


def _symbolic_targets(
    path: tuple[str | int, ...],
    target_addresses: tuple[str, ...],
    suffix: str = ".id",
) -> TerraformReferenceResolution:
    references = tuple(f"{address}{suffix}" for address in target_addresses)
    return TerraformReferenceResolution(
        path=path,
        state=TerraformReferenceResolutionState.SYMBOLIC,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=references,
        targets=tuple(
            TerraformReferenceTarget(address=address, reference=f"{address}{suffix}") for address in target_addresses
        ),
    )


def _storage(*, unknown_id: bool = True) -> TerraformResource:
    return _resource(
        "azurerm_storage_account.orders",
        AzureResourceType.STORAGE_ACCOUNT,
        {
            "id": None if unknown_id else _STORAGE_ID,
            "name": "orders",
            "allow_nested_items_to_be_public": False,
            "shared_access_key_enabled": False,
            "min_tls_version": "TLS1_2",
            "public_network_access_enabled": False,
        },
        unknown_values={"id": True} if unknown_id else {},
    )


def _subnet() -> TerraformResource:
    return _resource(
        "azurerm_subnet.private",
        AzureResourceType.SUBNET,
        {
            "id": None,
            "name": "private",
            "virtual_network_name": "azurerm_virtual_network.main.name",
            "address_prefixes": ["10.0.1.0/24"],
        },
        unknown_values={"id": True},
    )


def _dns_zone() -> TerraformResource:
    return _resource(
        "azurerm_private_dns_zone.blob",
        AzureResourceType.PRIVATE_DNS_ZONE,
        {"id": None, "name": "privatelink.blob.core.windows.net"},
        unknown_values={"id": True},
    )


def _virtual_network() -> TerraformResource:
    return _resource(
        "azurerm_virtual_network.main",
        AzureResourceType.VIRTUAL_NETWORK,
        {"id": None, "name": "main", "address_space": ["10.0.0.0/16"]},
        unknown_values={"id": True},
    )


def _dns_link(
    references: tuple[TerraformReferenceResolution, ...],
    *,
    zone_name: object = None,
    virtual_network_id: object = None,
) -> TerraformResource:
    return _resource(
        "azurerm_private_dns_zone_virtual_network_link.blob",
        AzureResourceType.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_LINK,
        {"id": None, "private_dns_zone_name": zone_name, "virtual_network_id": virtual_network_id},
        unknown_values={
            "id": True,
            "private_dns_zone_name": True if zone_name is None else False,
            "virtual_network_id": True if virtual_network_id is None else False,
        },
        reference_resolutions=references,
    )


def _private_endpoint(
    references: tuple[TerraformReferenceResolution, ...],
) -> TerraformResource:
    return _resource(
        "azurerm_private_endpoint.orders",
        AzureResourceType.PRIVATE_ENDPOINT,
        {
            "id": None,
            "name": "orders",
            "subnet_id": None,
            "private_service_connection": [
                {
                    "name": "orders",
                    "private_connection_resource_id": None,
                    "subresource_names": ["blob"],
                    "is_manual_connection": False,
                }
            ],
            "private_dns_zone_group": [
                {"name": "blob", "private_dns_zone_ids": None},
            ],
        },
        unknown_values={
            "id": True,
            "subnet_id": True,
            "private_service_connection": [{"private_connection_resource_id": True}],
            "private_dns_zone_group": [{"private_dns_zone_ids": True}],
        },
        reference_resolutions=references,
    )


class AzureNetworkSymbolicRelationshipTests(unittest.TestCase):
    def test_private_endpoint_relationships_feed_existing_coverage_index(self) -> None:
        storage = _storage()
        subnet = _subnet()
        zone = _dns_zone()
        endpoint = _private_endpoint(
            (
                _symbolic(
                    ("private_service_connection", 0, "private_connection_resource_id"),
                    storage.address,
                    ".id",
                ),
                _symbolic(("subnet_id",), subnet.address, ".id"),
                _symbolic(
                    ("private_dns_zone_group", 0, "private_dns_zone_ids"),
                    zone.address,
                    ".id",
                ),
            )
        )

        inventory = AzureNormalizer().normalize([endpoint, storage, subnet, zone])
        normalized_endpoint = inventory.get_by_address(endpoint.address)
        normalized_storage = inventory.get_by_address(storage.address)
        assert normalized_endpoint is not None
        assert normalized_storage is not None

        endpoint_facts = azure_facts(normalized_endpoint)
        connection = endpoint_facts.private_service_connections[0]
        self.assertEqual(connection["resolved_target_resource_address"], storage.address)
        self.assertEqual(endpoint_facts.resolved_subnet_addresses, [subnet.address])
        self.assertEqual(
            endpoint_facts.private_dns_zone_groups[0]["resolved_private_dns_zone_addresses"],
            [zone.address],
        )
        self.assertIsNone(connection.get("private_connection_resource_id"))

        coverage = build_azure_private_endpoint_index(inventory).coverage_for(normalized_storage)
        self.assertTrue(coverage.has_private_endpoint)
        self.assertIsNone(coverage.connections[0].target_resource_id)
        self.assertEqual(coverage.connections[0].target_resource_address, storage.address)
        self.assertEqual(coverage.private_dns_zone_addresses, (zone.address,))

    def test_private_endpoint_target_wrong_attribute_is_not_promoted(self) -> None:
        storage = _storage()
        endpoint = _private_endpoint(
            (
                _symbolic(
                    ("private_service_connection", 0, "private_connection_resource_id"),
                    storage.address,
                    ".name",
                ),
            )
        )

        inventory = AzureNormalizer().normalize([endpoint, storage])
        normalized_endpoint = inventory.get_by_address(endpoint.address)
        assert normalized_endpoint is not None
        self.assertNotIn(
            "resolved_target_resource_address",
            azure_facts(normalized_endpoint).private_service_connections[0],
        )
        normalized_storage = inventory.get_by_address(storage.address)
        assert normalized_storage is not None
        self.assertFalse(
            build_azure_private_endpoint_index(inventory).coverage_for(normalized_storage).has_private_endpoint
        )

    def test_app_service_symbolic_subnet_suppresses_missing_vnet_finding(self) -> None:
        subnet = _subnet()
        app = _resource(
            "azurerm_linux_web_app.api",
            AzureResourceType.LINUX_WEB_APP,
            {
                "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/api",
                "name": "api",
                "public_network_access_enabled": True,
                "virtual_network_subnet_id": None,
            },
            unknown_values={"virtual_network_subnet_id": True},
            reference_resolutions=(_symbolic(("virtual_network_subnet_id",), subnet.address, ".id"),),
        )

        inventory = AzureNormalizer().normalize([app, subnet])
        normalized_app = inventory.get_by_address(app.address)
        assert normalized_app is not None
        self.assertEqual(azure_facts(normalized_app).resolved_subnet_addresses, [subnet.address])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"azure-app-service-vnet-integration-missing"})),
        )
        self.assertEqual(findings, [])

    def test_private_dns_zone_link_symbolic_relationships_preserve_reference_fields(self) -> None:
        zone = _dns_zone()
        virtual_network = _resource(
            "azurerm_virtual_network.main",
            AzureResourceType.VIRTUAL_NETWORK,
            {"id": None, "name": "main", "address_space": ["10.0.0.0/16"]},
            unknown_values={"id": True},
        )
        link = _resource(
            "azurerm_private_dns_zone_virtual_network_link.blob",
            AzureResourceType.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_LINK,
            {"id": None, "private_dns_zone_name": None, "virtual_network_id": None},
            unknown_values={"id": True, "private_dns_zone_name": True, "virtual_network_id": True},
            reference_resolutions=(
                _symbolic(("private_dns_zone_name",), zone.address, ".name"),
                _symbolic(("virtual_network_id",), virtual_network.address, ".id"),
            ),
        )

        inventory = AzureNormalizer().normalize([link, virtual_network, zone])
        normalized_link = inventory.get_by_address(link.address)
        assert normalized_link is not None
        facts = azure_facts(normalized_link)
        self.assertEqual(facts.private_dns_zone_reference, f"{zone.address}.name")
        self.assertEqual(
            facts.private_dns_zone_virtual_network_reference,
            f"{virtual_network.address}.id",
        )

    def test_exact_symbolic_dns_zone_and_vnet_link_stay_quiet(self) -> None:
        storage = _storage()
        subnet = _subnet()
        zone = _dns_zone()
        virtual_network = _virtual_network()
        endpoint = _private_endpoint(
            (
                _symbolic(
                    ("private_service_connection", 0, "private_connection_resource_id"),
                    storage.address,
                    ".id",
                ),
                _symbolic(("subnet_id",), subnet.address, ".id"),
                _symbolic(
                    ("private_dns_zone_group", 0, "private_dns_zone_ids"),
                    zone.address,
                    ".id",
                ),
            )
        )
        link = _dns_link(
            (
                _symbolic(("private_dns_zone_name",), zone.address, ".name"),
                _symbolic(("virtual_network_id",), virtual_network.address, ".id"),
            )
        )

        inventory = AzureNormalizer().normalize([endpoint, storage, subnet, zone, virtual_network, link])
        normalized_endpoint = inventory.get_by_address(endpoint.address)
        assert normalized_endpoint is not None
        endpoint_facts = azure_facts(normalized_endpoint)
        self.assertEqual(endpoint_facts.private_dns_zone_ids_state, "configured")

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"azure-private-endpoint-dns-posture-incomplete"})),
        )
        self.assertEqual(findings, [])

    def test_multiple_symbolic_dns_zones_remain_unresolved_without_collection_proof(self) -> None:
        storage = _storage()
        zone_one = _dns_zone()
        zone_two = _resource(
            "azurerm_private_dns_zone.file",
            AzureResourceType.PRIVATE_DNS_ZONE,
            {"id": None, "name": "privatelink.file.core.windows.net"},
            unknown_values={"id": True},
        )
        endpoint = _private_endpoint(
            (
                _symbolic_targets(
                    ("private_dns_zone_group", 0, "private_dns_zone_ids"),
                    (zone_one.address, zone_two.address),
                ),
            )
        )

        inventory = AzureNormalizer().normalize([endpoint, storage, zone_one, zone_two])
        normalized_endpoint = inventory.get_by_address(endpoint.address)
        assert normalized_endpoint is not None
        facts = azure_facts(normalized_endpoint)
        self.assertEqual(
            facts.private_dns_zone_groups[0].get("resolved_private_dns_zone_addresses", []),
            [],
        )
        self.assertEqual(facts.private_dns_zone_ids_state, "unknown")

    def test_endpoint_subnet_conflict_preserves_concrete_relationship(self) -> None:
        concrete_subnet = _resource(
            "azurerm_subnet.concrete",
            AzureResourceType.SUBNET,
            {"id": _SUBNET_ID, "name": "concrete", "virtual_network_name": "main"},
        )
        symbolic_subnet = _subnet()
        endpoint = _private_endpoint((_symbolic(("subnet_id",), symbolic_subnet.address, ".id"),))
        endpoint.values["subnet_id"] = f"{concrete_subnet.address}.id"
        endpoint.unknown_values["subnet_id"] = False

        inventory = AzureNormalizer().normalize([endpoint, concrete_subnet, symbolic_subnet])
        normalized_endpoint = inventory.get_by_address(endpoint.address)
        assert normalized_endpoint is not None
        facts = azure_facts(normalized_endpoint)
        self.assertEqual(facts.resolved_subnet_addresses, [])
        self.assertTrue(any("private endpoint subnet" in value for value in facts.private_endpoint_uncertainties))

    def test_endpoint_dns_zone_conflict_preserves_concrete_relationship(self) -> None:
        zone_one = _dns_zone()
        zone_two = _resource(
            "azurerm_private_dns_zone.file",
            AzureResourceType.PRIVATE_DNS_ZONE,
            {"id": None, "name": "privatelink.file.core.windows.net"},
            unknown_values={"id": True},
        )
        storage = _storage()
        endpoint = _private_endpoint(
            (
                _symbolic(
                    ("private_service_connection", 0, "private_connection_resource_id"),
                    storage.address,
                    ".id",
                ),
                _symbolic(("private_dns_zone_group", 0, "private_dns_zone_ids"), zone_two.address, ".id"),
            )
        )
        endpoint.values["private_dns_zone_group"] = [
            {"name": "blob", "private_dns_zone_ids": [f"{zone_one.address}.id"]}
        ]
        endpoint.unknown_values["private_dns_zone_group"] = [{"private_dns_zone_ids": False}]

        inventory = AzureNormalizer().normalize([endpoint, storage, zone_one, zone_two])
        normalized_endpoint = inventory.get_by_address(endpoint.address)
        assert normalized_endpoint is not None
        facts = azure_facts(normalized_endpoint)
        self.assertEqual(facts.resolved_private_dns_zone_addresses, [])
        self.assertTrue(any("private_dns_zone_ids" in value for value in facts.private_endpoint_uncertainties))

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"azure-private-endpoint-dns-posture-incomplete"})),
        )
        self.assertEqual(len(findings), 1)
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertTrue(
            any(
                "private_dns_zone_ids" in value and "conflicts" in value
                for value in evidence["private_endpoint_dns_posture"]
            )
        )

    def test_private_endpoint_external_concrete_target_blocks_symbolic_target(self) -> None:
        storage = _storage()
        external_target_id = (
            "/subscriptions/foreign/resourceGroups/other/providers/Microsoft.Storage/storageAccounts/external"
        )
        endpoint = _private_endpoint(
            (
                _symbolic(
                    ("private_service_connection", 0, "private_connection_resource_id"),
                    storage.address,
                    ".id",
                ),
            )
        )
        endpoint.values["private_service_connection"][0]["private_connection_resource_id"] = external_target_id
        endpoint.unknown_values["private_service_connection"] = [{"private_connection_resource_id": False}]

        inventory = AzureNormalizer().normalize([endpoint, storage])
        normalized_endpoint = inventory.get_by_address(endpoint.address)
        normalized_storage = inventory.get_by_address(storage.address)
        assert normalized_endpoint is not None
        assert normalized_storage is not None
        endpoint_facts = azure_facts(normalized_endpoint)
        self.assertEqual(endpoint_facts.resolved_private_endpoint_target_addresses, [])
        coverage = build_azure_private_endpoint_index(inventory).coverage_for(normalized_storage)
        self.assertFalse(coverage.has_private_endpoint)
        self.assertTrue(
            any("private endpoint target" in value for value in endpoint_facts.private_endpoint_uncertainties)
        )

    def test_endpoint_dns_zone_partial_concrete_agreement_is_rejected(self) -> None:
        storage = _storage()
        zone_one = _dns_zone()
        zone_two = _resource(
            "azurerm_private_dns_zone.file",
            AzureResourceType.PRIVATE_DNS_ZONE,
            {"id": None, "name": "privatelink.file.core.windows.net"},
            unknown_values={"id": True},
        )
        endpoint = _private_endpoint(
            (
                _symbolic(
                    ("private_service_connection", 0, "private_connection_resource_id"),
                    storage.address,
                    ".id",
                ),
                _symbolic(("private_dns_zone_group", 0, "private_dns_zone_ids"), zone_one.address, ".id"),
            )
        )
        endpoint.values["private_dns_zone_group"] = [
            {
                "name": "blob",
                "private_dns_zone_ids": [f"{zone_one.address}.id", f"{zone_two.address}.id"],
            }
        ]
        endpoint.unknown_values["private_dns_zone_group"] = [{"private_dns_zone_ids": False}]

        inventory = AzureNormalizer().normalize([endpoint, storage, zone_one, zone_two])
        normalized_endpoint = inventory.get_by_address(endpoint.address)
        assert normalized_endpoint is not None
        facts = azure_facts(normalized_endpoint)
        self.assertEqual(facts.resolved_private_dns_zone_addresses, [])
        self.assertTrue(any("private_dns_zone_ids" in value for value in facts.private_endpoint_uncertainties))

    def test_app_service_subnet_conflict_preserves_concrete_relationship(self) -> None:
        concrete_subnet = _resource(
            "azurerm_subnet.concrete",
            AzureResourceType.SUBNET,
            {"id": _SUBNET_ID, "name": "concrete", "virtual_network_name": "main"},
        )
        symbolic_subnet = _subnet()
        app = _resource(
            "azurerm_linux_web_app.api",
            AzureResourceType.LINUX_WEB_APP,
            {
                "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/api",
                "name": "api",
                "virtual_network_subnet_id": f"{concrete_subnet.address}.id",
            },
            reference_resolutions=(_symbolic(("virtual_network_subnet_id",), symbolic_subnet.address, ".id"),),
        )

        inventory = AzureNormalizer().normalize([app, concrete_subnet, symbolic_subnet])
        normalized_app = inventory.get_by_address(app.address)
        assert normalized_app is not None
        facts = azure_facts(normalized_app)
        self.assertEqual(facts.resolved_subnet_addresses, [])
        self.assertTrue(
            any("App Service VNet integration subnet" in value for value in facts.app_service_posture_uncertainties)
        )

    def test_dns_zone_link_conflict_preserves_concrete_relationship(self) -> None:
        concrete_zone = _dns_zone()
        symbolic_zone = _resource(
            "azurerm_private_dns_zone.file",
            AzureResourceType.PRIVATE_DNS_ZONE,
            {"id": None, "name": "privatelink.file.core.windows.net"},
            unknown_values={"id": True},
        )
        virtual_network = _virtual_network()
        symbolic_virtual_network = _resource(
            "azurerm_virtual_network.other",
            AzureResourceType.VIRTUAL_NETWORK,
            {"id": None, "name": "other", "address_space": ["10.1.0.0/16"]},
            unknown_values={"id": True},
        )
        link = _dns_link(
            (
                _symbolic(("private_dns_zone_name",), symbolic_zone.address, ".name"),
                _symbolic(("virtual_network_id",), symbolic_virtual_network.address, ".id"),
            ),
            zone_name=f"{concrete_zone.address}.name",
            virtual_network_id=f"{virtual_network.address}.id",
        )
        link.unknown_values["private_dns_zone_name"] = False
        link.unknown_values["virtual_network_id"] = False

        inventory = AzureNormalizer().normalize(
            [link, concrete_zone, symbolic_zone, virtual_network, symbolic_virtual_network]
        )
        normalized_link = inventory.get_by_address(link.address)
        assert normalized_link is not None
        facts = azure_facts(normalized_link)
        self.assertEqual(facts.private_dns_zone_reference, f"{concrete_zone.address}.name")
        self.assertEqual(
            facts.private_dns_zone_virtual_network_reference,
            f"{virtual_network.address}.id",
        )
        self.assertTrue(any("private DNS zone link zone" in value for value in facts.private_dns_zone_uncertainties))
        self.assertTrue(
            any("private DNS zone link virtual network" in value for value in facts.private_dns_zone_uncertainties)
        )

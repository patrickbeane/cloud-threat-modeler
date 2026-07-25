from __future__ import annotations

import unittest

from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.catalog import default_resource_capability_registry
from tfstride.providers.resource_capabilities import ResourceCapability

_ACCOUNT_ID = "/subscriptions/example/resourceGroups/data/providers/Microsoft.DocumentDB/databaseAccounts/orders"
_KEY_ID = "azurerm_key_vault_key.cosmos.id"
_IDENTITY_ID = "azurerm_user_assigned_identity.cosmos.id"
_SUBNET_ID = "azurerm_subnet.cosmos.id"
_BYPASS_ID = "/subscriptions/example/resourceGroups/apps/providers/Microsoft.Web/sites/processor"


def _account(
    *,
    name: str = "orders",
    values: dict[str, object] | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"azurerm_cosmosdb_account.{name}",
        mode="managed",
        resource_type=AzureResourceType.COSMOSDB_ACCOUNT,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values={
            "id": _ACCOUNT_ID,
            "name": name,
            "resource_group_name": "data",
            "location": "eastus",
            "offer_type": "Standard",
            **(values or {}),
        },
        unknown_values=unknown_values or {},
    )


class AzureCosmosDbNormalizerTests(unittest.TestCase):
    def test_account_normalizes_encryption_backup_network_identity_and_failover_posture(
        self,
    ) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _account(
                    values={
                        "key_vault_key_id": _KEY_ID,
                        "default_identity_type": f"UserAssignedIdentity={_IDENTITY_ID}",
                        "backup": [
                            {
                                "type": "Continuous",
                                "tier": "Continuous30Days",
                                "interval_in_minutes": None,
                                "retention_in_hours": None,
                                "storage_redundancy": None,
                            }
                        ],
                        "public_network_access_enabled": False,
                        "ip_range_filter": ["198.51.100.0/24", "203.0.113.10"],
                        "is_virtual_network_filter_enabled": True,
                        "virtual_network_rule": [
                            {
                                "id": _SUBNET_ID,
                                "ignore_missing_vnet_service_endpoint": False,
                            }
                        ],
                        "network_acl_bypass_for_azure_services": False,
                        "network_acl_bypass_ids": [_BYPASS_ID],
                        "local_authentication_enabled": False,
                        "minimal_tls_version": "Tls12",
                        "identity": [
                            {
                                "type": "UserAssigned",
                                "principal_id": "principal-id",
                                "client_id": "client-id",
                                "tenant_id": "tenant-id",
                                "identity_ids": [_IDENTITY_ID],
                            }
                        ],
                        "automatic_failover_enabled": True,
                        "multiple_write_locations_enabled": True,
                        "geo_location": [
                            {
                                "location": "westus2",
                                "failover_priority": 1,
                                "zone_redundant": False,
                            },
                            {
                                "location": "eastus",
                                "failover_priority": 0,
                                "zone_redundant": True,
                            },
                        ],
                    }
                )
            ]
        )
        account = inventory.resources[0]
        facts = azure_facts(account)

        self.assertEqual(account.category, ResourceCategory.DATA)
        self.assertEqual(account.identifier, _ACCOUNT_ID)
        self.assertEqual(account.data_sensitivity, "sensitive")
        self.assertTrue(account.storage_encrypted)
        self.assertEqual(facts.cosmosdb_account_id, _ACCOUNT_ID)
        self.assertEqual(facts.cosmosdb_kind, "GlobalDocumentDB")
        self.assertEqual(facts.cosmosdb_offer_type, "Standard")
        self.assertEqual(facts.cosmosdb_customer_managed_key_state, "configured")
        self.assertTrue(facts.cosmosdb_customer_managed_encryption)
        self.assertEqual(facts.cosmosdb_key_vault_key_id, _KEY_ID)
        self.assertEqual(
            facts.cosmosdb_default_identity_type,
            f"UserAssignedIdentity={_IDENTITY_ID}",
        )
        self.assertEqual(facts.cosmosdb_backup_configuration_state, "configured")
        self.assertTrue(facts.cosmosdb_backup_block_configured)
        self.assertEqual(facts.cosmosdb_backup_type, "Continuous")
        self.assertEqual(facts.cosmosdb_backup_tier, "Continuous30Days")
        self.assertIsNone(facts.cosmosdb_backup_interval_minutes)
        self.assertIsNone(facts.cosmosdb_backup_retention_hours)
        self.assertIsNone(facts.cosmosdb_backup_storage_redundancy)
        self.assertFalse(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "disabled")
        self.assertEqual(facts.cosmosdb_ip_range_filter_state, "configured")
        self.assertEqual(
            facts.cosmosdb_ip_range_filter,
            ["198.51.100.0/24", "203.0.113.10"],
        )
        self.assertEqual(facts.cosmosdb_virtual_network_filter_state, "enabled")
        self.assertTrue(facts.cosmosdb_virtual_network_filter_enabled)
        self.assertEqual(facts.cosmosdb_virtual_network_rule_state, "configured")
        self.assertEqual(
            facts.cosmosdb_virtual_network_rules,
            [
                {
                    "subnet_id": _SUBNET_ID,
                    "ignore_missing_vnet_service_endpoint": False,
                }
            ],
        )
        self.assertEqual(facts.cosmosdb_network_acl_bypass_state, "disabled")
        self.assertFalse(facts.cosmosdb_network_acl_bypass_enabled)
        self.assertEqual(facts.cosmosdb_network_acl_bypass_ids_state, "configured")
        self.assertEqual(facts.cosmosdb_network_acl_bypass_ids, [_BYPASS_ID])
        self.assertEqual(facts.cosmosdb_local_authentication_state, "disabled")
        self.assertFalse(facts.cosmosdb_local_authentication_enabled)
        self.assertEqual(facts.min_tls_version, "Tls12")
        self.assertEqual(facts.identity_type, "UserAssigned")
        self.assertEqual(facts.principal_id, "principal-id")
        self.assertEqual(facts.client_id, "client-id")
        self.assertEqual(facts.tenant_id, "tenant-id")
        self.assertEqual(facts.attached_identity_references, [_IDENTITY_ID])
        self.assertTrue(facts.cosmosdb_automatic_failover_enabled)
        self.assertTrue(facts.cosmosdb_multiple_write_locations_enabled)
        self.assertEqual(facts.cosmosdb_geo_location_state, "configured")
        self.assertEqual(
            facts.cosmosdb_geo_locations,
            [
                {
                    "location": "eastus",
                    "failover_priority": 0,
                    "zone_redundant": True,
                },
                {
                    "location": "westus2",
                    "failover_priority": 1,
                    "zone_redundant": False,
                },
            ],
        )
        self.assertEqual(facts.cosmosdb_posture_uncertainties, [])
        self.assertEqual(facts.managed_identity_uncertainties, [])

    def test_periodic_public_account_preserves_retention_and_access_posture(self) -> None:
        facts = azure_facts(
            AzureNormalizer()
            .normalize(
                [
                    _account(
                        values={
                            "backup": [
                                {
                                    "type": "Periodic",
                                    "interval_in_minutes": 240,
                                    "retention_in_hours": 168,
                                    "storage_redundancy": "Geo",
                                }
                            ],
                            "public_network_access_enabled": True,
                            "ip_range_filter": [],
                            "is_virtual_network_filter_enabled": False,
                            "virtual_network_rule": [],
                            "network_acl_bypass_for_azure_services": True,
                            "network_acl_bypass_ids": [],
                            "local_authentication_enabled": True,
                            "minimal_tls_version": "Tls11",
                            "automatic_failover_enabled": False,
                            "multiple_write_locations_enabled": False,
                            "geo_location": [
                                {
                                    "location": "eastus",
                                    "failover_priority": 0,
                                    "zone_redundant": False,
                                }
                            ],
                        }
                    )
                ]
            )
            .resources[0]
        )

        self.assertEqual(facts.cosmosdb_customer_managed_key_state, "not_configured")
        self.assertFalse(facts.cosmosdb_customer_managed_encryption)
        self.assertEqual(facts.cosmosdb_backup_type, "Periodic")
        self.assertEqual(facts.cosmosdb_backup_interval_minutes, 240)
        self.assertEqual(facts.cosmosdb_backup_retention_hours, 168)
        self.assertEqual(facts.cosmosdb_backup_storage_redundancy, "Geo")
        self.assertTrue(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "enabled")
        self.assertTrue(facts.cosmosdb_public_network_access_enabled)
        self.assertEqual(facts.cosmosdb_public_network_access_state, "enabled")
        self.assertEqual(facts.cosmosdb_ip_range_filter_state, "not_configured")
        self.assertFalse(facts.cosmosdb_virtual_network_filter_enabled)
        self.assertEqual(facts.cosmosdb_virtual_network_rule_state, "not_configured")
        self.assertTrue(facts.cosmosdb_network_acl_bypass_enabled)
        self.assertEqual(facts.cosmosdb_network_acl_bypass_ids_state, "not_configured")
        self.assertTrue(facts.cosmosdb_local_authentication_enabled)
        self.assertEqual(facts.min_tls_version, "Tls11")
        self.assertEqual(facts.cosmosdb_minimal_tls_version, "Tls11")
        self.assertFalse(facts.cosmosdb_automatic_failover_enabled)
        self.assertFalse(facts.cosmosdb_multiple_write_locations_enabled)
        self.assertEqual(facts.cosmosdb_posture_uncertainties, [])

    def test_missing_optional_posture_materializes_effective_provider_defaults(self) -> None:
        inventory = AzureNormalizer().normalize([_account()])
        account = inventory.resources[0]
        facts = azure_facts(account)

        self.assertEqual(facts.cosmosdb_kind, "GlobalDocumentDB")
        self.assertEqual(facts.cosmosdb_default_identity_type, "FirstPartyIdentity")
        self.assertEqual(facts.cosmosdb_customer_managed_key_state, "not_configured")
        self.assertEqual(facts.cosmosdb_backup_configuration_state, "not_configured")
        self.assertFalse(facts.cosmosdb_backup_block_configured)
        self.assertEqual(facts.cosmosdb_backup_type, "Periodic")
        self.assertEqual(facts.cosmosdb_backup_interval_minutes, 240)
        self.assertEqual(facts.cosmosdb_backup_retention_hours, 8)
        self.assertEqual(facts.cosmosdb_backup_storage_redundancy, "Geo")
        self.assertEqual(facts.public_network_fallback_state, "enabled")
        self.assertTrue(facts.public_network_access_enabled)
        self.assertEqual(facts.cosmosdb_ip_range_filter_state, "not_configured")
        self.assertEqual(facts.cosmosdb_virtual_network_filter_state, "not_configured")
        self.assertEqual(facts.cosmosdb_virtual_network_rule_state, "not_configured")
        self.assertEqual(facts.cosmosdb_network_acl_bypass_state, "disabled")
        self.assertFalse(facts.cosmosdb_network_acl_bypass_enabled)
        self.assertEqual(facts.cosmosdb_network_acl_bypass_ids_state, "not_configured")
        self.assertEqual(facts.cosmosdb_local_authentication_state, "enabled")
        self.assertTrue(facts.cosmosdb_local_authentication_enabled)
        self.assertEqual(facts.min_tls_version, "Tls12")
        self.assertEqual(facts.cosmosdb_automatic_failover_state, "not_configured")
        self.assertEqual(facts.cosmosdb_multiple_write_locations_state, "not_configured")
        self.assertEqual(facts.cosmosdb_geo_location_state, "not_configured")
        self.assertEqual(facts.cosmosdb_posture_uncertainties, [])
        self.assertTrue(account.storage_encrypted)

    def test_periodic_backup_block_materializes_omitted_field_defaults(self) -> None:
        facts = azure_facts(
            AzureNormalizer().normalize([_account(values={"backup": [{"type": "Periodic"}]})]).resources[0]
        )

        self.assertEqual(facts.cosmosdb_backup_configuration_state, "configured")
        self.assertTrue(facts.cosmosdb_backup_block_configured)
        self.assertEqual(facts.cosmosdb_backup_type, "Periodic")
        self.assertEqual(facts.cosmosdb_backup_interval_minutes, 240)
        self.assertEqual(facts.cosmosdb_backup_retention_hours, 8)
        self.assertEqual(facts.cosmosdb_backup_storage_redundancy, "Geo")
        self.assertEqual(facts.cosmosdb_posture_uncertainties, [])

    def test_periodic_backup_unknown_field_is_not_replaced_by_default(self) -> None:
        facts = azure_facts(
            AzureNormalizer()
            .normalize(
                [
                    _account(
                        values={
                            "backup": [
                                {
                                    "type": "Periodic",
                                    "interval_in_minutes": None,
                                }
                            ]
                        },
                        unknown_values={"backup": [{"interval_in_minutes": True}]},
                    )
                ]
            )
            .resources[0]
        )

        self.assertEqual(facts.cosmosdb_backup_configuration_state, "configured")
        self.assertTrue(facts.cosmosdb_backup_block_configured)
        self.assertIsNone(facts.cosmosdb_backup_interval_minutes)
        self.assertEqual(facts.cosmosdb_backup_retention_hours, 8)
        self.assertEqual(facts.cosmosdb_backup_storage_redundancy, "Geo")
        self.assertEqual(
            facts.cosmosdb_posture_uncertainties,
            ["backup.interval_in_minutes is unknown after planning"],
        )

    def test_legacy_local_authentication_field_is_normalized_to_enabled_posture(self) -> None:
        for disabled, expected_enabled, expected_state in (
            (True, False, "disabled"),
            (False, True, "enabled"),
        ):
            with self.subTest(local_authentication_disabled=disabled):
                facts = azure_facts(
                    AzureNormalizer()
                    .normalize([_account(values={"local_authentication_disabled": disabled})])
                    .resources[0]
                )

                self.assertEqual(facts.cosmosdb_local_authentication_enabled, expected_enabled)
                self.assertEqual(facts.cosmosdb_local_authentication_state, expected_state)

    def test_unknown_legacy_local_authentication_value_remains_unknown(self) -> None:
        facts = azure_facts(
            AzureNormalizer()
            .normalize(
                [
                    _account(
                        values={"local_authentication_disabled": None},
                        unknown_values={"local_authentication_disabled": True},
                    )
                ]
            )
            .resources[0]
        )

        self.assertEqual(facts.cosmosdb_local_authentication_state, "unknown")
        self.assertIsNone(facts.cosmosdb_local_authentication_enabled)
        self.assertEqual(
            facts.cosmosdb_posture_uncertainties,
            ["local_authentication_disabled is unknown after planning"],
        )

    def test_unknown_posture_values_remain_unknown_with_field_evidence(self) -> None:
        facts = azure_facts(
            AzureNormalizer()
            .normalize(
                [
                    _account(
                        values={
                            "key_vault_key_id": None,
                            "backup": [{"type": None}],
                            "public_network_access_enabled": None,
                            "ip_range_filter": [],
                            "is_virtual_network_filter_enabled": None,
                            "virtual_network_rule": [{"id": None}],
                            "network_acl_bypass_for_azure_services": None,
                            "network_acl_bypass_ids": [],
                            "local_authentication_enabled": None,
                            "minimal_tls_version": None,
                            "identity": [],
                            "automatic_failover_enabled": None,
                            "multiple_write_locations_enabled": None,
                            "geo_location": [{"location": None, "failover_priority": None}],
                        },
                        unknown_values={
                            "location": True,
                            "kind": True,
                            "offer_type": True,
                            "key_vault_key_id": True,
                            "default_identity_type": True,
                            "backup": [{"type": True}],
                            "public_network_access_enabled": True,
                            "ip_range_filter": True,
                            "is_virtual_network_filter_enabled": True,
                            "virtual_network_rule": [{"id": True}],
                            "network_acl_bypass_for_azure_services": True,
                            "network_acl_bypass_ids": True,
                            "local_authentication_enabled": True,
                            "minimal_tls_version": True,
                            "identity": True,
                            "automatic_failover_enabled": True,
                            "multiple_write_locations_enabled": True,
                            "geo_location": [
                                {
                                    "location": True,
                                    "failover_priority": True,
                                    "zone_redundant": True,
                                }
                            ],
                        },
                    )
                ]
            )
            .resources[0]
        )

        self.assertEqual(facts.cosmosdb_customer_managed_key_state, "unknown")
        self.assertEqual(facts.cosmosdb_backup_configuration_state, "configured")
        self.assertTrue(facts.cosmosdb_backup_block_configured)
        self.assertEqual(facts.public_network_fallback_state, "unknown")
        self.assertEqual(facts.cosmosdb_ip_range_filter_state, "unknown")
        self.assertEqual(facts.cosmosdb_virtual_network_filter_state, "unknown")
        self.assertEqual(facts.cosmosdb_virtual_network_rule_state, "unknown")
        self.assertEqual(facts.cosmosdb_network_acl_bypass_state, "unknown")
        self.assertEqual(facts.cosmosdb_network_acl_bypass_ids_state, "unknown")
        self.assertEqual(facts.cosmosdb_local_authentication_state, "unknown")
        self.assertIsNone(facts.min_tls_version)
        self.assertEqual(facts.cosmosdb_automatic_failover_state, "unknown")
        self.assertEqual(facts.cosmosdb_multiple_write_locations_state, "unknown")
        self.assertEqual(facts.cosmosdb_geo_location_state, "unknown")
        self.assertEqual(
            facts.cosmosdb_posture_uncertainties,
            [
                "public_network_access_enabled is unknown after planning",
                "key_vault_key_id is unknown after planning",
                "backup.type is unknown after planning",
                "ip_range_filter is unknown after planning",
                "network_acl_bypass_ids is unknown after planning",
                "virtual_network_rule[0].id is unknown after planning",
                "geo_location[0].location is unknown after planning",
                "geo_location[0].failover_priority is unknown after planning",
                "geo_location[0].zone_redundant is unknown after planning",
                "location is unknown after planning",
                "kind is unknown after planning",
                "offer_type is unknown after planning",
                "default_identity_type is unknown after planning",
                "is_virtual_network_filter_enabled is unknown after planning",
                "network_acl_bypass_for_azure_services is unknown after planning",
                "local_authentication_enabled is unknown after planning",
                "automatic_failover_enabled is unknown after planning",
                "multiple_write_locations_enabled is unknown after planning",
                "minimal_tls_version is unknown after planning",
            ],
        )
        self.assertEqual(facts.managed_identity_uncertainties, ["identity is unknown after planning"])

    def test_account_is_supported_as_azure_data_store_and_database(self) -> None:
        inventory = AzureNormalizer().normalize([_account()])
        registry = default_resource_capability_registry()

        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual([resource.address for resource in inventory.resources], ["azurerm_cosmosdb_account.orders"])
        self.assertTrue(registry.has_capability(inventory.resources[0], ResourceCapability.DATA_STORE))
        self.assertTrue(registry.has_capability(inventory.resources[0], ResourceCapability.DATABASE))
        self.assertEqual(StrideRuleEngine().evaluate(inventory, []), [])


if __name__ == "__main__":
    unittest.main()

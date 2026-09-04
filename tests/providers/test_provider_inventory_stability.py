from __future__ import annotations

import unittest
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path

from tests.integration.analysis_support import AZURE_FIXTURE_PATH, FIXTURE_PATH, GCP_FIXTURE_PATH
from tfstride.app import TfStride
from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES
from tfstride.providers.azure.normalizer import SUPPORTED_AZURE_TYPES
from tfstride.providers.gcp.normalizer import SUPPORTED_GCP_TYPES
from tfstride.resource_metadata import InventoryMetadata


@dataclass(frozen=True, slots=True)
class _ProviderInventoryCase:
    provider: str
    fixture_path: Path
    expected_addresses: tuple[str, ...]
    supported_resource_types: Collection[str]
    expected_supported_type_count: int
    expected_input_count: int
    expected_unsupported_resources: tuple[str, ...]
    expected_unsupported_resource_types: Mapping[str, int]
    expected_primary_account_id: str | None
    expected_registered_rule_count: int


_PROVIDER_INVENTORY_CASES = (
    _ProviderInventoryCase(
        provider="aws",
        fixture_path=FIXTURE_PATH,
        expected_addresses=(
            "aws_vpc.main",
            "aws_subnet.public_app",
            "aws_subnet.private_data",
            "aws_internet_gateway.main",
            "aws_route_table.public",
            "aws_nat_gateway.main",
            "aws_route_table.private",
            "aws_route_table_association.public_app",
            "aws_route_table_association.private_data",
            "aws_security_group.app",
            "aws_security_group_rule.app_ssh_from_internet",
            "aws_security_group_rule.app_http_from_internet",
            "aws_security_group.db",
            "aws_security_group_rule.db_from_public_app",
            "aws_security_group_rule.db_from_internet",
            "aws_lb.web",
            "aws_instance.app",
            "aws_db_instance.app",
            "aws_s3_bucket.assets",
            "aws_iam_role.workload",
            "aws_iam_policy.admin_like",
            "aws_iam_role_policy_attachment.workload_admin_like",
            "aws_lambda_function.processor",
        ),
        supported_resource_types=SUPPORTED_AWS_TYPES,
        expected_supported_type_count=70,
        expected_input_count=24,
        expected_unsupported_resources=("aws_cloudwatch_log_group.processor",),
        expected_unsupported_resource_types={"aws_cloudwatch_log_group": 1},
        expected_primary_account_id="111122223333",
        expected_registered_rule_count=104,
    ),
    _ProviderInventoryCase(
        provider="gcp",
        fixture_path=GCP_FIXTURE_PATH,
        expected_addresses=(
            "google_compute_network.main",
            "google_compute_subnetwork.app",
            "google_compute_route.default_internet",
            "google_compute_firewall.public_ssh",
            "google_compute_firewall.public_app",
            "google_service_account.web",
            "google_service_account_key.web",
            "google_compute_instance.web",
            "google_sql_database_instance.app",
            "google_storage_bucket.logs",
            "google_storage_bucket_iam_member.public_logs_reader",
            "google_secret_manager_secret.api_key",
            "google_secret_manager_secret_iam_member.public_accessor",
            "google_kms_crypto_key.customer",
            "google_kms_crypto_key_iam_member.partner_decrypter",
            "google_pubsub_topic.events",
            "google_pubsub_subscription.events",
            "google_pubsub_topic_iam_member.public_publisher",
            "google_bigquery_dataset.analytics",
            "google_bigquery_table.events",
            "google_bigquery_dataset_iam_binding.analytics_viewers",
            "google_project_iam_member.web_viewer",
            "google_logging_project_sink.processor",
        ),
        supported_resource_types=SUPPORTED_GCP_TYPES,
        expected_supported_type_count=118,
        expected_input_count=23,
        expected_unsupported_resources=(),
        expected_unsupported_resource_types={},
        expected_primary_account_id=None,
        expected_registered_rule_count=97,
    ),
    _ProviderInventoryCase(
        provider="azure",
        fixture_path=AZURE_FIXTURE_PATH,
        expected_addresses=(
            "azurerm_storage_account.assets",
            "azurerm_storage_account_network_rules.assets",
            "azurerm_storage_container.public_assets",
            "azurerm_virtual_network.main",
            "azurerm_subnet.web",
            "azurerm_network_security_group.web_subnet",
            "azurerm_subnet_network_security_group_association.web",
            "azurerm_network_security_group.web_nic",
            "azurerm_network_security_rule.allow_ssh",
            "azurerm_public_ip.web",
            "azurerm_network_interface.web",
            "azurerm_network_interface_security_group_association.web",
            "azurerm_linux_virtual_machine.web",
            "azurerm_kubernetes_cluster.platform",
            "azurerm_key_vault.application",
        ),
        supported_resource_types=SUPPORTED_AZURE_TYPES,
        expected_supported_type_count=63,
        expected_input_count=15,
        expected_unsupported_resources=(),
        expected_unsupported_resource_types={},
        expected_primary_account_id=None,
        expected_registered_rule_count=116,
    ),
)


class ProviderInventoryStabilityTests(unittest.TestCase):
    maxDiff = None

    def test_real_provider_inventories_and_rule_counts_stay_stable(self) -> None:
        for case in _PROVIDER_INVENTORY_CASES:
            with self.subTest(provider=case.provider):
                result = TfStride(provider=case.provider).analyze_plan(case.fixture_path)
                inventory = result.inventory
                source_resources = {
                    resource.address: resource for resource in load_terraform_plan(case.fixture_path).resources
                }

                self.assertEqual(inventory.provider, case.provider)
                self.assertEqual(
                    tuple(resource.address for resource in inventory.resources),
                    case.expected_addresses,
                )
                self.assertEqual(
                    tuple(resource.resource_type for resource in inventory.resources),
                    tuple(address.split(".", 1)[0] for address in case.expected_addresses),
                )
                self.assertTrue(all(resource.provider == case.provider for resource in inventory.resources))
                self.assertEqual(
                    tuple(inventory.unsupported_resources),
                    case.expected_unsupported_resources,
                )

                self.assertEqual(len(case.supported_resource_types), case.expected_supported_type_count)
                expected_metadata: dict[str, object] = {
                    InventoryMetadata.SUPPORTED_RESOURCE_TYPES.key: sorted(case.supported_resource_types),
                    InventoryMetadata.TOTAL_INPUT_RESOURCES.key: case.expected_input_count,
                    InventoryMetadata.PROVIDER_RESOURCE_COUNT.key: case.expected_input_count,
                    InventoryMetadata.NORMALIZED_RESOURCE_COUNT.key: len(case.expected_addresses),
                    InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.key: dict(case.expected_unsupported_resource_types),
                }
                if case.expected_primary_account_id is not None:
                    expected_metadata[InventoryMetadata.PRIMARY_ACCOUNT_ID.key] = case.expected_primary_account_id
                self.assertEqual(inventory.metadata_snapshot(), expected_metadata)
                self.assertEqual(inventory.primary_account_id, case.expected_primary_account_id)

                for resource in inventory.resources:
                    source = source_resources[resource.address]
                    self.assertEqual(resource.provider_config_key, source.provider_config_key)
                    self.assertEqual(resource.reference_resolutions, source.reference_resolutions)
                    with self.assertRaisesRegex(RuntimeError, "decoration state is frozen"):
                        resource.add_attached_role_arn("arn:test:late-decoration")

                resource_coverage = result.analysis_coverage.resources
                self.assertEqual(resource_coverage.total_resources, case.expected_input_count)
                self.assertEqual(resource_coverage.provider_resources, case.expected_input_count)
                self.assertEqual(resource_coverage.normalized_resources, len(case.expected_addresses))
                self.assertEqual(
                    resource_coverage.unsupported_resources,
                    len(case.expected_unsupported_resources),
                )
                self.assertEqual(
                    resource_coverage.unsupported_resource_types,
                    dict(case.expected_unsupported_resource_types),
                )

                rule_coverage = result.analysis_coverage.rules
                self.assertEqual(
                    rule_coverage.registered_rule_count,
                    case.expected_registered_rule_count,
                )
                self.assertEqual(
                    len(rule_coverage.enabled_rules),
                    case.expected_registered_rule_count,
                )
                self.assertTrue(all(rule_id.startswith(f"{case.provider}-") for rule_id in rule_coverage.enabled_rules))


if __name__ == "__main__":
    unittest.main()

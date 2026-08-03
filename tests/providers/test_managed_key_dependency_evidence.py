from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.aws.kms_dependency_evidence import AwsKmsEncryptionDependency
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.key_vault_dependency_evidence import AzureKeyVaultEncryptionDependency
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.gcp.kms_dependency_evidence import GcpKmsEncryptionDependency
from tfstride.providers.gcp.resource_facts import gcp_facts


def _resource(provider: str) -> NormalizedResource:
    return NormalizedResource(
        address=f"{provider}_consumer.data",
        provider=provider,
        resource_type=f"{provider}_consumer",
        name="data",
        category=ResourceCategory.DATA,
    )


class ManagedKeyDependencyEvidenceTests(unittest.TestCase):
    def test_aws_dependency_contract_preserves_alias_resolution(self) -> None:
        resource = _resource("aws")
        dependency: AwsKmsEncryptionDependency = {
            "dependent_address": resource.address,
            "dependent_resource_type": resource.resource_type,
            "dependency_source_address": resource.address,
            "dependency_source_type": resource.resource_type,
            "configuration_path": ["server_side_encryption", 0, "kms_key_arn"],
            "configured_key_reference": "alias/orders",
            "reference_provenance": "planned_value",
            "reference_kind": "alias_name",
            "resolution_state": "resolved",
            "encryption_ownership_state": "customer_managed",
            "candidate_targets": [
                {
                    "address": "aws_kms_alias.orders",
                    "target_kind": "alias",
                }
            ],
            "key_address": "aws_kms_key.orders",
            "key_arn": "arn:aws:kms:us-east-1:111122223333:key/key-0001",
            "key_id": "key-0001",
            "alias_address": "aws_kms_alias.orders",
            "alias_name": "alias/orders",
            "alias_arn": "arn:aws:kms:us-east-1:111122223333:alias/orders",
            "key_origin": "AWS_KMS",
            "multi_region_state": "disabled",
            "posture_uncertainties": [],
        }

        facts = aws_facts(resource)
        facts.set_kms_encryption_dependency_posture(
            dependencies=[dependency],
            uncertainties=[],
        )

        self.assertEqual(facts.kms_encryption_dependencies, [dependency])
        self.assertEqual(facts.kms_encryption_dependency_uncertainties, [])
        self.assertEqual(facts.kms_encryption_dependencies[0]["alias_address"], "aws_kms_alias.orders")

    def test_aws_ambiguous_alias_candidates_are_not_promoted(self) -> None:
        resource = _resource("aws")
        dependency: AwsKmsEncryptionDependency = {
            "dependent_address": resource.address,
            "dependent_resource_type": resource.resource_type,
            "dependency_source_address": resource.address,
            "dependency_source_type": resource.resource_type,
            "configuration_path": ["server_side_encryption", 0, "kms_key_arn"],
            "configured_key_reference": "aws_kms_alias.selected.arn",
            "reference_provenance": "configuration_reference",
            "reference_kind": "terraform_reference",
            "resolution_state": "ambiguous",
            "encryption_ownership_state": "unknown",
            "candidate_targets": [
                {"address": "aws_kms_alias.blue", "target_kind": "alias"},
                {"address": "aws_kms_alias.green", "target_kind": "alias"},
            ],
            "key_address": None,
            "key_arn": None,
            "key_id": None,
            "alias_address": None,
            "alias_name": None,
            "alias_arn": None,
            "key_origin": None,
            "multi_region_state": None,
            "posture_uncertainties": ["alias reference has multiple modeled candidates"],
        }

        facts = aws_facts(resource)
        facts.set_kms_encryption_dependency_posture(
            dependencies=[dependency],
            uncertainties=dependency["posture_uncertainties"],
        )

        self.assertEqual(
            facts.kms_encryption_dependencies[0]["candidate_targets"],
            [
                {"address": "aws_kms_alias.blue", "target_kind": "alias"},
                {"address": "aws_kms_alias.green", "target_kind": "alias"},
            ],
        )
        self.assertIsNone(facts.kms_encryption_dependencies[0]["alias_address"])
        self.assertIsNone(facts.kms_encryption_dependencies[0]["key_address"])

    def test_gcp_dependency_contract_preserves_key_and_version_ancestry(self) -> None:
        resource = _resource("gcp")
        dependency: GcpKmsEncryptionDependency = {
            "dependent_address": resource.address,
            "dependent_resource_type": resource.resource_type,
            "dependency_source_address": resource.address,
            "dependency_source_type": resource.resource_type,
            "configuration_path": ["kms_key_name"],
            "configured_key_reference": "projects/app/locations/us/keyRings/data/cryptoKeys/orders",
            "reference_provenance": "configuration_reference",
            "reference_kind": "crypto_key_resource_name",
            "resolution_state": "resolved",
            "customer_managed_encryption_state": "configured",
            "candidate_targets": [
                {
                    "address": "google_kms_crypto_key.orders",
                    "target_kind": "crypto_key",
                }
            ],
            "key_address": "google_kms_crypto_key.orders",
            "key_resource_name": "projects/app/locations/us/keyRings/data/cryptoKeys/orders",
            "key_project": "app",
            "key_location": "us",
            "key_ring": "projects/app/locations/us/keyRings/data",
            "key_purpose": "ENCRYPT_DECRYPT",
            "key_version_address": None,
            "key_version_resource_name": None,
            "version_reference_is_explicit": False,
            "posture_uncertainties": [],
        }

        facts = gcp_facts(resource)
        facts.set_kms_encryption_dependency_posture(
            dependencies=[dependency],
            uncertainties=[],
        )

        self.assertEqual(facts.kms_encryption_dependencies, [dependency])
        self.assertFalse(facts.kms_encryption_dependencies[0]["version_reference_is_explicit"])
        self.assertEqual(
            facts.kms_encryption_dependencies[0]["key_ring"],
            "projects/app/locations/us/keyRings/data",
        )

    def test_gcp_ambiguous_version_candidates_are_not_promoted(self) -> None:
        resource = _resource("gcp")
        dependency: GcpKmsEncryptionDependency = {
            "dependent_address": resource.address,
            "dependent_resource_type": resource.resource_type,
            "dependency_source_address": resource.address,
            "dependency_source_type": resource.resource_type,
            "configuration_path": ["kms_key_name"],
            "configured_key_reference": "google_kms_crypto_key_version.selected.name",
            "reference_provenance": "configuration_reference",
            "reference_kind": "terraform_reference",
            "resolution_state": "ambiguous",
            "customer_managed_encryption_state": "unknown",
            "candidate_targets": [
                {
                    "address": "google_kms_crypto_key_version.blue",
                    "target_kind": "crypto_key_version",
                },
                {
                    "address": "google_kms_crypto_key_version.green",
                    "target_kind": "crypto_key_version",
                },
            ],
            "key_address": None,
            "key_resource_name": None,
            "key_project": None,
            "key_location": None,
            "key_ring": None,
            "key_purpose": None,
            "key_version_address": None,
            "key_version_resource_name": None,
            "version_reference_is_explicit": True,
            "posture_uncertainties": ["key version reference has multiple modeled candidates"],
        }

        facts = gcp_facts(resource)
        facts.set_kms_encryption_dependency_posture(
            dependencies=[dependency],
            uncertainties=dependency["posture_uncertainties"],
        )

        self.assertEqual(
            [candidate["target_kind"] for candidate in facts.kms_encryption_dependencies[0]["candidate_targets"]],
            ["crypto_key_version", "crypto_key_version"],
        )
        self.assertIsNone(facts.kms_encryption_dependencies[0]["key_version_address"])
        self.assertIsNone(facts.kms_encryption_dependencies[0]["key_address"])

    def test_gcp_unresolved_version_identity_retains_unique_symbolic_candidate(self) -> None:
        resource = _resource("gcp")
        dependency: GcpKmsEncryptionDependency = {
            "dependent_address": resource.address,
            "dependent_resource_type": resource.resource_type,
            "dependency_source_address": resource.address,
            "dependency_source_type": resource.resource_type,
            "configuration_path": ["kms_key_name"],
            "configured_key_reference": "google_kms_crypto_key_version.pending.name",
            "reference_provenance": "configuration_reference",
            "reference_kind": "terraform_reference",
            "resolution_state": "unresolved",
            "customer_managed_encryption_state": "unknown",
            "candidate_targets": [
                {
                    "address": "google_kms_crypto_key_version.pending",
                    "target_kind": "crypto_key_version",
                }
            ],
            "key_address": None,
            "key_resource_name": None,
            "key_project": None,
            "key_location": None,
            "key_ring": None,
            "key_purpose": None,
            "key_version_address": None,
            "key_version_resource_name": None,
            "version_reference_is_explicit": True,
            "posture_uncertainties": ["key version identity is unknown after planning"],
        }

        facts = gcp_facts(resource)
        facts.set_kms_encryption_dependency_posture(
            dependencies=[dependency],
            uncertainties=dependency["posture_uncertainties"],
        )

        self.assertEqual(
            facts.kms_encryption_dependencies[0]["candidate_targets"],
            [
                {
                    "address": "google_kms_crypto_key_version.pending",
                    "target_kind": "crypto_key_version",
                }
            ],
        )
        self.assertEqual(facts.kms_encryption_dependencies[0]["resolution_state"], "unresolved")
        self.assertIsNone(facts.kms_encryption_dependencies[0]["key_version_resource_name"])
        self.assertIsNone(facts.kms_encryption_dependencies[0]["key_version_address"])

    def test_azure_dependency_contract_keeps_versioned_and_versionless_identities_distinct(self) -> None:
        resource = _resource("azure")
        dependency: AzureKeyVaultEncryptionDependency = {
            "dependent_address": resource.address,
            "dependent_resource_type": resource.resource_type,
            "dependency_source_address": resource.address,
            "dependency_source_type": resource.resource_type,
            "configuration_path": ["key_vault_key_id"],
            "configured_key_reference": "https://app.vault.azure.net/keys/orders/v1",
            "reference_provenance": "planned_value",
            "reference_kind": "versioned_uri",
            "resolution_state": "resolved",
            "customer_managed_key_state": "configured",
            "candidate_key_addresses": ["azurerm_key_vault_key.orders"],
            "target_kind": "key_version",
            "key_address": "azurerm_key_vault_key.orders",
            "key_vault_address": "azurerm_key_vault.app",
            "key_vault_id": "/subscriptions/sub/resourceGroups/app/providers/Microsoft.KeyVault/vaults/app",
            "key_vault_uri": "https://app.vault.azure.net/",
            "key_name": "orders",
            "key_version": "v1",
            "key_uri": "https://app.vault.azure.net/keys/orders/v1",
            "key_versionless_uri": "https://app.vault.azure.net/keys/orders",
            "key_resource_id": (
                "/subscriptions/sub/resourceGroups/app/providers/Microsoft.KeyVault/vaults/app/keys/orders/v1"
            ),
            "key_versionless_resource_id": (
                "/subscriptions/sub/resourceGroups/app/providers/Microsoft.KeyVault/vaults/app/keys/orders"
            ),
            "posture_uncertainties": [],
        }

        facts = azure_facts(resource)
        facts.set_key_vault_encryption_dependency_posture(
            dependencies=[dependency],
            uncertainties=[],
        )

        self.assertEqual(facts.key_vault_encryption_dependencies, [dependency])
        self.assertNotEqual(
            facts.key_vault_encryption_dependencies[0]["key_uri"],
            facts.key_vault_encryption_dependencies[0]["key_versionless_uri"],
        )
        self.assertEqual(facts.key_vault_encryption_dependency_uncertainties, [])


if __name__ == "__main__":
    unittest.main()

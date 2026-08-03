from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import (
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
    TerraformResource,
)
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_AWS_ACCOUNT_ID = "111122223333"
_AWS_KEY_ID = "11111111-1111-1111-1111-111111111111"
_AWS_KEY_ARN = f"arn:aws:kms:us-east-1:{_AWS_ACCOUNT_ID}:key/{_AWS_KEY_ID}"
_AWS_ALIAS_NAME = "alias/orders"
_AWS_ALIAS_ARN = f"arn:aws:kms:us-east-1:{_AWS_ACCOUNT_ID}:{_AWS_ALIAS_NAME}"

_GCP_PROJECT = "tfstride-demo"
_GCP_KEY_RING = f"projects/{_GCP_PROJECT}/locations/global/keyRings/application"
_GCP_KEY_PATH = f"{_GCP_KEY_RING}/cryptoKeys/orders"
_GCP_VERSION_PATH = f"{_GCP_KEY_PATH}/cryptoKeyVersions/1"

_AZURE_SUBSCRIPTION_ID = "sub-0001"
_AZURE_VAULT_ID = (
    f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}/resourceGroups/security/providers/Microsoft.KeyVault/vaults/application"
)
_AZURE_VAULT_URI = "https://application.vault.azure.net"
_AZURE_KEY_VERSION = "version-0001"
_AZURE_KEY_VERSIONLESS_URI = f"{_AZURE_VAULT_URI}/keys/orders"
_AZURE_KEY_URI = f"{_AZURE_KEY_VERSIONLESS_URI}/{_AZURE_KEY_VERSION}"
_AZURE_KEY_VERSIONLESS_RESOURCE_ID = f"{_AZURE_VAULT_ID}/keys/orders"
_AZURE_KEY_RESOURCE_ID = f"{_AZURE_KEY_VERSIONLESS_RESOURCE_ID}/{_AZURE_KEY_VERSION}"


def _resource(
    provider: str,
    resource_type: str,
    name: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = (),
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name=f"registry.terraform.io/hashicorp/{provider}",
        values=values,
        unknown_values=unknown_values or {},
        reference_resolutions=reference_resolutions,
    )


def _reference_resolution(
    path: tuple[str | int, ...],
    targets: tuple[str, ...],
    target_suffix: str,
    *,
    state: TerraformReferenceResolutionState = (TerraformReferenceResolutionState.SYMBOLIC),
) -> TerraformReferenceResolution:
    references = tuple(f"{target}{target_suffix}" for target in targets)
    return TerraformReferenceResolution(
        path=path,
        state=state,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=references,
        targets=tuple(
            TerraformReferenceTarget(address=target, reference=reference)
            for target, reference in zip(targets, references, strict=True)
        ),
    )


def _aws_key(
    name: str = "orders",
    *,
    exact_identity: bool = True,
) -> TerraformResource:
    values: dict[str, Any] = {
        "key_usage": "ENCRYPT_DECRYPT",
        "key_spec": "SYMMETRIC_DEFAULT",
        "origin": "AWS_KMS",
    }
    unknown_values: dict[str, Any] = {}
    if exact_identity:
        key_id = _AWS_KEY_ID if name == "orders" else "22222222-2222-2222-2222-222222222222"
        values.update(
            {
                "id": key_id,
                "key_id": key_id,
                "arn": (_AWS_KEY_ARN if name == "orders" else f"arn:aws:kms:us-east-1:{_AWS_ACCOUNT_ID}:key/{key_id}"),
            }
        )
    else:
        values.update({"id": None, "key_id": None, "arn": None})
        unknown_values.update({"id": True, "key_id": True, "arn": True})
    return _resource(
        "aws",
        "aws_kms_key",
        name,
        values,
        unknown_values=unknown_values,
    )


def _aws_table(
    name: str,
    *,
    key_arn: str | None = None,
    key_reference: TerraformReferenceResolution | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "name": name,
        "arn": f"arn:aws:dynamodb:us-east-1:{_AWS_ACCOUNT_ID}:table/{name}",
    }
    unknown_values: dict[str, Any] = {}
    if key_arn is not None:
        values["server_side_encryption"] = [
            {
                "enabled": True,
                "kms_key_arn": key_arn,
            }
        ]
    elif key_reference is not None:
        values["server_side_encryption"] = [
            {
                "enabled": True,
                "kms_key_arn": None,
            }
        ]
        unknown_values["server_side_encryption"] = [
            {
                "kms_key_arn": True,
            }
        ]
    return _resource(
        "aws",
        "aws_dynamodb_table",
        name,
        values,
        unknown_values=unknown_values,
        reference_resolutions=(key_reference,) if key_reference is not None else (),
    )


def _gcp_key_ring() -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.KMS_KEY_RING,
        "application",
        {
            "id": _GCP_KEY_RING,
            "name": "application",
            "project": _GCP_PROJECT,
            "location": "global",
        },
    )


def _gcp_key(
    name: str = "orders",
    *,
    exact_identity: bool = True,
) -> TerraformResource:
    key_path = _GCP_KEY_PATH if name == "orders" else f"{_GCP_KEY_RING}/cryptoKeys/{name}"
    values: dict[str, Any] = {
        "name": name,
        "purpose": "ENCRYPT_DECRYPT",
    }
    unknown_values: dict[str, Any] = {}
    if exact_identity:
        values.update(
            {
                "id": key_path,
                "key_ring": _GCP_KEY_RING,
            }
        )
    else:
        values.update({"id": None, "key_ring": None})
        unknown_values.update({"id": True, "key_ring": True})
    return _resource(
        "google",
        GcpResourceType.KMS_CRYPTO_KEY,
        name,
        values,
        unknown_values=unknown_values,
    )


def _gcp_version() -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.KMS_CRYPTO_KEY_VERSION,
        "primary",
        {
            "crypto_key": "google_kms_crypto_key.orders.id",
            "id": _GCP_VERSION_PATH,
            "name": _GCP_VERSION_PATH,
            "state": "ENABLED",
            "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
            "protection_level": "SOFTWARE",
            "generate_time": "2026-07-24T00:00:00Z",
        },
    )


def _gcp_topic(
    name: str,
    *,
    key_name: str | None = None,
    key_reference: TerraformReferenceResolution | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": f"projects/{_GCP_PROJECT}/topics/{name}",
        "name": name,
        "project": _GCP_PROJECT,
    }
    unknown_values: dict[str, Any] = {}
    if key_name is not None:
        values["kms_key_name"] = key_name
    elif key_reference is not None:
        values["kms_key_name"] = None
        unknown_values["kms_key_name"] = True
    return _resource(
        "google",
        GcpResourceType.PUBSUB_TOPIC,
        name,
        values,
        unknown_values=unknown_values,
        reference_resolutions=(key_reference,) if key_reference is not None else (),
    )


def _azure_vault() -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.KEY_VAULT,
        "application",
        {
            "id": _AZURE_VAULT_ID,
            "name": "application",
            "vault_uri": _AZURE_VAULT_URI,
            "tenant_id": "tenant-id",
        },
    )


def _azure_key(
    name: str = "orders",
    *,
    exact_identity: bool = True,
) -> TerraformResource:
    values: dict[str, Any] = {
        "name": name,
        "key_type": "RSA",
        "key_opts": ["decrypt", "encrypt", "unwrapKey", "wrapKey"],
    }
    unknown_values: dict[str, Any] = {}
    if exact_identity:
        if name == "orders":
            versionless_uri = _AZURE_KEY_VERSIONLESS_URI
            versioned_uri = _AZURE_KEY_URI
            versionless_resource_id = _AZURE_KEY_VERSIONLESS_RESOURCE_ID
            versioned_resource_id = _AZURE_KEY_RESOURCE_ID
        else:
            versionless_uri = f"{_AZURE_VAULT_URI}/keys/{name}"
            versioned_uri = f"{versionless_uri}/{_AZURE_KEY_VERSION}"
            versionless_resource_id = f"{_AZURE_VAULT_ID}/keys/{name}"
            versioned_resource_id = f"{versionless_resource_id}/{_AZURE_KEY_VERSION}"
        values.update(
            {
                "id": versioned_uri,
                "versionless_id": versionless_uri,
                "resource_id": versioned_resource_id,
                "resource_versionless_id": versionless_resource_id,
                "version": _AZURE_KEY_VERSION,
                "key_vault_id": "azurerm_key_vault.application.id",
            }
        )
    else:
        values.update(
            {
                "id": None,
                "versionless_id": None,
                "resource_id": None,
                "resource_versionless_id": None,
                "version": None,
                "key_vault_id": None,
            }
        )
        unknown_values.update(
            {
                "id": True,
                "versionless_id": True,
                "resource_id": True,
                "resource_versionless_id": True,
                "version": True,
                "key_vault_id": True,
            }
        )
    return _resource(
        "azurerm",
        AzureResourceType.KEY_VAULT_KEY,
        name,
        values,
        unknown_values=unknown_values,
    )


def _azure_cosmos_account(
    name: str,
    *,
    key_id: str | None = None,
    key_reference: TerraformReferenceResolution | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": (
            f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}/resourceGroups/app/providers/"
            f"Microsoft.DocumentDB/databaseAccounts/{name}"
        ),
        "name": name,
        "resource_group_name": "app",
        "location": "eastus",
        "offer_type": "Standard",
    }
    unknown_values: dict[str, Any] = {}
    if key_id is not None:
        values["key_vault_key_id"] = key_id
    elif key_reference is not None:
        values["key_vault_key_id"] = None
        unknown_values["key_vault_key_id"] = True
    return _resource(
        "azurerm",
        AzureResourceType.COSMOSDB_ACCOUNT,
        name,
        values,
        unknown_values=unknown_values,
        reference_resolutions=(key_reference,) if key_reference is not None else (),
    )


class ManagedKeyEncryptionDependencyCharacterizationTests(unittest.TestCase):
    """Pin dependency inputs without asserting downstream security impact."""

    def test_concrete_key_references_remain_provider_native(self) -> None:
        aws_inventory = AwsNormalizer().normalize(
            [
                _aws_key(),
                _aws_table("orders", key_arn=_AWS_KEY_ARN),
            ]
        )
        gcp_inventory = GcpNormalizer().normalize(
            [
                _gcp_key_ring(),
                _gcp_key(),
                _gcp_topic("orders", key_name=_GCP_KEY_PATH),
            ]
        )
        azure_inventory = AzureNormalizer().normalize(
            [
                _azure_vault(),
                _azure_key(),
                _azure_cosmos_account(
                    "orders",
                    key_id=_AZURE_KEY_VERSIONLESS_URI,
                ),
            ]
        )

        aws_table = aws_inventory.get_by_address("aws_dynamodb_table.orders")
        gcp_topic = gcp_inventory.get_by_address("google_pubsub_topic.orders")
        azure_account = azure_inventory.get_by_address("azurerm_cosmosdb_account.orders")
        assert aws_table is not None
        assert gcp_topic is not None
        assert azure_account is not None

        aws = aws_facts(aws_table)
        self.assertEqual(aws.dynamodb_kms_key_arn, _AWS_KEY_ARN)
        self.assertEqual(
            aws.dynamodb_encryption_ownership_state,
            "customer_managed",
        )
        self.assertTrue(aws_table.storage_encrypted)

        gcp = gcp_facts(gcp_topic)
        self.assertEqual(gcp.pubsub_topic_kms_key_name, _GCP_KEY_PATH)
        self.assertEqual(gcp.pubsub_topic_cmek_state, "configured")
        self.assertTrue(gcp.pubsub_topic_customer_managed_encryption)
        self.assertTrue(gcp_topic.storage_encrypted)

        azure = azure_facts(azure_account)
        self.assertEqual(
            azure.cosmosdb_key_vault_key_id,
            _AZURE_KEY_VERSIONLESS_URI,
        )
        self.assertEqual(
            azure.cosmosdb_customer_managed_key_state,
            "configured",
        )
        self.assertTrue(azure.cosmosdb_customer_managed_encryption)
        self.assertTrue(azure_account.storage_encrypted)

    def test_symbolic_first_apply_references_preserve_exact_candidates(self) -> None:
        aws_resolution = _reference_resolution(
            ("server_side_encryption", 0, "kms_key_arn"),
            ("aws_kms_key.orders",),
            ".arn",
        )
        gcp_resolution = _reference_resolution(
            ("kms_key_name",),
            ("google_kms_crypto_key.orders",),
            ".id",
        )
        azure_resolution = _reference_resolution(
            ("key_vault_key_id",),
            ("azurerm_key_vault_key.orders",),
            ".versionless_id",
        )

        aws_inventory = AwsNormalizer().normalize(
            [
                _aws_key(),
                _aws_table("symbolic", key_reference=aws_resolution),
            ]
        )
        gcp_inventory = GcpNormalizer().normalize(
            [
                _gcp_key_ring(),
                _gcp_key(),
                _gcp_topic("symbolic", key_reference=gcp_resolution),
            ]
        )
        azure_inventory = AzureNormalizer().normalize(
            [
                _azure_vault(),
                _azure_key(),
                _azure_cosmos_account(
                    "symbolic",
                    key_reference=azure_resolution,
                ),
            ]
        )

        aws_table = aws_inventory.get_by_address("aws_dynamodb_table.symbolic")
        gcp_topic = gcp_inventory.get_by_address("google_pubsub_topic.symbolic")
        azure_account = azure_inventory.get_by_address("azurerm_cosmosdb_account.symbolic")
        assert aws_table is not None
        assert gcp_topic is not None
        assert azure_account is not None

        cases = (
            (
                aws_table.reference_resolution(
                    "server_side_encryption",
                    0,
                    "kms_key_arn",
                ),
                "aws_kms_key.orders",
            ),
            (
                gcp_topic.reference_resolution("kms_key_name"),
                "google_kms_crypto_key.orders",
            ),
            (
                azure_account.reference_resolution("key_vault_key_id"),
                "azurerm_key_vault_key.orders",
            ),
        )
        for resolution, target_address in cases:
            with self.subTest(target=target_address):
                self.assertEqual(
                    resolution.state,
                    TerraformReferenceResolutionState.SYMBOLIC,
                )
                self.assertEqual(
                    resolution.provenance,
                    TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
                )
                self.assertEqual(
                    [target.address for target in resolution.targets],
                    [target_address],
                )

        self.assertEqual(
            aws_facts(aws_table).dynamodb_kms_key_arn,
            "aws_kms_key.orders",
        )
        self.assertEqual(
            aws_facts(aws_table).dynamodb_encryption_ownership_state,
            "unknown",
        )
        self.assertIsNone(gcp_facts(gcp_topic).pubsub_topic_kms_key_name)
        self.assertEqual(gcp_facts(gcp_topic).pubsub_topic_cmek_state, "unknown")
        self.assertIsNone(azure_facts(azure_account).cosmosdb_key_vault_key_id)
        self.assertEqual(
            azure_facts(azure_account).cosmosdb_customer_managed_key_state,
            "unknown",
        )

    def test_ambiguous_symbolic_references_do_not_choose_a_key(self) -> None:
        aws_resolution = _reference_resolution(
            ("server_side_encryption", 0, "kms_key_arn"),
            ("aws_kms_key.orders", "aws_kms_key.audit"),
            ".arn",
            state=TerraformReferenceResolutionState.AMBIGUOUS,
        )
        gcp_resolution = _reference_resolution(
            ("kms_key_name",),
            (
                "google_kms_crypto_key.orders",
                "google_kms_crypto_key.audit",
            ),
            ".id",
            state=TerraformReferenceResolutionState.AMBIGUOUS,
        )
        azure_resolution = _reference_resolution(
            ("key_vault_key_id",),
            (
                "azurerm_key_vault_key.orders",
                "azurerm_key_vault_key.audit",
            ),
            ".versionless_id",
            state=TerraformReferenceResolutionState.AMBIGUOUS,
        )

        aws_inventory = AwsNormalizer().normalize(
            [
                _aws_key(),
                _aws_key("audit"),
                _aws_table("ambiguous", key_reference=aws_resolution),
            ]
        )
        gcp_inventory = GcpNormalizer().normalize(
            [
                _gcp_key_ring(),
                _gcp_key(),
                _gcp_key("audit"),
                _gcp_topic("ambiguous", key_reference=gcp_resolution),
            ]
        )
        azure_inventory = AzureNormalizer().normalize(
            [
                _azure_vault(),
                _azure_key(),
                _azure_key("audit"),
                _azure_cosmos_account(
                    "ambiguous",
                    key_reference=azure_resolution,
                ),
            ]
        )

        aws_table = aws_inventory.get_by_address("aws_dynamodb_table.ambiguous")
        gcp_topic = gcp_inventory.get_by_address("google_pubsub_topic.ambiguous")
        azure_account = azure_inventory.get_by_address("azurerm_cosmosdb_account.ambiguous")
        assert aws_table is not None
        assert gcp_topic is not None
        assert azure_account is not None

        resolutions = (
            aws_table.reference_resolution(
                "server_side_encryption",
                0,
                "kms_key_arn",
            ),
            gcp_topic.reference_resolution("kms_key_name"),
            azure_account.reference_resolution("key_vault_key_id"),
        )
        for resolution in resolutions:
            self.assertEqual(
                resolution.state,
                TerraformReferenceResolutionState.AMBIGUOUS,
            )
            self.assertEqual(len(resolution.targets), 2)

        self.assertIsNone(aws_facts(aws_table).dynamodb_kms_key_arn)
        self.assertEqual(
            aws_facts(aws_table).dynamodb_encryption_ownership_state,
            "unknown",
        )
        self.assertIsNone(gcp_facts(gcp_topic).pubsub_topic_kms_key_name)
        self.assertEqual(gcp_facts(gcp_topic).pubsub_topic_cmek_state, "unknown")
        self.assertIsNone(azure_facts(azure_account).cosmosdb_key_vault_key_id)
        self.assertEqual(
            azure_facts(azure_account).cosmosdb_customer_managed_key_state,
            "unknown",
        )

    def test_provider_managed_defaults_do_not_create_customer_key_references(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize([_aws_table("default")])
        gcp_inventory = GcpNormalizer().normalize([_gcp_topic("default")])
        azure_inventory = AzureNormalizer().normalize([_azure_cosmos_account("default")])

        aws_table = aws_inventory.get_by_address("aws_dynamodb_table.default")
        gcp_topic = gcp_inventory.get_by_address("google_pubsub_topic.default")
        azure_account = azure_inventory.get_by_address("azurerm_cosmosdb_account.default")
        assert aws_table is not None
        assert gcp_topic is not None
        assert azure_account is not None

        aws = aws_facts(aws_table)
        self.assertIsNone(aws.dynamodb_kms_key_arn)
        self.assertEqual(aws.dynamodb_encryption_ownership_state, "aws_owned")
        self.assertEqual(
            aws.dynamodb_encryption_configuration_state,
            "not_configured",
        )

        gcp = gcp_facts(gcp_topic)
        self.assertIsNone(gcp.pubsub_topic_kms_key_name)
        self.assertEqual(gcp.pubsub_topic_cmek_state, "not_configured")
        self.assertFalse(gcp.pubsub_topic_customer_managed_encryption)

        azure = azure_facts(azure_account)
        self.assertIsNone(azure.cosmosdb_key_vault_key_id)
        self.assertEqual(
            azure.cosmosdb_customer_managed_key_state,
            "not_configured",
        )
        self.assertFalse(azure.cosmosdb_customer_managed_encryption)

        self.assertTrue(aws_table.storage_encrypted)
        self.assertTrue(gcp_topic.storage_encrypted)
        self.assertTrue(azure_account.storage_encrypted)

    def test_alias_version_and_vault_ancestry_remain_provider_native(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize(
            [
                _aws_key(),
                _resource(
                    "aws",
                    "aws_kms_alias",
                    "orders",
                    {
                        "id": _AWS_ALIAS_NAME,
                        "name": _AWS_ALIAS_NAME,
                        "arn": _AWS_ALIAS_ARN,
                        "target_key_id": "aws_kms_key.orders.key_id",
                        "target_key_arn": _AWS_KEY_ARN,
                    },
                ),
                _resource(
                    "aws",
                    "aws_sqs_queue",
                    "orders",
                    {
                        "name": "orders",
                        "kms_master_key_id": _AWS_ALIAS_NAME,
                        "sqs_managed_sse_enabled": False,
                    },
                ),
            ]
        )
        gcp_inventory = GcpNormalizer().normalize(
            [
                _gcp_key_ring(),
                _gcp_key(),
                _gcp_version(),
            ]
        )
        azure_inventory = AzureNormalizer().normalize(
            [
                _azure_vault(),
                _azure_key(),
            ]
        )

        aws_key = aws_inventory.get_by_address("aws_kms_key.orders")
        aws_alias = aws_inventory.get_by_address("aws_kms_alias.orders")
        aws_queue = aws_inventory.get_by_address("aws_sqs_queue.orders")
        gcp_version = gcp_inventory.get_by_address("google_kms_crypto_key_version.primary")
        azure_key = azure_inventory.get_by_address("azurerm_key_vault_key.orders")
        assert aws_key is not None
        assert aws_alias is not None
        assert aws_queue is not None
        assert gcp_version is not None
        assert azure_key is not None

        alias_facts = aws_facts(aws_alias)
        self.assertEqual(alias_facts.kms_alias_name, _AWS_ALIAS_NAME)
        self.assertEqual(
            alias_facts.kms_alias_resolved_key_address,
            aws_key.address,
        )
        self.assertEqual(
            aws_facts(aws_queue).sqs_kms_master_key_id,
            _AWS_ALIAS_NAME,
        )
        self.assertEqual(
            aws_facts(aws_queue).sqs_encryption_ownership_state,
            "customer_managed",
        )
        self.assertEqual(
            aws_facts(aws_key).kms_aliases[0]["resolved_key_address"],
            aws_key.address,
        )

        version_facts = gcp_facts(gcp_version)
        self.assertEqual(
            version_facts.kms_crypto_key_version_reference,
            _GCP_VERSION_PATH,
        )
        self.assertEqual(
            version_facts.kms_crypto_key_version_crypto_key_path,
            _GCP_KEY_PATH,
        )
        self.assertEqual(
            version_facts.kms_crypto_key_version_resolved_key_address,
            "google_kms_crypto_key.orders",
        )
        self.assertEqual(
            version_facts.kms_crypto_key_version_key_ring,
            _GCP_KEY_RING,
        )

        azure_key_facts = azure_facts(azure_key)
        self.assertEqual(
            azure_key_facts.resolved_key_vault_address,
            "azurerm_key_vault.application",
        )
        self.assertEqual(
            azure_key_facts.key_vault_key_uri,
            _AZURE_KEY_URI,
        )
        self.assertEqual(
            azure_key_facts.key_vault_key_versionless_uri,
            _AZURE_KEY_VERSIONLESS_URI,
        )
        self.assertEqual(
            azure_key_facts.key_vault_key_resource_id,
            _AZURE_KEY_RESOURCE_ID,
        )
        self.assertEqual(
            azure_key_facts.key_vault_key_versionless_resource_id,
            _AZURE_KEY_VERSIONLESS_RESOURCE_ID,
        )
        self.assertEqual(
            azure_key_facts.key_vault_key_version,
            _AZURE_KEY_VERSION,
        )

    def test_symbolic_candidate_does_not_supply_missing_cloud_identity(
        self,
    ) -> None:
        aws_resolution = _reference_resolution(
            ("server_side_encryption", 0, "kms_key_arn"),
            ("aws_kms_key.unresolved",),
            ".arn",
        )
        gcp_resolution = _reference_resolution(
            ("kms_key_name",),
            ("google_kms_crypto_key.unresolved",),
            ".id",
        )
        azure_resolution = _reference_resolution(
            ("key_vault_key_id",),
            ("azurerm_key_vault_key.unresolved",),
            ".versionless_id",
        )

        aws_inventory = AwsNormalizer().normalize(
            [
                _aws_key("unresolved", exact_identity=False),
                _aws_table("unresolved", key_reference=aws_resolution),
            ]
        )
        gcp_inventory = GcpNormalizer().normalize(
            [
                _gcp_key("unresolved", exact_identity=False),
                _gcp_topic("unresolved", key_reference=gcp_resolution),
            ]
        )
        azure_inventory = AzureNormalizer().normalize(
            [
                _azure_key("unresolved", exact_identity=False),
                _azure_cosmos_account(
                    "unresolved",
                    key_reference=azure_resolution,
                ),
            ]
        )

        aws_key = aws_inventory.get_by_address("aws_kms_key.unresolved")
        aws_table = aws_inventory.get_by_address("aws_dynamodb_table.unresolved")
        gcp_key = gcp_inventory.get_by_address("google_kms_crypto_key.unresolved")
        gcp_topic = gcp_inventory.get_by_address("google_pubsub_topic.unresolved")
        azure_key = azure_inventory.get_by_address("azurerm_key_vault_key.unresolved")
        azure_account = azure_inventory.get_by_address("azurerm_cosmosdb_account.unresolved")
        assert aws_key is not None
        assert aws_table is not None
        assert gcp_key is not None
        assert gcp_topic is not None
        assert azure_key is not None
        assert azure_account is not None

        cases = (
            (
                aws_table.reference_resolution(
                    "server_side_encryption",
                    0,
                    "kms_key_arn",
                ),
                aws_key.address,
            ),
            (
                gcp_topic.reference_resolution("kms_key_name"),
                gcp_key.address,
            ),
            (
                azure_account.reference_resolution("key_vault_key_id"),
                azure_key.address,
            ),
        )
        for resolution, target_address in cases:
            with self.subTest(target=target_address):
                self.assertEqual(
                    resolution.state,
                    TerraformReferenceResolutionState.SYMBOLIC,
                )
                self.assertEqual(
                    [target.address for target in resolution.targets],
                    [target_address],
                )

        self.assertIsNone(aws_key.arn)
        self.assertIsNone(aws_facts(aws_key).kms_key_id)
        symbolic_key_reference = aws_facts(aws_table).dynamodb_kms_key_arn
        self.assertEqual(
            symbolic_key_reference,
            aws_key.address,
        )
        assert symbolic_key_reference is not None
        self.assertFalse(symbolic_key_reference.startswith("arn:"))
        self.assertEqual(
            aws_facts(aws_table).dynamodb_encryption_ownership_state,
            "unknown",
        )

        self.assertIsNone(gcp_facts(gcp_key).kms_key_ring)
        self.assertNotIn(
            "/cryptoKeys/",
            gcp_facts(gcp_key).kms_crypto_key_reference or "",
        )
        self.assertIsNone(gcp_facts(gcp_topic).pubsub_topic_kms_key_name)
        self.assertEqual(gcp_facts(gcp_topic).pubsub_topic_cmek_state, "unknown")

        self.assertEqual(
            azure_facts(azure_key).key_vault_key_identity_state,
            "unknown",
        )
        self.assertIsNone(azure_facts(azure_key).key_vault_key_versionless_uri)
        self.assertIsNone(azure_facts(azure_account).cosmosdb_key_vault_key_id)
        self.assertEqual(
            azure_facts(azure_account).cosmosdb_customer_managed_key_state,
            "unknown",
        )


if __name__ == "__main__":
    unittest.main()

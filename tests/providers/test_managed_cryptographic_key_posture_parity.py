from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts

_AWS_ACCOUNT_ID = "111122223333"
_AWS_KEY_ID = "12345678-1234-1234-1234-123456789012"
_AWS_KEY_ARN = f"arn:aws:kms:us-east-1:{_AWS_ACCOUNT_ID}:key/{_AWS_KEY_ID}"
_AWS_RUNTIME_ROLE_ARN = f"arn:aws:iam::{_AWS_ACCOUNT_ID}:role/orders-runtime"

_GCP_PROJECT = "tfstride-demo"
_GCP_KEY_RING = f"projects/{_GCP_PROJECT}/locations/global/keyRings/application"
_GCP_KEY_PATH = f"{_GCP_KEY_RING}/cryptoKeys/customer"
_GCP_VERSION_PATH = f"{_GCP_KEY_PATH}/cryptoKeyVersions/1"
_GCP_RUNTIME_MEMBER = "serviceAccount:orders@tfstride-demo.iam.gserviceaccount.com"

_AZURE_SUBSCRIPTION_SCOPE = "/subscriptions/sub-0001"
_AZURE_VAULT_ID = f"{_AZURE_SUBSCRIPTION_SCOPE}/resourceGroups/security/providers/Microsoft.KeyVault/vaults/application"
_AZURE_VAULT_URI = "https://application.vault.azure.net"
_AZURE_KEY_VERSION = "key-version-0001"
_AZURE_KEY_VERSIONLESS_URI = f"{_AZURE_VAULT_URI}/keys/customer"
_AZURE_KEY_URI = f"{_AZURE_KEY_VERSIONLESS_URI}/{_AZURE_KEY_VERSION}"
_AZURE_KEY_VERSIONLESS_RESOURCE_ID = f"{_AZURE_VAULT_ID}/keys/customer"
_AZURE_KEY_RESOURCE_ID = f"{_AZURE_KEY_VERSIONLESS_RESOURCE_ID}/{_AZURE_KEY_VERSION}"
_AZURE_RUNTIME_PRINCIPAL_ID = "runtime-principal-id"
_AZURE_CRYPTO_USER_ROLE_ID = "/providers/Microsoft.Authorization/roleDefinitions/12338af0-0e69-4776-bea7-57ae8d297424"


def _resource(
    provider: str,
    resource_type: str,
    name: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name=f"registry.terraform.io/hashicorp/{provider}",
        values=values,
        unknown_values=unknown_values or {},
    )


def _aws_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RuntimeCryptographicUse",
                    "Effect": "Allow",
                    "Principal": {"AWS": _AWS_RUNTIME_ROLE_ARN},
                    "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "kms:EncryptionContext:service": "orders",
                        }
                    },
                },
                {
                    "Sid": "DenyDestructiveAdministration",
                    "Effect": "Deny",
                    "Principal": {"AWS": "*"},
                    "Action": ["kms:DisableKey", "kms:ScheduleKeyDeletion"],
                    "Resource": "*",
                },
            ],
        }
    )


def _aws_key(
    *,
    unknown_values: dict[str, Any] | None = None,
    **overrides: Any,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": _AWS_KEY_ID,
        "key_id": _AWS_KEY_ID,
        "arn": _AWS_KEY_ARN,
        "key_usage": "ENCRYPT_DECRYPT",
        "key_spec": "SYMMETRIC_DEFAULT",
        "origin": "AWS_KMS",
        "multi_region": True,
        "enable_key_rotation": True,
        "rotation_period_in_days": 365,
        "deletion_window_in_days": 30,
        "policy": _aws_policy(),
    }
    values.update(overrides)
    return _resource(
        "aws",
        "aws_kms_key",
        "customer",
        values,
        unknown_values=unknown_values,
    )


def _gcp_key(
    *,
    unknown_values: dict[str, Any] | None = None,
    **overrides: Any,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": _GCP_KEY_PATH,
        "name": "customer",
        "key_ring": _GCP_KEY_RING,
        "purpose": "ENCRYPT_DECRYPT",
        "rotation_period": "7776000s",
        "destroy_scheduled_duration": "604800s",
    }
    values.update(overrides)
    return _resource(
        "google",
        "google_kms_crypto_key",
        "customer",
        values,
        unknown_values=unknown_values,
    )


def _gcp_version(
    *,
    unknown_values: dict[str, Any] | None = None,
    **overrides: Any,
) -> TerraformResource:
    values: dict[str, Any] = {
        "crypto_key": "google_kms_crypto_key.customer.id",
        "id": _GCP_VERSION_PATH,
        "name": _GCP_VERSION_PATH,
        "state": "ENABLED",
        "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
        "protection_level": "SOFTWARE",
        "generate_time": "2026-07-19T00:00:00Z",
        "deletion_policy": "DELETE",
    }
    values.update(overrides)
    return _resource(
        "google",
        "google_kms_crypto_key_version",
        "primary",
        values,
        unknown_values=unknown_values,
    )


def _azure_vault(
    *,
    rbac_enabled: object = True,
    unknown_values: dict[str, Any] | None = None,
    **overrides: Any,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": _AZURE_VAULT_ID,
        "name": "application",
        "vault_uri": _AZURE_VAULT_URI,
        "tenant_id": "tenant-id",
        "enable_rbac_authorization": rbac_enabled,
        "purge_protection_enabled": True,
    }
    values.update(overrides)
    return _resource(
        "azurerm",
        AzureResourceType.KEY_VAULT,
        "application",
        values,
        unknown_values=unknown_values,
    )


def _azure_key(
    *,
    unknown_values: dict[str, Any] | None = None,
    **overrides: Any,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": _AZURE_KEY_URI,
        "versionless_id": _AZURE_KEY_VERSIONLESS_URI,
        "resource_id": _AZURE_KEY_RESOURCE_ID,
        "resource_versionless_id": _AZURE_KEY_VERSIONLESS_RESOURCE_ID,
        "name": "customer",
        "version": _AZURE_KEY_VERSION,
        "key_vault_id": "azurerm_key_vault.application.id",
        "key_type": "RSA-HSM",
        "key_size": 2048,
        "key_opts": [
            "decrypt",
            "encrypt",
            "sign",
            "unwrapKey",
            "verify",
            "wrapKey",
        ],
        "expiration_date": "2027-07-20T00:00:00Z",
        "rotation_policy": [
            {
                "expire_after": "P90D",
                "notify_before_expiry": "P30D",
                "automatic": [
                    {
                        "time_after_creation": "P30D",
                        "time_before_expiry": "P15D",
                    }
                ],
            }
        ],
    }
    values.update(overrides)
    return _resource(
        "azurerm",
        AzureResourceType.KEY_VAULT_KEY,
        "customer",
        values,
        unknown_values=unknown_values,
    )


class ManagedCryptographicKeyPostureParityTests(unittest.TestCase):
    """Pin shared key concepts without imposing a cross-provider fact schema."""

    def test_exact_identity_and_cryptographic_capabilities_remain_native(self) -> None:
        aws_inventory = AwsNormalizer().normalize([_aws_key()])
        gcp_inventory = GcpNormalizer().normalize([_gcp_key(), _gcp_version()])
        azure_inventory = AzureNormalizer().normalize([_azure_vault(), _azure_key()])

        aws_key = aws_inventory.get_by_address("aws_kms_key.customer")
        gcp_key = gcp_inventory.get_by_address("google_kms_crypto_key.customer")
        gcp_version = gcp_inventory.get_by_address("google_kms_crypto_key_version.primary")
        azure_key = azure_inventory.get_by_address("azurerm_key_vault_key.customer")
        assert aws_key is not None
        assert gcp_key is not None
        assert gcp_version is not None
        assert azure_key is not None

        aws = aws_facts(aws_key)
        self.assertEqual(aws_key.identifier, _AWS_KEY_ID)
        self.assertEqual(aws_key.arn, _AWS_KEY_ARN)
        self.assertEqual(aws.kms_key_usage, "ENCRYPT_DECRYPT")
        self.assertEqual(aws.kms_key_spec, "SYMMETRIC_DEFAULT")

        gcp_key_facts = gcp_facts(gcp_key)
        gcp_version_facts = gcp_facts(gcp_version)
        self.assertEqual(gcp_key.identifier, _GCP_KEY_PATH)
        self.assertEqual(gcp_key_facts.kms_key_ring, _GCP_KEY_RING)
        self.assertEqual(gcp_key_facts.kms_purpose, "ENCRYPT_DECRYPT")
        self.assertEqual(gcp_version.identifier, _GCP_VERSION_PATH)
        self.assertEqual(
            gcp_version_facts.kms_crypto_key_version_crypto_key_path,
            _GCP_KEY_PATH,
        )
        self.assertEqual(
            gcp_version_facts.kms_crypto_key_version_resolved_key_address,
            gcp_key.address,
        )
        self.assertEqual(
            gcp_version_facts.kms_crypto_key_version_algorithm,
            "GOOGLE_SYMMETRIC_ENCRYPTION",
        )
        self.assertEqual(
            gcp_version_facts.kms_crypto_key_version_protection_level,
            "SOFTWARE",
        )

        azure = azure_facts(azure_key)
        self.assertEqual(azure.key_vault_key_identity_state, "resolved")
        self.assertEqual(azure.key_vault_key_uri, _AZURE_KEY_URI)
        self.assertEqual(
            azure.key_vault_key_versionless_uri,
            _AZURE_KEY_VERSIONLESS_URI,
        )
        self.assertEqual(azure.key_vault_key_resource_id, _AZURE_KEY_RESOURCE_ID)
        self.assertEqual(
            azure.key_vault_key_versionless_resource_id,
            _AZURE_KEY_VERSIONLESS_RESOURCE_ID,
        )
        self.assertEqual(azure.key_vault_key_version, _AZURE_KEY_VERSION)
        self.assertEqual(azure.key_vault_key_type, "RSA-HSM")
        self.assertEqual(
            set(azure.key_vault_key_ops),
            {"decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"},
        )

    def test_lifecycle_and_destruction_recovery_semantics_remain_native(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize([_aws_key()])
        gcp_inventory = GcpNormalizer().normalize([_gcp_key(), _gcp_version()])
        azure_inventory = AzureNormalizer().normalize([_azure_vault(), _azure_key()])

        aws_key = aws_inventory.get_by_address("aws_kms_key.customer")
        gcp_key = gcp_inventory.get_by_address("google_kms_crypto_key.customer")
        gcp_version = gcp_inventory.get_by_address("google_kms_crypto_key_version.primary")
        azure_vault = azure_inventory.get_by_address("azurerm_key_vault.application")
        azure_key = azure_inventory.get_by_address("azurerm_key_vault_key.customer")
        assert aws_key is not None
        assert gcp_key is not None
        assert gcp_version is not None
        assert azure_vault is not None
        assert azure_key is not None

        aws = aws_facts(aws_key)
        self.assertEqual(aws.kms_key_origin, "AWS_KMS")
        self.assertEqual(aws.kms_multi_region_state, "enabled")
        self.assertEqual(aws.kms_enable_key_rotation_state, "enabled")
        self.assertEqual(aws.kms_rotation_period_in_days, 365)
        self.assertEqual(aws.kms_deletion_window_in_days, 30)

        gcp_key_facts = gcp_facts(gcp_key)
        gcp_version_facts = gcp_facts(gcp_version)
        self.assertEqual(gcp_key_facts.kms_rotation_period, "7776000s")
        self.assertEqual(
            gcp_key_facts.kms_destroy_scheduled_duration,
            "604800s",
        )
        self.assertEqual(
            gcp_version_facts.kms_crypto_key_version_state,
            "ENABLED",
        )
        self.assertEqual(
            gcp_version_facts.kms_crypto_key_version_import_posture,
            "generated",
        )
        self.assertEqual(
            gcp_version_facts.kms_crypto_key_version_deletion_policy_state,
            "delete",
        )
        self.assertEqual(
            gcp_version_facts.kms_crypto_key_version_destroy_scheduled_duration,
            "604800s",
        )

        azure_vault_facts = azure_facts(azure_vault)
        azure_key_facts = azure_facts(azure_key)
        self.assertTrue(azure_vault_facts.purge_protection_enabled)
        self.assertEqual(
            azure_key_facts.key_vault_key_expiration_state,
            "configured",
        )
        self.assertEqual(
            azure_key_facts.key_vault_rotation_policy_expire_after,
            "P90D",
        )
        self.assertEqual(
            azure_key_facts.key_vault_rotation_policy_automatic_time_after_creation,
            "P30D",
        )

    def test_authorization_sources_scopes_and_conditions_remain_native(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize(
            [
                _aws_key(),
                _resource(
                    "aws",
                    "aws_kms_grant",
                    "runtime",
                    {
                        "key_id": _AWS_KEY_ARN,
                        "grantee_principal": _AWS_RUNTIME_ROLE_ARN,
                        "operations": ["Decrypt"],
                        "constraints": [
                            {
                                "encryption_context_equals": {
                                    "service": "orders",
                                }
                            }
                        ],
                        "retire_on_delete": True,
                    },
                ),
            ]
        )
        gcp_condition = {
            "title": "business-hours",
            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
        }
        gcp_inventory = GcpNormalizer().normalize(
            [
                _gcp_key(),
                _resource(
                    "google",
                    "google_project_iam_member",
                    "runtime_decrypter",
                    {
                        "project": _GCP_PROJECT,
                        "role": "roles/cloudkms.cryptoKeyDecrypter",
                        "member": _GCP_RUNTIME_MEMBER,
                    },
                ),
                _resource(
                    "google",
                    "google_kms_key_ring_iam_binding",
                    "operators",
                    {
                        "key_ring_id": _GCP_KEY_RING,
                        "role": "roles/cloudkms.admin",
                        "members": ["group:key-operators@example.com"],
                        "condition": [gcp_condition],
                    },
                ),
                _resource(
                    "google",
                    "google_kms_crypto_key_iam_member",
                    "runtime_encrypter",
                    {
                        "crypto_key_id": "google_kms_crypto_key.customer.id",
                        "role": "roles/cloudkms.cryptoKeyEncrypter",
                        "member": _GCP_RUNTIME_MEMBER,
                    },
                ),
            ]
        )
        azure_rbac_inventory = AzureNormalizer().normalize(
            [
                _azure_vault(),
                _azure_key(),
                _azure_role_assignment(
                    "runtime",
                    scope="azurerm_key_vault_key.customer.resource_versionless_id",
                ),
                _azure_role_assignment(
                    "conditioned",
                    scope="azurerm_key_vault_key.customer.resource_versionless_id",
                    condition=("@Resource[Microsoft.KeyVault/vaults/keys:Name] StringEqualsIgnoreCase 'customer'"),
                ),
            ]
        )
        azure_legacy_inventory = AzureNormalizer().normalize(
            [
                _azure_vault(rbac_enabled=False),
                _azure_key(),
                _resource(
                    "azurerm",
                    AzureResourceType.KEY_VAULT_ACCESS_POLICY,
                    "runtime",
                    {
                        "key_vault_id": "azurerm_key_vault.application.id",
                        "tenant_id": "tenant-id",
                        "object_id": _AZURE_RUNTIME_PRINCIPAL_ID,
                        "key_permissions": ["Decrypt", "Get"],
                    },
                ),
            ]
        )

        aws_key = aws_inventory.get_by_address("aws_kms_key.customer")
        gcp_key = gcp_inventory.get_by_address("google_kms_crypto_key.customer")
        azure_rbac_key = azure_rbac_inventory.get_by_address("azurerm_key_vault_key.customer")
        azure_legacy_key = azure_legacy_inventory.get_by_address("azurerm_key_vault_key.customer")
        assert aws_key is not None
        assert gcp_key is not None
        assert azure_rbac_key is not None
        assert azure_legacy_key is not None

        aws = aws_facts(aws_key)
        self.assertEqual(aws.kms_policy_configuration_state, "configured")
        self.assertEqual(aws.kms_policy_completeness_state, "complete")
        self.assertEqual(aws.kms_key_policies[0]["source"], aws_key.address)
        self.assertEqual(aws.kms_key_policies[0]["source_type"], "inline")
        self.assertEqual(len(aws_key.policy_statements[0].conditions), 1)
        self.assertEqual(aws_key.policy_statements[1].effect, "Deny")
        self.assertEqual(aws.kms_grants[0]["source"], "aws_kms_grant.runtime")
        self.assertEqual(
            aws.kms_grants[0]["resolved_key_address"],
            aws_key.address,
        )
        self.assertEqual(
            aws.kms_grants[0]["constraints"],
            {"encryption_context_equals": {"service": "orders"}},
        )

        gcp_grants = {grant["scope_type"]: grant for grant in gcp_facts(gcp_key).kms_iam_grants}
        self.assertEqual(set(gcp_grants), {"project", "key_ring", "crypto_key"})
        self.assertEqual(
            gcp_grants["project"]["source"],
            "google_project_iam_member.runtime_decrypter",
        )
        self.assertEqual(
            gcp_grants["key_ring"]["authorization_state"],
            "conditional",
        )
        self.assertEqual(gcp_grants["key_ring"]["condition"], gcp_condition)
        self.assertEqual(gcp_grants["crypto_key"]["scope"], _GCP_KEY_PATH)
        self.assertEqual(
            gcp_grants["crypto_key"]["authorization_state"],
            "granted",
        )

        azure_rbac_grants = {
            grant["grant_source_address"]: grant
            for grant in azure_facts(azure_rbac_key).key_vault_key_authorization_grants
        }
        deterministic_rbac = azure_rbac_grants["azurerm_role_assignment.runtime"]
        self.assertEqual(deterministic_rbac["grant_kind"], "rbac")
        self.assertEqual(deterministic_rbac["grant_scope_type"], "key")
        self.assertEqual(
            deterministic_rbac["key_resource_id"],
            _AZURE_KEY_VERSIONLESS_RESOURCE_ID,
        )
        self.assertEqual(deterministic_rbac["authorization_state"], "granted")
        conditioned_rbac = azure_rbac_grants["azurerm_role_assignment.conditioned"]
        self.assertEqual(
            conditioned_rbac["condition_applicability_state"],
            "unsupported",
        )
        self.assertEqual(conditioned_rbac["authorization_state"], "unknown")

        azure_legacy_grant = azure_facts(azure_legacy_key).key_vault_key_authorization_grants[0]
        self.assertEqual(azure_legacy_grant["grant_kind"], "access_policy")
        self.assertEqual(azure_legacy_grant["grant_scope_type"], "vault")
        self.assertEqual(azure_legacy_grant["authorization_state"], "granted")
        self.assertEqual(
            set(azure_legacy_grant["matched_operations"]),
            {"decrypt", "read"},
        )

    def test_unknown_values_never_become_explicit_posture_or_authority(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize(
            [
                _aws_key(
                    unknown_values={
                        "key_id": True,
                        "id": True,
                        "arn": True,
                        "key_usage": True,
                        "key_spec": True,
                        "origin": True,
                        "multi_region": True,
                        "enable_key_rotation": True,
                        "rotation_period_in_days": True,
                        "deletion_window_in_days": True,
                        "policy": True,
                    }
                )
            ]
        )
        gcp_inventory = GcpNormalizer().normalize(
            [
                _gcp_key(
                    unknown_values={
                        "purpose": True,
                        "rotation_period": True,
                        "destroy_scheduled_duration": True,
                    }
                ),
                _gcp_version(
                    unknown_values={
                        "id": True,
                        "name": True,
                        "state": True,
                        "algorithm": True,
                        "protection_level": True,
                        "generate_time": True,
                        "deletion_policy": True,
                    }
                ),
                _resource(
                    "google",
                    "google_kms_crypto_key_iam_member",
                    "unknown_role",
                    {
                        "crypto_key_id": "google_kms_crypto_key.customer.id",
                        "member": _GCP_RUNTIME_MEMBER,
                    },
                    unknown_values={"role": True},
                ),
            ]
        )
        azure_identity_inventory = AzureNormalizer().normalize(
            [
                _resource(
                    "azurerm",
                    AzureResourceType.KEY_VAULT_KEY,
                    "pending",
                    {
                        "name": "pending",
                        "key_vault_id": None,
                        "id": _AZURE_KEY_URI,
                        "versionless_id": _AZURE_KEY_VERSIONLESS_URI,
                        "resource_id": _AZURE_KEY_RESOURCE_ID,
                        "resource_versionless_id": (_AZURE_KEY_VERSIONLESS_RESOURCE_ID),
                        "key_type": "RSA-HSM",
                        "key_opts": ["decrypt"],
                        "expiration_date": "2027-07-20T00:00:00Z",
                    },
                    unknown_values={
                        "key_vault_id": True,
                        "id": True,
                        "versionless_id": True,
                        "resource_id": True,
                        "resource_versionless_id": True,
                        "key_type": True,
                        "key_opts": True,
                        "expiration_date": True,
                    },
                )
            ]
        )
        azure_authorization_inventory = AzureNormalizer().normalize(
            [
                _azure_vault(
                    rbac_enabled=None,
                    unknown_values={
                        "enable_rbac_authorization": True,
                        "access_policy": True,
                    },
                ),
                _azure_key(),
                _azure_role_assignment(
                    "unknown_role",
                    scope="azurerm_key_vault_key.customer.resource_versionless_id",
                    role_definition_id=None,
                    unknown_values={"role_definition_id": True},
                ),
            ]
        )

        aws_key = aws_inventory.get_by_address("aws_kms_key.customer")
        gcp_key = gcp_inventory.get_by_address("google_kms_crypto_key.customer")
        gcp_version = gcp_inventory.get_by_address("google_kms_crypto_key_version.primary")
        azure_pending = azure_identity_inventory.get_by_address("azurerm_key_vault_key.pending")
        azure_key = azure_authorization_inventory.get_by_address("azurerm_key_vault_key.customer")
        assert aws_key is not None
        assert gcp_key is not None
        assert gcp_version is not None
        assert azure_pending is not None
        assert azure_key is not None

        aws = aws_facts(aws_key)
        self.assertIsNone(aws_key.identifier)
        self.assertIsNone(aws_key.arn)
        self.assertIsNone(aws.kms_key_usage)
        self.assertIsNone(aws.kms_key_spec)
        self.assertIsNone(aws.kms_key_origin)
        self.assertEqual(aws.kms_multi_region_state, "unknown")
        self.assertEqual(aws.kms_enable_key_rotation_state, "unknown")
        self.assertIsNone(aws.kms_rotation_period_in_days)
        self.assertIsNone(aws.kms_deletion_window_in_days)
        self.assertEqual(aws.kms_policy_completeness_state, "unknown")
        self.assertEqual(aws_key.policy_statements, ())
        self.assertTrue(aws.kms_posture_uncertainties)

        gcp_key_facts = gcp_facts(gcp_key)
        gcp_version_facts = gcp_facts(gcp_version)
        self.assertIsNone(gcp_key_facts.kms_purpose)
        self.assertIsNone(gcp_key_facts.kms_rotation_period)
        self.assertIsNone(gcp_key_facts.kms_destroy_scheduled_duration)
        self.assertIsNone(gcp_version_facts.kms_crypto_key_version_reference)
        self.assertIsNone(gcp_version_facts.kms_crypto_key_version_state)
        self.assertIsNone(gcp_version_facts.kms_crypto_key_version_algorithm)
        self.assertIsNone(gcp_version_facts.kms_crypto_key_version_protection_level)
        self.assertEqual(
            gcp_version_facts.kms_crypto_key_version_import_posture,
            "unknown",
        )
        self.assertEqual(
            gcp_version_facts.kms_crypto_key_version_deletion_policy_state,
            "unknown",
        )
        self.assertEqual(gcp_key_facts.kms_iam_grants, [])
        self.assertTrue(gcp_key_facts.kms_iam_posture_uncertainties)

        azure_pending_facts = azure_facts(azure_pending)
        self.assertEqual(
            azure_pending_facts.key_vault_key_identity_state,
            "unknown",
        )
        self.assertIsNone(azure_pending_facts.key_vault_key_uri)
        self.assertIsNone(azure_pending_facts.key_vault_key_versionless_uri)
        self.assertIsNone(azure_pending_facts.key_vault_key_resource_id)
        self.assertIsNone(azure_pending_facts.key_vault_key_versionless_resource_id)
        self.assertIsNone(azure_pending_facts.key_vault_key_type)
        self.assertEqual(azure_pending_facts.key_vault_key_ops, [])
        self.assertEqual(
            azure_pending_facts.key_vault_key_expiration_state,
            "unknown",
        )
        self.assertTrue(azure_pending_facts.key_vault_identity_uncertainties)
        self.assertTrue(azure_pending_facts.key_vault_key_posture_uncertainties)

        azure_authorization_facts = azure_facts(azure_key)
        self.assertEqual(
            azure_authorization_facts.key_vault_key_authorization_grants[0]["authorization_state"],
            "unknown",
        )
        self.assertEqual(
            azure_authorization_facts.key_vault_key_authorization_grants[0]["matched_operations"],
            [],
        )
        self.assertTrue(azure_authorization_facts.key_vault_key_authorization_uncertainties)


def _azure_role_assignment(
    name: str,
    *,
    scope: object,
    role_definition_id: object | None = _AZURE_CRYPTO_USER_ROLE_ID,
    condition: object | None = None,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "scope": scope,
        "principal_id": _AZURE_RUNTIME_PRINCIPAL_ID,
        "principal_type": "ServicePrincipal",
        "role_definition_name": "Key Vault Crypto User",
    }
    if role_definition_id is not None:
        values["role_definition_id"] = role_definition_id
    if condition is not None:
        values["condition"] = condition
        values["condition_version"] = "2.0"
    return _resource(
        "azurerm",
        AzureResourceType.ROLE_ASSIGNMENT,
        name,
        values,
        unknown_values=unknown_values,
    )


if __name__ == "__main__":
    unittest.main()

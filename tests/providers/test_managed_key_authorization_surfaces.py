from __future__ import annotations

import json
import unittest
from typing import Any, cast

from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts

_AWS_ACCOUNT_ID = "111122223333"
_AWS_KEY_ID = "12345678-1234-1234-1234-123456789012"
_AWS_KEY_ARN = f"arn:aws:kms:us-east-1:{_AWS_ACCOUNT_ID}:key/{_AWS_KEY_ID}"
_AWS_RUNTIME_ROLE_ARN = f"arn:aws:iam::{_AWS_ACCOUNT_ID}:role/orders-runtime"

_GCP_KEY_RING = "projects/tfstride-demo/locations/global/keyRings/application"
_GCP_KEY_ID = f"{_GCP_KEY_RING}/cryptoKeys/customer"
_GCP_RUNTIME_MEMBER = "serviceAccount:orders@tfstride-demo.iam.gserviceaccount.com"

_AZURE_VAULT_ID = "/subscriptions/sub-0001/resourceGroups/security/providers/Microsoft.KeyVault/vaults/application"
_AZURE_VAULT_URI = "https://application.vault.azure.net"
_AZURE_KEY_RESOURCE_ID = f"{_AZURE_VAULT_ID}/keys/customer"
_AZURE_KEY_VERSION = "key-version-0001"
_AZURE_KEY_URI = f"{_AZURE_VAULT_URI}/keys/customer/{_AZURE_KEY_VERSION}"
_AZURE_ROLE_DEFINITION_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/11111111-2222-3333-4444-555555555555"
)


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


def _aws_key_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowRuntimeCryptographicUse",
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


def _aws_key() -> TerraformResource:
    return _resource(
        "aws",
        "aws_kms_key",
        "customer",
        {
            "id": _AWS_KEY_ID,
            "key_id": _AWS_KEY_ID,
            "arn": _AWS_KEY_ARN,
            "key_usage": "ENCRYPT_DECRYPT",
            "policy": _aws_key_policy(),
        },
    )


def _gcp_key() -> TerraformResource:
    return _resource(
        "google",
        "google_kms_crypto_key",
        "customer",
        {
            "id": _GCP_KEY_ID,
            "name": "customer",
            "key_ring": _GCP_KEY_RING,
            "purpose": "ENCRYPT_DECRYPT",
        },
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
            "enable_rbac_authorization": True,
            "access_policy": [
                {
                    "tenant_id": "tenant-id",
                    "object_id": "break-glass-object-id",
                    "key_permissions": ["Get", "Decrypt"],
                }
            ],
        },
    )


def _azure_key() -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.KEY_VAULT_KEY,
        "customer",
        {
            "id": _AZURE_KEY_URI,
            "versionless_id": f"{_AZURE_VAULT_URI}/keys/customer",
            "resource_id": _AZURE_KEY_RESOURCE_ID,
            "version": _AZURE_KEY_VERSION,
            "name": "customer",
            "key_vault_id": "azurerm_key_vault.application.id",
            "key_type": "RSA",
            "key_opts": ["decrypt", "encrypt", "unwrapKey", "wrapKey"],
        },
    )


class ManagedKeyAuthorizationSurfaceCharacterizationTests(unittest.TestCase):
    """Pin provider-native key authorization inputs before access-path analysis."""

    def test_aws_key_policy_preserves_exact_identity_conditions_and_denies(self) -> None:
        inventory = AwsNormalizer().normalize([_aws_key()])
        key = inventory.get_by_address("aws_kms_key.customer")
        assert key is not None

        self.assertEqual(key.identifier, _AWS_KEY_ID)
        self.assertEqual(key.arn, _AWS_KEY_ARN)
        self.assertEqual(len(key.policy_statements), 2)

        allow, deny = key.policy_statements
        self.assertEqual(allow.effect, "Allow")
        self.assertEqual(allow.actions, ["kms:Decrypt", "kms:GenerateDataKey"])
        self.assertEqual(allow.resources, ["*"])
        self.assertEqual(allow.principals, [_AWS_RUNTIME_ROLE_ARN])
        self.assertEqual(
            [(entry.kind, entry.value) for entry in allow.principal_entries],
            [("AWS", _AWS_RUNTIME_ROLE_ARN)],
        )
        self.assertEqual(
            [(condition.operator, condition.key, condition.values) for condition in allow.conditions],
            [
                (
                    "StringEquals",
                    "kms:EncryptionContext:service",
                    ["orders"],
                )
            ],
        )

        self.assertEqual(deny.effect, "Deny")
        self.assertEqual(
            deny.actions,
            ["kms:DisableKey", "kms:ScheduleKeyDeletion"],
        )
        self.assertEqual(deny.resources, ["*"])
        self.assertEqual(deny.principals, ["*"])
        self.assertEqual(deny.conditions, [])

    def test_aws_alias_and_grant_inputs_resolve_to_exact_key_facts(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _aws_key(),
                _resource(
                    "aws",
                    "aws_kms_alias",
                    "customer",
                    {
                        "id": "alias/customer",
                        "name": "alias/customer",
                        "arn": f"arn:aws:kms:us-east-1:{_AWS_ACCOUNT_ID}:alias/customer",
                        "target_key_id": "aws_kms_key.customer.key_id",
                        "target_key_arn": _AWS_KEY_ARN,
                    },
                ),
                _resource(
                    "aws",
                    "aws_kms_grant",
                    "runtime",
                    {
                        "id": "grant-0001",
                        "grant_id": "grant-0001",
                        "name": "runtime",
                        "key_id": "aws_kms_key.customer.key_id",
                        "grantee_principal": _AWS_RUNTIME_ROLE_ARN,
                        "retiring_principal": _AWS_RUNTIME_ROLE_ARN,
                        "operations": ["Decrypt", "GenerateDataKey"],
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

        key = inventory.get_by_address("aws_kms_key.customer")
        alias = inventory.get_by_address("aws_kms_alias.customer")
        grant = inventory.get_by_address("aws_kms_grant.runtime")
        assert key is not None
        assert alias is not None
        assert grant is not None
        self.assertEqual(inventory.unsupported_resources, [])

        alias_facts = aws_facts(alias)
        grant_facts = aws_facts(grant)
        key_facts = aws_facts(key)
        self.assertEqual(alias_facts.kms_alias_name, "alias/customer")
        self.assertEqual(alias_facts.kms_alias_target_key_reference, "aws_kms_key.customer.key_id")
        self.assertEqual(alias_facts.kms_alias_resolved_key_address, key.address)
        self.assertEqual(grant_facts.kms_grant_id, "grant-0001")
        self.assertEqual(grant_facts.kms_grant_operations, ["Decrypt", "GenerateDataKey"])
        self.assertEqual(grant_facts.kms_grant_constraints, {"encryption_context_equals": {"service": "orders"}})
        self.assertEqual(grant_facts.kms_grant_resolved_key_address, key.address)
        self.assertEqual(len(key_facts.kms_aliases), 1)
        self.assertEqual(len(key_facts.kms_grants), 1)
        self.assertEqual(key_facts.kms_aliases[0]["resolved_key_address"], key.address)
        self.assertEqual(key_facts.kms_grants[0]["grantee_principal"], _AWS_RUNTIME_ROLE_ARN)

    def test_gcp_key_and_key_ring_iam_preserve_native_scopes_and_conditions(self) -> None:
        version_condition = {
            "title": "version-one-only",
            "expression": "resource.name.endsWith('/cryptoKeyVersions/1')",
        }
        inventory = GcpNormalizer().normalize(
            [
                _gcp_key(),
                _resource(
                    "google",
                    "google_kms_crypto_key_iam_member",
                    "runtime_decrypter",
                    {
                        "crypto_key_id": "google_kms_crypto_key.customer.id",
                        "role": "roles/cloudkms.cryptoKeyDecrypter",
                        "member": _GCP_RUNTIME_MEMBER,
                        "condition": version_condition,
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
                    unknown_values={"condition": True},
                ),
                _resource(
                    "google",
                    "google_kms_key_ring_iam_binding",
                    "operators",
                    {
                        "key_ring_id": _GCP_KEY_RING,
                        "role": "roles/cloudkms.admin",
                        "members": ["group:key-operators@example.com"],
                    },
                ),
                _resource(
                    "google",
                    "google_kms_crypto_key_iam_policy",
                    "auditors",
                    {
                        "crypto_key_id": _GCP_KEY_ID,
                        "policy_data": json.dumps(
                            {
                                "bindings": [
                                    {
                                        "role": "roles/cloudkms.viewer",
                                        "members": ["group:key-auditors@example.com"],
                                    }
                                ]
                            }
                        ),
                    },
                ),
            ]
        )
        key = inventory.get_by_address("google_kms_crypto_key.customer")
        assert key is not None

        facts = gcp_facts(key)
        self.assertEqual(key.identifier, _GCP_KEY_ID)
        self.assertEqual(
            key.get_metadata_field(GcpResourceMetadata.KMS_KEY_RING),
            _GCP_KEY_RING,
        )
        bindings_by_source = {binding["source"]: binding for binding in facts.bindings}
        self.assertEqual(
            bindings_by_source["google_kms_crypto_key_iam_member.runtime_decrypter"],
            {
                "role": "roles/cloudkms.cryptoKeyDecrypter",
                "members": [_GCP_RUNTIME_MEMBER],
                "source": "google_kms_crypto_key_iam_member.runtime_decrypter",
                "condition": version_condition,
            },
        )
        self.assertEqual(
            bindings_by_source["google_kms_crypto_key_iam_member.runtime_encrypter"],
            {
                "role": "roles/cloudkms.cryptoKeyEncrypter",
                "members": [_GCP_RUNTIME_MEMBER],
                "source": "google_kms_crypto_key_iam_member.runtime_encrypter",
                "condition_state": "unknown",
            },
        )
        self.assertEqual(
            bindings_by_source["google_kms_key_ring_iam_binding.operators"],
            {
                "role": "roles/cloudkms.admin",
                "members": ["group:key-operators@example.com"],
                "source": "google_kms_key_ring_iam_binding.operators",
            },
        )
        self.assertEqual(
            bindings_by_source["google_kms_crypto_key_iam_policy.auditors"],
            {
                "role": "roles/cloudkms.viewer",
                "members": ["group:key-auditors@example.com"],
                "source": "google_kms_crypto_key_iam_policy.auditors",
            },
        )
        self.assertEqual(
            set(facts.resource_policy_source_addresses),
            set(bindings_by_source),
        )

    def test_gcp_unresolved_key_reference_and_key_version_do_not_become_grants(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gcp_key(),
                _resource(
                    "google",
                    "google_kms_crypto_key_iam_member",
                    "external_decrypter",
                    {
                        "crypto_key_id": "google_kms_crypto_key.external.id",
                        "role": "roles/cloudkms.cryptoKeyDecrypter",
                        "member": _GCP_RUNTIME_MEMBER,
                    },
                ),
                _resource(
                    "google",
                    "google_kms_crypto_key_version",
                    "primary",
                    {
                        "crypto_key": "google_kms_crypto_key.customer.id",
                        "state": "ENABLED",
                    },
                ),
            ]
        )
        key = inventory.get_by_address("google_kms_crypto_key.customer")
        external_binding = inventory.get_by_address("google_kms_crypto_key_iam_member.external_decrypter")
        assert key is not None
        assert external_binding is not None

        self.assertEqual(gcp_facts(key).bindings, [])
        self.assertEqual(
            gcp_facts(external_binding).target_reference,
            "google_kms_crypto_key.external.id",
        )
        self.assertEqual(
            gcp_facts(external_binding).bindings,
            [
                {
                    "role": "roles/cloudkms.cryptoKeyDecrypter",
                    "members": [_GCP_RUNTIME_MEMBER],
                }
            ],
        )
        self.assertEqual(
            inventory.unsupported_resources,
            ["google_kms_crypto_key_version.primary"],
        )

    def test_azure_key_access_policy_and_rbac_preserve_native_scope_and_version(self) -> None:
        condition = "@Resource[Microsoft.KeyVault/vaults/keys:Name] StringEqualsIgnoreCase 'customer'"
        inventory = AzureNormalizer().normalize(
            [
                _azure_vault(),
                _azure_key(),
                _resource(
                    "azurerm",
                    AzureResourceType.KEY_VAULT_ACCESS_POLICY,
                    "runtime",
                    {
                        "key_vault_id": "azurerm_key_vault.application.id",
                        "tenant_id": "tenant-id",
                        "object_id": "runtime-principal-id",
                        "key_permissions": ["Decrypt", "Encrypt", "UnwrapKey", "WrapKey"],
                    },
                ),
                _resource(
                    "azurerm",
                    AzureResourceType.ROLE_DEFINITION,
                    "crypto_operator",
                    {
                        "name": "Application Key Crypto Operator",
                        "role_definition_id": _AZURE_ROLE_DEFINITION_ID,
                        "scope": "/subscriptions/sub-0001",
                        "assignable_scopes": [_AZURE_KEY_RESOURCE_ID],
                        "permissions": [
                            {
                                "actions": [],
                                "not_actions": [],
                                "data_actions": [
                                    "Microsoft.KeyVault/vaults/keys/decrypt/action",
                                    "Microsoft.KeyVault/vaults/keys/encrypt/action",
                                ],
                                "not_data_actions": [
                                    "Microsoft.KeyVault/vaults/keys/delete",
                                    "Microsoft.KeyVault/vaults/keys/purge/action",
                                ],
                            }
                        ],
                    },
                ),
                _resource(
                    "azurerm",
                    AzureResourceType.ROLE_ASSIGNMENT,
                    "runtime_key_crypto",
                    {
                        "scope": "azurerm_key_vault_key.customer.resource_manager_id",
                        "role_definition_id": "azurerm_role_definition.crypto_operator.id",
                        "principal_id": "runtime-principal-id",
                        "principal_type": "ServicePrincipal",
                        "condition": condition,
                    },
                ),
            ]
        )
        vault = inventory.get_by_address("azurerm_key_vault.application")
        key = inventory.get_by_address("azurerm_key_vault_key.customer")
        role_definition = inventory.get_by_address("azurerm_role_definition.crypto_operator")
        assignment = inventory.get_by_address("azurerm_role_assignment.runtime_key_crypto")
        assert vault is not None
        assert key is not None
        assert role_definition is not None
        assert assignment is not None

        vault_facts = azure_facts(vault)
        key_facts = azure_facts(key)
        role_facts = azure_facts(role_definition)
        assignment_facts = azure_facts(assignment)
        vault_policies = cast(
            list[dict[str, Any]],
            vault_facts.key_vault_access_policies,
        )

        self.assertEqual(key.identifier, _AZURE_KEY_URI)
        self.assertEqual(key_facts.resolved_key_vault_address, vault.address)
        self.assertEqual(
            {policy["source"]: policy for policy in vault_policies},
            {
                "azurerm_key_vault.application": {
                    "source": "azurerm_key_vault.application",
                    "tenant_id": "tenant-id",
                    "object_id": "break-glass-object-id",
                    "application_id": None,
                    "key_permissions": ["decrypt", "get"],
                    "secret_permissions": [],
                    "certificate_permissions": [],
                    "storage_permissions": [],
                },
                "azurerm_key_vault_access_policy.runtime": {
                    "source": "azurerm_key_vault_access_policy.runtime",
                    "tenant_id": "tenant-id",
                    "object_id": "runtime-principal-id",
                    "application_id": None,
                    "key_permissions": [
                        "decrypt",
                        "encrypt",
                        "unwrapkey",
                        "wrapkey",
                    ],
                    "secret_permissions": [],
                    "certificate_permissions": [],
                    "storage_permissions": [],
                },
            },
        )
        self.assertEqual(
            role_facts.role_definition_data_actions,
            [
                "Microsoft.KeyVault/vaults/keys/decrypt/action",
                "Microsoft.KeyVault/vaults/keys/encrypt/action",
            ],
        )
        self.assertEqual(
            role_facts.role_definition_not_data_actions,
            [
                "Microsoft.KeyVault/vaults/keys/delete",
                "Microsoft.KeyVault/vaults/keys/purge/action",
            ],
        )
        self.assertEqual(
            assignment_facts.role_assignment_scope,
            "azurerm_key_vault_key.customer.resource_manager_id",
        )
        self.assertEqual(assignment_facts.role_assignment_scope_kind, "resource")
        self.assertEqual(
            assignment_facts.role_assignment_target_resource_address,
            key.address,
        )
        self.assertEqual(
            assignment_facts.role_assignment_target_resource_type,
            AzureResourceType.KEY_VAULT_KEY,
        )
        self.assertEqual(
            assignment_facts.resolved_role_definition_address,
            role_definition.address,
        )
        self.assertEqual(assignment_facts.role_assignment_condition, condition)

    def test_azure_unresolved_policy_scope_and_condition_remain_non_authoritative(self) -> None:
        external_key_scope = (
            "/subscriptions/sub-0001/resourceGroups/external/providers/Microsoft.KeyVault/vaults/external/keys/customer"
        )
        inventory = AzureNormalizer().normalize(
            [
                _azure_vault(),
                _azure_key(),
                _resource(
                    "azurerm",
                    AzureResourceType.KEY_VAULT_ACCESS_POLICY,
                    "external",
                    {
                        "key_vault_id": "azurerm_key_vault.external.id",
                        "tenant_id": "tenant-id",
                        "object_id": "external-principal-id",
                        "key_permissions": ["Decrypt"],
                    },
                ),
                _resource(
                    "azurerm",
                    AzureResourceType.ROLE_ASSIGNMENT,
                    "external_key_crypto",
                    {
                        "scope": external_key_scope,
                        "role_definition_name": "Key Vault Crypto User",
                        "principal_id": "external-principal-id",
                        "principal_type": "ServicePrincipal",
                    },
                ),
                _resource(
                    "azurerm",
                    AzureResourceType.ROLE_ASSIGNMENT,
                    "unknown_condition",
                    {
                        "scope": "azurerm_key_vault_key.customer.resource_manager_id",
                        "role_definition_name": "Key Vault Crypto User",
                        "principal_id": "runtime-principal-id",
                        "principal_type": "ServicePrincipal",
                    },
                    unknown_values={"condition": True},
                ),
            ]
        )
        vault = inventory.get_by_address("azurerm_key_vault.application")
        external_policy = inventory.get_by_address("azurerm_key_vault_access_policy.external")
        external_assignment = inventory.get_by_address("azurerm_role_assignment.external_key_crypto")
        unknown_assignment = inventory.get_by_address("azurerm_role_assignment.unknown_condition")
        assert vault is not None
        assert external_policy is not None
        assert external_assignment is not None
        assert unknown_assignment is not None

        vault_policies = cast(
            list[dict[str, Any]],
            azure_facts(vault).key_vault_access_policies,
        )
        self.assertEqual(
            [policy["source"] for policy in vault_policies],
            ["azurerm_key_vault.application"],
        )
        self.assertEqual(
            external_policy.get_metadata_field(AzureResourceMetadata.UNRESOLVED_RESOURCE_REFERENCES),
            ["key_vault:azurerm_key_vault.external.id"],
        )
        self.assertIsNone(azure_facts(external_assignment).role_assignment_target_resource_address)
        self.assertEqual(
            external_assignment.get_metadata_field(AzureResourceMetadata.UNRESOLVED_RESOURCE_REFERENCES),
            [f"key_vault_scope:{external_key_scope}"],
        )
        self.assertEqual(
            azure_facts(unknown_assignment).role_assignment_target_resource_address,
            "azurerm_key_vault_key.customer",
        )
        self.assertIsNone(azure_facts(unknown_assignment).role_assignment_condition)
        self.assertIn(
            "condition is unknown after planning",
            azure_facts(unknown_assignment).key_vault_authorization_uncertainties,
        )


if __name__ == "__main__":
    unittest.main()

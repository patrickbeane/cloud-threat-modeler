from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_SUBSCRIPTION_ID = "sub-0001"
_SUBSCRIPTION_SCOPE = f"/subscriptions/{_SUBSCRIPTION_ID}"
_RESOURCE_GROUP_SCOPE = f"{_SUBSCRIPTION_SCOPE}/resourceGroups/app"
_VAULT_ID = f"{_RESOURCE_GROUP_SCOPE}/providers/Microsoft.KeyVault/vaults/orders"
_VAULT_URI = "https://orders.vault.azure.net"
_KEY_VERSIONLESS_URI = f"{_VAULT_URI}/keys/signing"
_KEY_URI = f"{_KEY_VERSIONLESS_URI}/v-001"
_KEY_VERSIONLESS_RESOURCE_ID = f"{_VAULT_ID}/keys/signing"
_KEY_RESOURCE_ID = f"{_KEY_VERSIONLESS_RESOURCE_ID}/v-001"
_SYSTEM_PRINCIPAL_ID = "app-system-principal-id"
_USER_PRINCIPAL_ID = "app-user-principal-id"
_USER_IDENTITY_ID = f"{_RESOURCE_GROUP_SCOPE}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/orders-runtime"
_ROLE_ID_PREFIX = "/providers/Microsoft.Authorization/roleDefinitions"
_CRYPTO_USER_ID = "12338af0-0e69-4776-bea7-57ae8d297424"
_SERVICE_ENCRYPTION_USER_ID = "e147488a-f6f5-4113-8e2d-b22465e65bf6"
_CUSTOM_ROLE_ID = f"{_SUBSCRIPTION_SCOPE}/providers/Microsoft.Authorization/roleDefinitions/custom-key-operator"


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, object],
    *,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values=unknown_values or {},
    )


def _vault(*, rbac_enabled: object = False) -> TerraformResource:
    return _resource(
        AzureResourceType.KEY_VAULT,
        "orders",
        {
            "id": _VAULT_ID,
            "name": "orders",
            "vault_uri": _VAULT_URI,
            "enable_rbac_authorization": rbac_enabled,
        },
    )


def _key(
    *,
    key_opts: object = ("decrypt", "unwrapKey", "sign"),
    version: str | None = "v-001",
    unknown_key_opts: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "versionless_id": _KEY_VERSIONLESS_URI,
        "resource_versionless_id": _KEY_VERSIONLESS_RESOURCE_ID,
        "name": "signing",
        "key_vault_id": "azurerm_key_vault.orders.id",
        "key_type": "RSA-HSM",
        "key_opts": list(key_opts) if isinstance(key_opts, tuple) else key_opts,
    }
    if version is not None:
        values.update(
            {
                "id": f"{_KEY_VERSIONLESS_URI}/{version}",
                "resource_id": f"{_KEY_VERSIONLESS_RESOURCE_ID}/{version}",
                "version": version,
            }
        )
    return _resource(
        AzureResourceType.KEY_VAULT_KEY,
        "signing",
        values,
        unknown_values={"key_opts": True} if unknown_key_opts else None,
    )


def _web_app(
    *,
    key_vault_reference_identity_id: str | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": f"{_RESOURCE_GROUP_SCOPE}/providers/Microsoft.Web/sites/orders",
        "name": "orders",
        "identity": [
            {
                "type": "SystemAssigned",
                "principal_id": _SYSTEM_PRINCIPAL_ID,
                "tenant_id": "tenant-id",
                "identity_ids": [],
            }
        ],
    }
    if key_vault_reference_identity_id is not None:
        values["key_vault_reference_identity_id"] = key_vault_reference_identity_id
    return _resource(AzureResourceType.LINUX_WEB_APP, "orders", values)


def _function_app() -> TerraformResource:
    return _resource(
        AzureResourceType.LINUX_FUNCTION_APP,
        "orders_worker",
        {
            "id": f"{_RESOURCE_GROUP_SCOPE}/providers/Microsoft.Web/sites/orders-worker",
            "name": "orders-worker",
            "identity": [
                {
                    "type": "UserAssigned",
                    "identity_ids": ["azurerm_user_assigned_identity.orders_runtime.id"],
                }
            ],
        },
    )


def _user_assigned_identity() -> TerraformResource:
    return _resource(
        AzureResourceType.USER_ASSIGNED_IDENTITY,
        "orders_runtime",
        {
            "id": _USER_IDENTITY_ID,
            "name": "orders-runtime",
            "principal_id": _USER_PRINCIPAL_ID,
            "client_id": "orders-runtime-client-id",
            "tenant_id": "tenant-id",
        },
    )


def _access_policy(
    *,
    principal_id: object = _USER_PRINCIPAL_ID,
    key_permissions: object = ("Decrypt", "UnwrapKey", "Sign"),
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.KEY_VAULT_ACCESS_POLICY,
        "runtime",
        {
            "key_vault_id": "azurerm_key_vault.orders.id",
            "tenant_id": "tenant-id",
            "object_id": principal_id,
            "key_permissions": (list(key_permissions) if isinstance(key_permissions, tuple) else key_permissions),
        },
        unknown_values=unknown_values,
    )


def _role_assignment(
    *,
    principal_id: object = _SYSTEM_PRINCIPAL_ID,
    scope: object = "azurerm_key_vault.orders.id",
    role_id: str = _CRYPTO_USER_ID,
    role_name: str = "Key Vault Crypto User",
    condition: str | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "scope": scope,
        "role_definition_id": f"{_ROLE_ID_PREFIX}/{role_id}",
        "role_definition_name": role_name,
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if condition is not None:
        values["condition"] = condition
        values["condition_version"] = "2.0"
    return _resource(AzureResourceType.ROLE_ASSIGNMENT, "key_access", values)


def _unknown_custom_role() -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_DEFINITION,
        "key_operator",
        {
            "id": _CUSTOM_ROLE_ID,
            "name": "Custom Key Operator",
            "scope": _SUBSCRIPTION_SCOPE,
            "assignable_scopes": [_SUBSCRIPTION_SCOPE],
            "permissions": [
                {
                    "actions": [],
                    "not_actions": [],
                    "data_actions": [
                        "Microsoft.KeyVault/vaults/keys/decrypt/action",
                    ],
                    "not_data_actions": [],
                }
            ],
        },
        unknown_values={"permissions": True},
    )


def _custom_role_assignment() -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        "custom_key_access",
        {
            "scope": "azurerm_key_vault.orders.id",
            "role_definition_id": _CUSTOM_ROLE_ID,
            "principal_id": _SYSTEM_PRINCIPAL_ID,
            "principal_type": "ServicePrincipal",
        },
    )


def _workload_facts(
    resources: list[TerraformResource],
    *,
    address: str = "azurerm_linux_web_app.orders",
):
    inventory = AzureNormalizer().normalize(resources)
    workload = inventory.get_by_address(address)
    assert workload is not None
    return azure_facts(workload)


class AzureAppServiceKeyVaultOperationPathTests(unittest.TestCase):
    def test_system_identity_crypto_user_preserves_operations_and_exact_key_identity(self) -> None:
        facts = _workload_facts(
            [
                _vault(rbac_enabled=True),
                _key(),
                _web_app(key_vault_reference_identity_id=_USER_IDENTITY_ID),
                _role_assignment(scope=_SUBSCRIPTION_SCOPE),
            ]
        )

        paths = facts.app_service_key_vault_operation_paths
        self.assertEqual({path["operation"] for path in paths}, {"decrypt", "unwrap", "sign"})
        self.assertEqual(
            {path["operation_class"] for path in paths},
            {"plaintext_recovery", "authenticator_generation"},
        )
        for path in paths:
            self.assertEqual(path["identity_kind"], "system_assigned")
            self.assertEqual(path["identity_address"], "azurerm_linux_web_app.orders")
            self.assertEqual(path["principal_id"], _SYSTEM_PRINCIPAL_ID)
            self.assertEqual(path["credential_context"], "workload_runtime")
            self.assertEqual(path["key_address"], "azurerm_key_vault_key.signing")
            self.assertEqual(path["key_uri"], _KEY_URI)
            self.assertEqual(path["key_versionless_uri"], _KEY_VERSIONLESS_URI)
            self.assertEqual(path["key_resource_id"], _KEY_RESOURCE_ID)
            self.assertEqual(path["key_versionless_resource_id"], _KEY_VERSIONLESS_RESOURCE_ID)
            self.assertEqual(path["key_version"], "v-001")
            self.assertEqual(path["authorization_state"], "granted")
            self.assertEqual(path["authorization_model"], "azure_rbac")
            self.assertEqual(path["scope_type"], "subscription")
            self.assertEqual(path["scope_arm_id"], _SUBSCRIPTION_SCOPE)
            self.assertEqual(path["grant_source_type"], AzureResourceType.ROLE_ASSIGNMENT)
        self.assertEqual(facts.app_service_key_vault_operation_path_uncertainties, [])

    def test_user_identity_legacy_policy_intersects_grant_with_key_operations(self) -> None:
        facts = _workload_facts(
            [
                _vault(),
                _key(key_opts=("unwrapKey", "sign")),
                _user_assigned_identity(),
                _function_app(),
                _access_policy(),
            ],
            address="azurerm_linux_function_app.orders_worker",
        )

        paths = facts.app_service_key_vault_operation_paths
        self.assertEqual({path["operation"] for path in paths}, {"unwrap", "sign"})
        self.assertNotIn("decrypt", {path["operation"] for path in paths})
        self.assertEqual(
            next(path for path in paths if path["operation"] == "unwrap")["matched_key_operation"],
            "unwrapKey",
        )
        for path in paths:
            self.assertEqual(path["identity_kind"], "user_assigned")
            self.assertEqual(
                path["identity_address"],
                "azurerm_user_assigned_identity.orders_runtime",
            )
            self.assertEqual(path["principal_id"], _USER_PRINCIPAL_ID)
            self.assertEqual(path["grant_kind"], "access_policy")
            self.assertEqual(path["authorization_model"], "access_policy")
            self.assertEqual(path["scope_type"], "vault")
            self.assertEqual(path["scope_arm_id"], _VAULT_ID)
            self.assertEqual(
                path["grant_source_address"],
                "azurerm_key_vault_access_policy.runtime",
            )
            self.assertEqual(
                path["grant_source_type"],
                AzureResourceType.KEY_VAULT_ACCESS_POLICY,
            )

    def test_service_encryption_user_exposes_unwrap_but_not_wrap_or_sign(self) -> None:
        facts = _workload_facts(
            [
                _vault(rbac_enabled=True),
                _key(key_opts=("wrapKey", "unwrapKey", "sign")),
                _web_app(),
                _role_assignment(
                    role_id=_SERVICE_ENCRYPTION_USER_ID,
                    role_name="Key Vault Crypto Service Encryption User",
                ),
            ]
        )

        self.assertEqual(
            [path["operation"] for path in facts.app_service_key_vault_operation_paths],
            ["unwrap"],
        )
        self.assertEqual(
            facts.app_service_key_vault_operation_paths[0]["operation_class"],
            "plaintext_recovery",
        )

    def test_rbac_scope_granularity_is_preserved(self) -> None:
        cases = (
            ("subscription", _SUBSCRIPTION_SCOPE, _SUBSCRIPTION_SCOPE),
            ("resource_group", _RESOURCE_GROUP_SCOPE, _RESOURCE_GROUP_SCOPE),
            ("vault", "azurerm_key_vault.orders.id", _VAULT_ID),
            (
                "key",
                "azurerm_key_vault_key.signing.resource_versionless_id",
                _KEY_VERSIONLESS_RESOURCE_ID,
            ),
        )
        for expected_type, scope, expected_arm_id in cases:
            with self.subTest(scope_type=expected_type):
                facts = _workload_facts(
                    [
                        _vault(rbac_enabled=True),
                        _key(key_opts=("decrypt",)),
                        _web_app(),
                        _role_assignment(scope=scope),
                    ]
                )
                path = facts.app_service_key_vault_operation_paths[0]
                self.assertEqual(path["scope_type"], expected_type)
                self.assertEqual(path["scope"], scope)
                self.assertEqual(path["scope_arm_id"], expected_arm_id)

    def test_versionless_key_identity_is_not_promoted_to_versioned_fields(self) -> None:
        facts = _workload_facts(
            [
                _vault(),
                _key(key_opts=("decrypt",), version=None),
                _web_app(),
                _access_policy(
                    principal_id=_SYSTEM_PRINCIPAL_ID,
                    key_permissions=("Decrypt",),
                ),
            ]
        )

        path = facts.app_service_key_vault_operation_paths[0]
        self.assertIsNone(path["key_uri"])
        self.assertEqual(path["key_versionless_uri"], _KEY_VERSIONLESS_URI)
        self.assertIsNone(path["key_resource_id"])
        self.assertEqual(path["key_versionless_resource_id"], _KEY_VERSIONLESS_RESOURCE_ID)
        self.assertIsNone(path["key_version"])

    def test_key_vault_reference_identity_is_not_an_application_runtime_identity(self) -> None:
        facts = _workload_facts(
            [
                _vault(rbac_enabled=True),
                _key(key_opts=("decrypt",)),
                _user_assigned_identity(),
                _web_app(key_vault_reference_identity_id=_USER_IDENTITY_ID),
                _role_assignment(principal_id=_USER_PRINCIPAL_ID),
            ]
        )

        self.assertEqual(facts.app_service_key_vault_operation_paths, [])
        self.assertEqual(facts.app_service_key_vault_operation_path_uncertainties, [])

    def test_conditional_authority_and_unknown_key_operations_remain_uncertain(self) -> None:
        conditional = _workload_facts(
            [
                _vault(rbac_enabled=True),
                _key(key_opts=("decrypt",)),
                _web_app(),
                _role_assignment(condition="@Resource[Microsoft.KeyVault/vaults/keys:name] StringEquals 'signing'"),
            ]
        )
        unknown_key_ops = _workload_facts(
            [
                _vault(rbac_enabled=True),
                _key(key_opts=("decrypt",), unknown_key_opts=True),
                _web_app(),
                _role_assignment(),
            ]
        )

        self.assertEqual(conditional.app_service_key_vault_operation_paths, [])
        self.assertTrue(
            any(
                "non-deterministic decrypt authority" in value
                for value in conditional.app_service_key_vault_operation_path_uncertainties
            )
        )
        self.assertEqual(unknown_key_ops.app_service_key_vault_operation_paths, [])
        self.assertTrue(
            any(
                "key_opts are unresolved" in value
                for value in unknown_key_ops.app_service_key_vault_operation_path_uncertainties
            )
        )

    def test_unknown_quiet_grant_operations_do_not_create_path_uncertainty(self) -> None:
        unknown_role = _workload_facts(
            [
                _vault(rbac_enabled=True),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _unknown_custom_role(),
                _custom_role_assignment(),
            ]
        )
        unresolved_principal = _workload_facts(
            [
                _vault(),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _access_policy(
                    principal_id="stale-principal",
                    key_permissions=("Decrypt",),
                    unknown_values={"object_id": True},
                ),
            ]
        )

        self.assertEqual(unknown_role.app_service_key_vault_operation_paths, [])
        self.assertEqual(
            unknown_role.app_service_key_vault_operation_path_uncertainties,
            [],
        )
        self.assertEqual(
            unresolved_principal.app_service_key_vault_operation_paths,
            [],
        )
        self.assertEqual(
            unresolved_principal.app_service_key_vault_operation_path_uncertainties,
            [],
        )

    def test_unresolved_principal_remains_uncertain_but_unrelated_and_quiet_grants_do_not(self) -> None:
        unresolved = _workload_facts(
            [
                _vault(),
                _key(key_opts=("decrypt",)),
                _web_app(),
                _access_policy(
                    principal_id="stale-principal",
                    key_permissions=("Decrypt",),
                    unknown_values={"object_id": True},
                ),
            ]
        )
        unrelated = _workload_facts(
            [
                _vault(),
                _key(key_opts=("decrypt",)),
                _web_app(),
                _access_policy(
                    principal_id="other-principal",
                    key_permissions=("Decrypt",),
                ),
            ]
        )
        quiet = _workload_facts(
            [
                _vault(),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _access_policy(
                    principal_id=_SYSTEM_PRINCIPAL_ID,
                    key_permissions=("Encrypt",),
                ),
            ]
        )

        self.assertEqual(unresolved.app_service_key_vault_operation_paths, [])
        self.assertTrue(
            any(
                "principal applicability is unresolved" in value
                for value in unresolved.app_service_key_vault_operation_path_uncertainties
            )
        )
        self.assertEqual(unrelated.app_service_key_vault_operation_paths, [])
        self.assertEqual(unrelated.app_service_key_vault_operation_path_uncertainties, [])
        self.assertEqual(quiet.app_service_key_vault_operation_paths, [])
        self.assertEqual(quiet.app_service_key_vault_operation_path_uncertainties, [])


if __name__ == "__main__":
    unittest.main()

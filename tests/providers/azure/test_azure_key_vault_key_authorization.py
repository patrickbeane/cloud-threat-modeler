from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_SUBSCRIPTION_ID = "sub-0001"
_SUBSCRIPTION_SCOPE = f"/subscriptions/{_SUBSCRIPTION_ID}"
_RESOURCE_GROUP_SCOPE = f"{_SUBSCRIPTION_SCOPE}/resourceGroups/app"
_OTHER_RESOURCE_GROUP_SCOPE = f"{_SUBSCRIPTION_SCOPE}/resourceGroups/other"
_MANAGEMENT_GROUP_SCOPE = "/providers/Microsoft.Management/managementGroups/platform"
_VAULT_ID = f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/app/providers/Microsoft.KeyVault/vaults/orders"
_VAULT_URI = "https://orders.vault.azure.net"
_KEY_VERSIONLESS_URI = f"{_VAULT_URI}/keys/signing"
_KEY_URI = f"{_KEY_VERSIONLESS_URI}/v-001"
_KEY_VERSIONLESS_RESOURCE_ID = f"{_VAULT_ID}/keys/signing"
_KEY_RESOURCE_ID = f"{_KEY_VERSIONLESS_RESOURCE_ID}/v-001"
_PRINCIPAL_ID = "runtime-principal-id"
_ROLE_ID_PREFIX = "/providers/Microsoft.Authorization/roleDefinitions"
_ADMINISTRATOR_ID = "00482a5a-887f-4fb3-b363-3b7fe8e74483"
_CRYPTO_OFFICER_ID = "14b46e9e-c2b7-41b4-b07b-48a6ebf60603"
_SERVICE_ENCRYPTION_USER_ID = "e147488a-f6f5-4113-8e2d-b22465e65bf6"
_CRYPTO_USER_ID = "12338af0-0e69-4776-bea7-57ae8d297424"
_CUSTOM_ROLE_ID = (
    f"/subscriptions/{_SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/custom-key-operator"
)


def _resource(
    resource_type: str,
    values: dict[str, object],
    *,
    name: str,
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


def _vault(
    *,
    rbac_enabled: object = False,
    inline_access_policies: list[dict[str, object]] | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": _VAULT_ID,
        "name": "orders",
        "vault_uri": _VAULT_URI,
        "enable_rbac_authorization": rbac_enabled,
    }
    if inline_access_policies is not None:
        values["access_policy"] = inline_access_policies
    return _resource(
        AzureResourceType.KEY_VAULT,
        values,
        name="orders",
        unknown_values=unknown_values,
    )


def _key(*, name: str = "signing", version: str = "v-001") -> TerraformResource:
    versionless_uri = f"{_VAULT_URI}/keys/{name}"
    versionless_resource_id = f"{_VAULT_ID}/keys/{name}"
    return _resource(
        AzureResourceType.KEY_VAULT_KEY,
        {
            "id": f"{versionless_uri}/{version}",
            "versionless_id": versionless_uri,
            "resource_id": f"{versionless_resource_id}/{version}",
            "resource_versionless_id": versionless_resource_id,
            "name": name,
            "version": version,
            "key_vault_id": "azurerm_key_vault.orders.id",
            "key_type": "RSA-HSM",
            "key_opts": ["encrypt", "decrypt", "wrapKey", "unwrapKey", "sign", "verify"],
        },
        name=name,
    )


def _access_policy(
    *,
    key_permissions: object = ("Get", "Decrypt"),
    object_id: object = _PRINCIPAL_ID,
    name: str = "runtime",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.KEY_VAULT_ACCESS_POLICY,
        {
            "key_vault_id": "azurerm_key_vault.orders.id",
            "tenant_id": "tenant-id",
            "object_id": object_id,
            "key_permissions": list(key_permissions) if isinstance(key_permissions, tuple) else key_permissions,
        },
        name=name,
        unknown_values=unknown_values,
    )


def _role_assignment(
    *,
    role_id: object | None = f"{_ROLE_ID_PREFIX}/{_CRYPTO_USER_ID}",
    role_name: object | None = "Key Vault Crypto User",
    scope: object = "azurerm_key_vault.orders.id",
    principal_id: object = _PRINCIPAL_ID,
    condition: object | None = None,
    condition_version: object | None = None,
    name: str = "key_access",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "scope": scope,
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if role_id is not None:
        values["role_definition_id"] = role_id
    if role_name is not None:
        values["role_definition_name"] = role_name
    if condition is not None or (unknown_values and "condition" in unknown_values):
        values["condition"] = condition
    if condition_version is not None or (unknown_values and "condition_version" in unknown_values):
        values["condition_version"] = condition_version
    return _resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        values,
        name=name,
        unknown_values=unknown_values,
    )


def _custom_role(
    *,
    data_actions: list[str],
    not_data_actions: list[str] | None = None,
    assignable_scopes: object = (f"/subscriptions/{_SUBSCRIPTION_ID}",),
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_DEFINITION,
        {
            "id": _CUSTOM_ROLE_ID,
            "name": "Custom Key Operator",
            "scope": f"/subscriptions/{_SUBSCRIPTION_ID}",
            "assignable_scopes": (
                list(assignable_scopes) if isinstance(assignable_scopes, tuple) else assignable_scopes
            ),
            "permissions": [
                {
                    "actions": [],
                    "not_actions": [],
                    "data_actions": data_actions,
                    "not_data_actions": not_data_actions or [],
                }
            ],
        },
        name="key_operator",
        unknown_values=unknown_values,
    )


def _key_facts(resources: list[TerraformResource], *, name: str = "signing"):
    inventory = AzureNormalizer().normalize(resources)
    key = inventory.get_by_address(f"azurerm_key_vault_key.{name}")
    assert key is not None
    return azure_facts(key)


class AzureKeyVaultKeyAuthorizationTests(unittest.TestCase):
    def test_legacy_access_policy_projects_exact_key_operations(self) -> None:
        facts = _key_facts(
            [
                _vault(),
                _key(),
                _access_policy(key_permissions=("Get", "Decrypt", "WrapKey", "Delete")),
            ]
        )

        self.assertEqual(len(facts.key_vault_key_authorization_grants), 1)
        grant = facts.key_vault_key_authorization_grants[0]
        self.assertEqual(grant["grant_kind"], "access_policy")
        self.assertEqual(grant["grant_scope_type"], "vault")
        self.assertEqual(grant["principal_id"], _PRINCIPAL_ID)
        self.assertEqual(grant["authorization_state"], "granted")
        self.assertEqual(
            grant["matched_operations"],
            ["read", "delete", "decrypt", "wrap"],
        )
        self.assertEqual(
            grant["access_classes"],
            ["metadata_read", "cryptographic_use", "destructive_administration"],
        )
        self.assertEqual(facts.key_vault_key_authorization_uncertainties, [])

    def test_list_only_access_policy_does_not_grant_exact_key_read(self) -> None:
        facts = _key_facts(
            [
                _vault(),
                _key(),
                _access_policy(key_permissions=("List",)),
            ]
        )

        grant = facts.key_vault_key_authorization_grants[0]
        self.assertEqual(grant["key_permissions"], ["list"])
        self.assertEqual(grant["matched_operations"], ["list"])
        self.assertNotIn("read", grant["matched_operations"])
        self.assertEqual(grant["access_classes"], ["metadata_read"])
        self.assertEqual(grant["authorization_state"], "granted")

    def test_named_built_in_roles_retain_exact_modeled_key_operations(self) -> None:
        cases = (
            (
                "Key Vault Administrator",
                _ADMINISTRATOR_ID,
                {operation for operation in _all_operation_names()},
            ),
            (
                "Key Vault Crypto Officer",
                _CRYPTO_OFFICER_ID,
                {operation for operation in _all_operation_names()},
            ),
            (
                "Key Vault Crypto Service Encryption User",
                _SERVICE_ENCRYPTION_USER_ID,
                {"read", "wrap", "unwrap"},
            ),
            (
                "Key Vault Crypto User",
                _CRYPTO_USER_ID,
                {
                    "read",
                    "update",
                    "backup",
                    "encrypt",
                    "decrypt",
                    "wrap",
                    "unwrap",
                    "sign",
                    "verify",
                },
            ),
        )
        for role_name, role_id, expected_operations in cases:
            with self.subTest(role=role_name):
                facts = _key_facts(
                    [
                        _vault(rbac_enabled=True),
                        _key(),
                        _role_assignment(
                            role_id=f"{_ROLE_ID_PREFIX}/{role_id}",
                            role_name=role_name,
                        ),
                    ]
                )
                self.assertEqual(len(facts.key_vault_key_authorization_grants), 1)
                grant = facts.key_vault_key_authorization_grants[0]
                self.assertEqual(grant["role_kind"], "built_in")
                self.assertEqual(grant["role_resolution_state"], "modeled_subset")
                self.assertEqual(set(grant["matched_operations"]), expected_operations)
                self.assertEqual(grant["authorization_state"], "granted")

    def test_role_name_fallback_works_only_when_role_id_is_absent(self) -> None:
        facts = _key_facts(
            [
                _vault(rbac_enabled=True),
                _key(),
                _role_assignment(
                    role_id=None,
                    role_name="Key Vault Crypto Service Encryption User",
                ),
            ]
        )

        grant = facts.key_vault_key_authorization_grants[0]
        self.assertEqual(grant["matched_operations"], ["read", "wrap", "unwrap"])
        self.assertEqual(grant["authorization_state"], "granted")

    def test_exact_key_scope_does_not_fan_out_to_sibling_key(self) -> None:
        resources = [
            _vault(rbac_enabled=True),
            _key(),
            _key(name="archive"),
            _role_assignment(
                scope="azurerm_key_vault_key.signing.resource_versionless_id",
            ),
        ]
        signing = _key_facts(resources)
        archive = _key_facts(resources, name="archive")

        self.assertEqual(signing.key_vault_key_authorization_grants[0]["grant_scope_type"], "key")
        self.assertEqual(signing.key_vault_key_authorization_grants[0]["authorization_state"], "granted")
        self.assertEqual(archive.key_vault_key_authorization_grants, [])

    def test_subscription_scope_role_assignment_applies_to_key(self) -> None:
        facts = _key_facts(
            [
                _vault(rbac_enabled=True),
                _key(),
                _role_assignment(scope=_SUBSCRIPTION_SCOPE),
            ]
        )

        grant = facts.key_vault_key_authorization_grants[0]
        self.assertEqual(grant["grant_scope_type"], "subscription")
        self.assertEqual(grant["scope_resolution_state"], "resolved")
        self.assertEqual(grant["authorization_state"], "granted")

    def test_resource_group_scope_role_assignment_applies_only_within_group(self) -> None:
        matching = _key_facts(
            [
                _vault(rbac_enabled=True),
                _key(),
                _role_assignment(scope=_RESOURCE_GROUP_SCOPE),
            ]
        )
        unrelated = _key_facts(
            [
                _vault(rbac_enabled=True),
                _key(),
                _role_assignment(scope=_OTHER_RESOURCE_GROUP_SCOPE),
            ]
        )

        grant = matching.key_vault_key_authorization_grants[0]
        self.assertEqual(grant["grant_scope_type"], "resource_group")
        self.assertEqual(grant["scope_resolution_state"], "resolved")
        self.assertEqual(grant["authorization_state"], "granted")
        self.assertEqual(unrelated.key_vault_key_authorization_grants, [])

    def test_parent_scope_custom_role_checks_actual_assignment_scope(self) -> None:
        facts = _key_facts(
            [
                _vault(rbac_enabled=True),
                _key(),
                _custom_role(
                    data_actions=["Microsoft.KeyVault/vaults/keys/decrypt/action"],
                    assignable_scopes=(_RESOURCE_GROUP_SCOPE,),
                ),
                _role_assignment(
                    role_id="azurerm_role_definition.key_operator.role_definition_resource_id",
                    role_name=None,
                    scope=_SUBSCRIPTION_SCOPE,
                ),
            ]
        )

        grant = facts.key_vault_key_authorization_grants[0]
        self.assertEqual(grant["grant_scope_type"], "subscription")
        self.assertEqual(
            grant["assignable_scope_compatibility_state"],
            "outside_assignable_scope",
        )
        self.assertEqual(grant["authorization_state"], "unknown")

    def test_management_group_scope_remains_an_uncertain_candidate(self) -> None:
        facts = _key_facts(
            [
                _vault(rbac_enabled=True),
                _key(),
                _role_assignment(scope=_MANAGEMENT_GROUP_SCOPE),
            ]
        )

        grant = facts.key_vault_key_authorization_grants[0]
        self.assertEqual(grant["grant_scope_type"], "management_group")
        self.assertEqual(grant["scope_resolution_state"], "unknown")
        self.assertEqual(grant["authorization_state"], "unknown")
        self.assertTrue(
            any(
                "management_group scope inheritance cannot be proven" in value
                for value in facts.key_vault_key_authorization_uncertainties
            )
        )

    def test_versioned_or_data_plane_key_scope_is_not_an_exact_rbac_scope(self) -> None:
        for scope in (
            "azurerm_key_vault_key.signing.resource_id",
            _KEY_RESOURCE_ID,
            _KEY_VERSIONLESS_URI,
        ):
            with self.subTest(scope=scope):
                facts = _key_facts(
                    [
                        _vault(rbac_enabled=True),
                        _key(),
                        _role_assignment(scope=scope),
                    ]
                )
                self.assertEqual(facts.key_vault_key_authorization_grants, [])
                self.assertTrue(
                    any(
                        "not a valid Key Vault RBAC" in value
                        for value in facts.key_vault_key_authorization_uncertainties
                    )
                )

    def test_custom_role_wildcard_and_not_data_actions_are_applied(self) -> None:
        facts = _key_facts(
            [
                _vault(rbac_enabled=True),
                _key(),
                _custom_role(
                    data_actions=["Microsoft.KeyVault/vaults/keys/*"],
                    not_data_actions=[
                        "Microsoft.KeyVault/vaults/keys/decrypt/action",
                        "Microsoft.KeyVault/vaults/keys/delete",
                    ],
                ),
                _role_assignment(
                    role_id="azurerm_role_definition.key_operator.role_definition_resource_id",
                    role_name="Key Vault Crypto User",
                    scope="azurerm_key_vault_key.signing.resource_versionless_id",
                ),
            ]
        )

        grant = facts.key_vault_key_authorization_grants[0]
        self.assertEqual(grant["role_kind"], "custom")
        self.assertEqual(grant["role_definition_address"], "azurerm_role_definition.key_operator")
        self.assertEqual(grant["assignable_scope_compatibility_state"], "resolved")
        self.assertNotIn("decrypt", grant["matched_operations"])
        self.assertNotIn("delete", grant["matched_operations"])
        self.assertEqual(
            set(grant["excluded_data_actions"]),
            {
                "Microsoft.KeyVault/vaults/keys/decrypt/action",
                "Microsoft.KeyVault/vaults/keys/delete",
            },
        )
        self.assertEqual(grant["authorization_state"], "granted")

    def test_custom_role_outside_assignable_scope_is_not_deterministic(self) -> None:
        facts = _key_facts(
            [
                _vault(rbac_enabled=True),
                _key(),
                _custom_role(
                    data_actions=["Microsoft.KeyVault/vaults/keys/decrypt/action"],
                    assignable_scopes=(f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/other",),
                ),
                _role_assignment(
                    role_id="azurerm_role_definition.key_operator.role_definition_resource_id",
                    role_name=None,
                ),
            ]
        )

        grant = facts.key_vault_key_authorization_grants[0]
        self.assertEqual(
            grant["assignable_scope_compatibility_state"],
            "outside_assignable_scope",
        )
        self.assertEqual(grant["authorization_state"], "unknown")
        self.assertTrue(
            any("outside_assignable_scope" in value for value in facts.key_vault_key_authorization_uncertainties)
        )

    def test_custom_role_id_is_authoritative_over_conflicting_builtin_name(self) -> None:
        facts = _key_facts(
            [
                _vault(rbac_enabled=True),
                _key(),
                _custom_role(
                    data_actions=["Microsoft.KeyVault/vaults/keys/decrypt/action"],
                ),
                _role_assignment(
                    role_id="azurerm_role_definition.key_operator.role_definition_resource_id",
                    role_name="Key Vault Administrator",
                ),
            ]
        )

        grant = facts.key_vault_key_authorization_grants[0]
        self.assertEqual(grant["role_kind"], "custom")
        self.assertEqual(grant["matched_operations"], ["decrypt"])

    def test_key_rbac_conditions_remain_unsupported_or_unknown(self) -> None:
        conditional = _key_facts(
            [
                _vault(rbac_enabled=True),
                _key(),
                _role_assignment(
                    condition="@Resource[Microsoft.KeyVault/vaults:Name] StringEquals 'orders'",
                    condition_version="2.0",
                ),
            ]
        )
        unknown = _key_facts(
            [
                _vault(rbac_enabled=True),
                _key(),
                _role_assignment(
                    condition=None,
                    condition_version="2.0",
                    unknown_values={"condition": True},
                ),
            ]
        )

        conditional_grant = conditional.key_vault_key_authorization_grants[0]
        self.assertEqual(conditional_grant["condition_state"], "configured")
        self.assertEqual(conditional_grant["condition_version"], "2.0")
        self.assertEqual(
            conditional_grant["condition_applicability_state"],
            "unsupported",
        )
        self.assertEqual(conditional_grant["authorization_state"], "unknown")
        self.assertTrue(
            any(
                "condition applicability is unsupported" in value
                for value in conditional.key_vault_key_authorization_uncertainties
            )
        )
        unknown_grant = unknown.key_vault_key_authorization_grants[0]
        self.assertEqual(unknown_grant["condition_state"], "unknown")
        self.assertEqual(unknown_grant["condition_applicability_state"], "unknown")
        self.assertEqual(unknown_grant["authorization_state"], "unknown")

    def test_active_authorization_model_filters_inactive_grant_family(self) -> None:
        rbac = _key_facts(
            [
                _vault(rbac_enabled=True),
                _key(),
                _access_policy(),
                _role_assignment(),
            ]
        )
        legacy = _key_facts(
            [
                _vault(rbac_enabled=False),
                _key(),
                _access_policy(),
                _role_assignment(),
            ]
        )
        unknown = _key_facts(
            [
                _vault(
                    rbac_enabled=None,
                    unknown_values={"enable_rbac_authorization": True},
                ),
                _key(),
                _access_policy(),
                _role_assignment(),
            ]
        )

        self.assertEqual(
            {grant["grant_kind"] for grant in rbac.key_vault_key_authorization_grants},
            {"rbac"},
        )
        self.assertEqual(
            {grant["grant_kind"] for grant in legacy.key_vault_key_authorization_grants},
            {"access_policy"},
        )
        self.assertEqual(
            {grant["grant_kind"] for grant in unknown.key_vault_key_authorization_grants},
            {"access_policy", "rbac"},
        )
        self.assertEqual(
            {grant["authorization_state"] for grant in unknown.key_vault_key_authorization_grants},
            {"unknown"},
        )

    def test_unknown_inline_policy_set_remains_authorization_uncertainty(self) -> None:
        facts = _key_facts(
            [
                _vault(unknown_values={"access_policy": True}),
                _key(),
            ]
        )

        self.assertEqual(facts.key_vault_key_authorization_grants, [])
        self.assertTrue(
            any(
                "access_policy is unknown after planning" in value
                for value in facts.key_vault_key_authorization_uncertainties
            )
        )

    def test_unrecognized_access_policy_permission_does_not_expand_authority(self) -> None:
        facts = _key_facts(
            [
                _vault(),
                _key(),
                _access_policy(key_permissions=("All",)),
            ]
        )

        grant = facts.key_vault_key_authorization_grants[0]
        self.assertEqual(grant["matched_operations"], [])
        self.assertEqual(grant["authorization_state"], "unknown")
        self.assertTrue(
            any(
                "unrecognized Key Vault key permissions all" in value
                for value in facts.key_vault_key_authorization_uncertainties
            )
        )

    def test_unknown_access_policy_principal_and_permissions_do_not_become_granted(self) -> None:
        facts = _key_facts(
            [
                _vault(),
                _key(),
                _access_policy(
                    key_permissions=("Decrypt",),
                    object_id="stale-principal",
                    unknown_values={"object_id": True, "key_permissions": True},
                ),
            ]
        )

        grant = facts.key_vault_key_authorization_grants[0]
        self.assertIsNone(grant["principal_id"])
        self.assertEqual(grant["principal_state"], "unknown")
        self.assertEqual(grant["key_permissions"], [])
        self.assertEqual(grant["key_permissions_state"], "unknown")
        self.assertEqual(grant["authorization_state"], "unknown")
        self.assertEqual(grant["matched_operations"], [])

    def test_unknown_role_id_cannot_fall_back_to_builtin_role_name(self) -> None:
        facts = _key_facts(
            [
                _vault(rbac_enabled=True),
                _key(),
                _role_assignment(
                    role_id=None,
                    role_name="Key Vault Administrator",
                    unknown_values={"role_definition_id": True},
                ),
            ]
        )

        grant = facts.key_vault_key_authorization_grants[0]
        self.assertEqual(grant["role_kind"], "unknown")
        self.assertEqual(grant["role_resolution_state"], "unresolved")
        self.assertEqual(grant["matched_operations"], [])
        self.assertEqual(grant["authorization_state"], "unknown")

    def test_unresolved_custom_role_permissions_remain_unknown(self) -> None:
        facts = _key_facts(
            [
                _vault(rbac_enabled=True),
                _key(),
                _custom_role(
                    data_actions=["Microsoft.KeyVault/vaults/keys/decrypt/action"],
                    unknown_values={"permissions": True},
                ),
                _role_assignment(
                    role_id="azurerm_role_definition.key_operator.role_definition_resource_id",
                    role_name=None,
                ),
            ]
        )

        grant = facts.key_vault_key_authorization_grants[0]
        self.assertEqual(grant["role_kind"], "custom")
        self.assertEqual(grant["role_resolution_state"], "unknown")
        self.assertEqual(grant["matched_operations"], [])
        self.assertEqual(grant["authorization_state"], "unknown")

    def test_resolved_non_key_vault_custom_role_does_not_attach_to_key(self) -> None:
        facts = _key_facts(
            [
                _vault(rbac_enabled=True),
                _key(),
                _custom_role(data_actions=["Microsoft.Storage/storageAccounts/read"]),
                _role_assignment(
                    role_id="azurerm_role_definition.key_operator.role_definition_resource_id",
                    role_name=None,
                ),
            ]
        )

        self.assertEqual(facts.key_vault_key_authorization_grants, [])
        self.assertEqual(facts.key_vault_key_authorization_uncertainties, [])

    def test_unknown_assignment_scope_is_preserved_as_key_uncertainty(self) -> None:
        facts = _key_facts(
            [
                _vault(rbac_enabled=True),
                _key(),
                _role_assignment(
                    scope=None,
                    unknown_values={"scope": True},
                ),
            ]
        )

        self.assertEqual(facts.key_vault_key_authorization_grants, [])
        self.assertTrue(
            any(
                "role assignment scope is unresolved" in value
                for value in facts.key_vault_key_authorization_uncertainties
            )
        )

    def test_inline_and_standalone_access_policy_managers_are_ambiguous(self) -> None:
        facts = _key_facts(
            [
                _vault(
                    inline_access_policies=[
                        {
                            "tenant_id": "tenant-id",
                            "object_id": "inline-principal",
                            "key_permissions": ["Get"],
                        }
                    ]
                ),
                _key(),
                _access_policy(key_permissions=("Decrypt",)),
            ]
        )

        self.assertEqual(len(facts.key_vault_key_authorization_grants), 2)
        self.assertEqual(
            {grant["management_state"] for grant in facts.key_vault_key_authorization_grants},
            {"ambiguous"},
        )
        self.assertEqual(
            {grant["authorization_state"] for grant in facts.key_vault_key_authorization_grants},
            {"ambiguous"},
        )
        self.assertTrue(
            any("inline and standalone" in value for value in facts.key_vault_key_authorization_uncertainties)
        )


def _all_operation_names() -> tuple[str, ...]:
    return (
        "read",
        "create",
        "import",
        "update",
        "recover",
        "restore",
        "delete",
        "backup",
        "purge",
        "encrypt",
        "decrypt",
        "wrap",
        "unwrap",
        "sign",
        "verify",
        "release",
        "rotate",
        "get_rotation_policy",
        "set_rotation_policy",
    )


if __name__ == "__main__":
    unittest.main()

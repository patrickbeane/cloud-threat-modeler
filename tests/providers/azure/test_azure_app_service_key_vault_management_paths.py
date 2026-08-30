from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _KEY_VERSIONLESS_RESOURCE_ID,
    _SYSTEM_PRINCIPAL_ID,
    _USER_PRINCIPAL_ID,
    _VAULT_ID,
    _access_policy,
    _function_app,
    _key,
    _resource,
    _role_assignment,
    _user_assigned_identity,
    _vault,
    _web_app,
)
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_CRYPTO_OFFICER_ID = "14b46e9e-c2b7-41b4-b07b-48a6ebf60603"
_KEY_VAULT_DATA_ACCESS_ADMIN_ID = "8b54135c-b56d-4d72-a534-26097cfdc8d8"
_CONTROL_ROLE_ID = "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/key-vault-control-admin"


def _vault_with_recovery(
    *,
    rbac_enabled: object,
    purge_protection: bool | None,
    purge_protection_unknown: bool = False,
) -> TerraformResource:
    vault = _vault(rbac_enabled=rbac_enabled)
    vault.values["purge_protection_enabled"] = purge_protection
    if purge_protection_unknown:
        vault.unknown_values["purge_protection_enabled"] = True
    return vault


def _crypto_officer_assignment(
    *,
    principal_id: object = _SYSTEM_PRINCIPAL_ID,
    scope: object = "azurerm_key_vault.orders.id",
) -> TerraformResource:
    return _role_assignment(
        principal_id=principal_id,
        scope=scope,
        role_id=_CRYPTO_OFFICER_ID,
        role_name="Key Vault Crypto Officer",
    )


def _control_role(
    *,
    actions: tuple[str, ...],
    not_actions: tuple[str, ...] = (),
    unknown_permissions: bool = False,
) -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_DEFINITION,
        "key_vault_control_admin",
        {
            "id": _CONTROL_ROLE_ID,
            "role_definition_id": _CONTROL_ROLE_ID,
            "name": "Key Vault Control Administrator",
            "scope": "/subscriptions/sub-0001",
            "assignable_scopes": [_VAULT_ID],
            "permissions": [
                {
                    "actions": list(actions),
                    "not_actions": list(not_actions),
                    "data_actions": [],
                    "not_data_actions": [],
                }
            ],
        },
        unknown_values={"permissions": True} if unknown_permissions else None,
    )


def _control_assignment(
    *,
    scope: object = _VAULT_ID,
    principal_id: object = _SYSTEM_PRINCIPAL_ID,
    condition: str | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "scope": scope,
        "role_definition_id": _CONTROL_ROLE_ID,
        "role_definition_name": "Key Vault Control Administrator",
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if condition is not None:
        values["condition"] = condition
        values["condition_version"] = "2.0"
    return _resource(AzureResourceType.ROLE_ASSIGNMENT, "control", values)


def _built_in_assignment(
    role_id: str,
    role_name: str,
    *,
    scope: object = _VAULT_ID,
) -> TerraformResource:
    return _role_assignment(
        principal_id=_SYSTEM_PRINCIPAL_ID,
        scope=scope,
        role_id=role_id,
        role_name=role_name,
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


class AzureAppServiceKeyVaultManagementPathTests(unittest.TestCase):
    def test_active_rbac_models_update_delete_and_delete_plus_purge(self) -> None:
        facts = _workload_facts(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _crypto_officer_assignment(scope="/subscriptions/sub-0001"),
            ]
        )

        paths = facts.app_service_key_vault_management_paths
        self.assertEqual(
            [path["operation"] for path in paths],
            ["delete", "delete_plus_purge", "update"],
        )
        for path in paths:
            self.assertEqual(path["identity_kind"], "system_assigned")
            self.assertEqual(path["principal_id"], _SYSTEM_PRINCIPAL_ID)
            self.assertEqual(path["credential_context"], "workload_runtime")
            self.assertEqual(path["target_type"], "key")
            self.assertEqual(path["target_address"], "azurerm_key_vault_key.signing")
            self.assertEqual(path["target_resource_id"], _KEY_VERSIONLESS_RESOURCE_ID)
            self.assertEqual(path["authorization_model"], "azure_rbac")
            self.assertEqual(path["authorization_basis"], "key_vault_data_plane_grant")
            self.assertEqual(path["scope_types"], ["subscription"])
            self.assertFalse(path["purge_protection_enabled"])
            self.assertEqual(path["lifecycle_compatibility_state"], "compatible")
            self.assertEqual(path["control_plane_grants"], [])
        sequence = next(path for path in paths if path["operation"] == "delete_plus_purge")
        self.assertEqual(sequence["step_operations"], ["delete", "purge"])
        self.assertEqual(sequence["operation_class"], "destructive_administration")
        self.assertEqual(sequence["management_effect"], "disruption")
        self.assertEqual(facts.app_service_key_vault_operation_paths, [])
        self.assertEqual(facts.app_service_key_vault_management_path_uncertainties, [])

    def test_purge_protection_blocks_permanent_delete_sequence(self) -> None:
        protected = _workload_facts(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=True),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _crypto_officer_assignment(),
            ]
        )
        unknown = _workload_facts(
            [
                _vault_with_recovery(
                    rbac_enabled=True,
                    purge_protection=None,
                    purge_protection_unknown=True,
                ),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _crypto_officer_assignment(),
            ]
        )

        self.assertEqual(
            {path["operation"] for path in protected.app_service_key_vault_management_paths},
            {"update", "delete"},
        )
        self.assertTrue(
            all(path["purge_protection_enabled"] is True for path in protected.app_service_key_vault_management_paths)
        )
        self.assertEqual(
            {path["operation"] for path in unknown.app_service_key_vault_management_paths},
            {"update", "delete"},
        )
        self.assertTrue(
            any(
                "delete-plus-purge compatibility" in value
                for value in unknown.app_service_key_vault_management_path_uncertainties
            )
        )

    def test_legacy_access_policy_uses_user_assigned_runtime_identity(self) -> None:
        facts = _workload_facts(
            [
                _vault_with_recovery(rbac_enabled=False, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _user_assigned_identity(),
                _function_app(),
                _access_policy(
                    principal_id=_USER_PRINCIPAL_ID,
                    key_permissions=("Update", "Delete", "Purge"),
                ),
            ],
            address="azurerm_linux_function_app.orders_worker",
        )

        self.assertEqual(
            {path["operation"] for path in facts.app_service_key_vault_management_paths},
            {"update", "delete", "delete_plus_purge"},
        )
        for path in facts.app_service_key_vault_management_paths:
            self.assertEqual(path["identity_kind"], "user_assigned")
            self.assertEqual(path["principal_id"], _USER_PRINCIPAL_ID)
            self.assertEqual(path["authorization_model"], "access_policy")
            self.assertEqual(path["scope_types"], ["vault"])

    def test_delete_and_purge_authority_do_not_combine_across_principals(self) -> None:
        facts = _workload_facts(
            [
                _vault_with_recovery(rbac_enabled=False, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _access_policy(
                    principal_id=_SYSTEM_PRINCIPAL_ID,
                    key_permissions=("Delete",),
                ),
                _resource(
                    AzureResourceType.KEY_VAULT_ACCESS_POLICY,
                    "other",
                    {
                        "key_vault_id": "azurerm_key_vault.orders.id",
                        "tenant_id": "tenant-id",
                        "object_id": "other-principal",
                        "key_permissions": ["Purge"],
                    },
                ),
            ]
        )

        self.assertEqual(
            [path["operation"] for path in facts.app_service_key_vault_management_paths],
            ["delete"],
        )

    def test_active_rbac_delegation_uses_only_control_plane_role_actions(self) -> None:
        facts = _workload_facts(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _control_role(actions=("Microsoft.Authorization/roleAssignments/write",)),
                _control_assignment(),
            ]
        )

        self.assertEqual(len(facts.app_service_key_vault_management_paths), 1)
        path = facts.app_service_key_vault_management_paths[0]
        self.assertEqual(path["operation"], "rbac_role_assignment_management")
        self.assertEqual(path["management_effect"], "delegation")
        self.assertEqual(path["delegation_mechanism"], "azure_rbac_role_assignment")
        self.assertEqual(path["target_type"], "vault")
        self.assertEqual(path["target_address"], "azurerm_key_vault.orders")
        self.assertEqual(path["target_resource_id"], _VAULT_ID)
        self.assertEqual(path["data_plane_grants"], [])
        self.assertEqual(path["grant_source_addresses"], ["azurerm_role_assignment.control"])
        self.assertEqual(
            path["control_plane_grants"][0]["matched_actions"],
            ["Microsoft.Authorization/roleAssignments/write"],
        )

    def test_legacy_delegation_is_distinct_from_rbac_role_management(self) -> None:
        facts = _workload_facts(
            [
                _vault_with_recovery(rbac_enabled=False, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _control_role(actions=("Microsoft.KeyVault/vaults/accessPolicies/write",)),
                _control_assignment(),
            ]
        )

        path = facts.app_service_key_vault_management_paths[0]
        self.assertEqual(path["operation"], "legacy_access_policy_mutation")
        self.assertEqual(path["delegation_mechanism"], "legacy_access_policy")
        self.assertEqual(path["authorization_model"], "access_policy")
        self.assertEqual(path["target_type"], "vault")
        self.assertEqual(path["evaluation_basis"], "modeled_arm_control_plane_authority")

    def test_active_model_filters_the_other_control_plane_delegation_mechanism(self) -> None:
        rbac = _workload_facts(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _control_role(actions=("Microsoft.KeyVault/vaults/accessPolicies/write",)),
                _control_assignment(),
            ]
        )
        legacy = _workload_facts(
            [
                _vault_with_recovery(rbac_enabled=False, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _control_role(actions=("Microsoft.Authorization/roleAssignments/write",)),
                _control_assignment(),
            ]
        )

        self.assertEqual(rbac.app_service_key_vault_management_paths, [])
        self.assertEqual(legacy.app_service_key_vault_management_paths, [])
        self.assertEqual(rbac.app_service_key_vault_management_path_uncertainties, [])
        self.assertEqual(legacy.app_service_key_vault_management_path_uncertainties, [])

    def test_vault_write_on_active_rbac_models_authorization_transition(self) -> None:
        facts = _workload_facts(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _web_app(),
                _control_role(actions=("Microsoft.KeyVault/vaults/write",)),
                _control_assignment(),
            ]
        )

        self.assertEqual(len(facts.app_service_key_vault_management_paths), 1)
        path = facts.app_service_key_vault_management_paths[0]
        self.assertEqual(path["operation"], "authorization_model_mutation")
        self.assertEqual(path["management_effect"], "delegation")
        self.assertEqual(
            path["delegation_mechanism"],
            "authorization_model_transition",
        )
        self.assertEqual(
            path["authorization_model_transition"],
            "azure_rbac_to_access_policy",
        )
        self.assertEqual(
            path["step_operations"],
            ["Microsoft.KeyVault/vaults/write"],
        )

    def test_data_plane_administrator_does_not_imply_control_plane_delegation(self) -> None:
        facts = _workload_facts(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _crypto_officer_assignment(),
            ]
        )

        self.assertEqual(
            {path["management_effect"] for path in facts.app_service_key_vault_management_paths},
            {"disruption"},
        )
        self.assertNotIn(
            "rbac_role_assignment_management",
            {path["operation"] for path in facts.app_service_key_vault_management_paths},
        )

    def test_not_actions_conditions_and_unknown_roles_fail_closed(self) -> None:
        excluded = _workload_facts(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _control_role(
                    actions=("*",),
                    not_actions=(
                        "Microsoft.Authorization/roleAssignments/write",
                        "Microsoft.KeyVault/vaults/write",
                    ),
                ),
                _control_assignment(),
            ]
        )
        conditioned = _workload_facts(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _control_role(actions=("Microsoft.Authorization/roleAssignments/write",)),
                _control_assignment(
                    condition="@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] StringEquals 'x'"
                ),
            ]
        )
        unknown = _workload_facts(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _control_role(
                    actions=("Microsoft.Authorization/roleAssignments/write",),
                    unknown_permissions=True,
                ),
                _control_assignment(),
            ]
        )

        self.assertEqual(excluded.app_service_key_vault_management_paths, [])
        self.assertEqual(excluded.app_service_key_vault_management_path_uncertainties, [])
        self.assertEqual(conditioned.app_service_key_vault_management_paths, [])
        self.assertTrue(conditioned.app_service_key_vault_management_path_uncertainties)
        self.assertEqual(unknown.app_service_key_vault_management_paths, [])
        self.assertTrue(unknown.app_service_key_vault_management_path_uncertainties)

    def test_key_vault_data_access_administrator_retains_delegation_constraint(self) -> None:
        facts = _workload_facts(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _built_in_assignment(
                    _KEY_VAULT_DATA_ACCESS_ADMIN_ID,
                    "Key Vault Data Access Administrator",
                ),
            ]
        )

        path = facts.app_service_key_vault_management_paths[0]
        self.assertEqual(path["operation"], "rbac_role_assignment_management")
        grant = path["control_plane_grants"][0]
        self.assertEqual(grant["assignment_condition_state"], "not_configured")
        self.assertEqual(grant["role_definition_condition_state"], "configured")
        self.assertEqual(
            grant["delegation_constraint_kind"],
            "allowed_role_definition_ids",
        )
        self.assertEqual(len(grant["allowed_role_definition_ids"]), 8)

    def test_key_scoped_rbac_delegation_preserves_exact_key_target(self) -> None:
        facts = _workload_facts(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _control_role(actions=("Microsoft.Authorization/roleAssignments/write",)),
                _control_assignment(scope=_KEY_VERSIONLESS_RESOURCE_ID),
            ]
        )

        path = facts.app_service_key_vault_management_paths[0]
        self.assertEqual(path["target_type"], "key")
        self.assertEqual(path["target_address"], "azurerm_key_vault_key.signing")
        self.assertEqual(path["scope_types"], ["key"])
        self.assertEqual(path["scope_arm_ids"], [_KEY_VERSIONLESS_RESOURCE_ID])

    def test_vault_delegation_does_not_require_a_modeled_key(self) -> None:
        facts = _workload_facts(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _web_app(),
                _control_role(actions=("Microsoft.Authorization/roleAssignments/write",)),
                _control_assignment(),
            ]
        )

        self.assertEqual(len(facts.app_service_key_vault_management_paths), 1)
        path = facts.app_service_key_vault_management_paths[0]
        self.assertEqual(path["operation"], "rbac_role_assignment_management")
        self.assertEqual(path["target_type"], "vault")
        self.assertEqual(path["target_address"], "azurerm_key_vault.orders")
        self.assertIsNone(path["key_address"])
        self.assertEqual(path["target_resource_id"], _VAULT_ID)
        self.assertEqual(facts.app_service_key_vault_management_path_uncertainties, [])

    def test_unknown_scope_on_data_plane_only_role_stays_quiet(self) -> None:
        assignment = _role_assignment(scope=None)
        assignment.unknown_values["scope"] = True
        facts = _workload_facts(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _web_app(),
                assignment,
            ]
        )

        self.assertEqual(facts.app_service_key_vault_management_paths, [])
        self.assertEqual(facts.app_service_key_vault_management_path_uncertainties, [])


if __name__ == "__main__":
    unittest.main()

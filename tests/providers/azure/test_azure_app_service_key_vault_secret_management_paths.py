from __future__ import annotations

import json
import unittest

from tests.providers.test_public_workload_secret_integrity_boundaries import (
    _AZURE_REFERENCE_IDENTITY_ID,
    _AZURE_REFERENCE_PRINCIPAL_ID,
    _AZURE_RUNTIME_IDENTITY_ID,
    _AZURE_RUNTIME_PRINCIPAL_ID,
    _AZURE_SECRET_RESOURCE_ID,
    _AZURE_SECRET_URI,
    _AZURE_SECRET_VERSION,
    _AZURE_SECRET_VERSIONLESS_URI,
    _AZURE_SYSTEM_PRINCIPAL_ID,
    _SECRET_PAYLOAD_SENTINEL,
    _azure_access_policy,
    _azure_identity,
    _azure_reference_reader_assignment,
    _azure_role_assignment,
    _azure_secret,
    _azure_secret_admin_role,
    _azure_vault,
    _azure_web_app,
    _resource,
)
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_decoration_stages import (
    default_azure_decoration_stages,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_SECRETS_OFFICER_ID = "/providers/Microsoft.Authorization/roleDefinitions/b86a8fe4-44ce-4948-aee5-eccb2c155cd7"


def _normalize(
    resources: list[TerraformResource],
):
    return AzureNormalizer().normalize(resources)


def _runtime_identity() -> TerraformResource:
    return _azure_identity(
        "runtime",
        identity_id=_AZURE_RUNTIME_IDENTITY_ID,
        principal_id=_AZURE_RUNTIME_PRINCIPAL_ID,
    )


def _system_secret_assignment(
    *,
    name: str = "system_secret_integrity",
    scope: str = "azurerm_key_vault.orders.id",
    condition: str | None = None,
) -> TerraformResource:
    assignment = _azure_role_assignment(
        name,
        principal_id=_AZURE_SYSTEM_PRINCIPAL_ID,
        role_definition_id=("azurerm_role_definition.secret_integrity.role_definition_resource_id"),
        role_definition_name="Orders Secret Integrity",
        condition=condition,
    )
    assignment.values["scope"] = scope
    return assignment


def _access_policy(
    name: str,
    *,
    principal_id: str,
    secret_permissions: tuple[str, ...],
) -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.KEY_VAULT_ACCESS_POLICY,
        name,
        {
            "key_vault_id": "azurerm_key_vault.orders.id",
            "tenant_id": "tenant-id",
            "object_id": principal_id,
            "secret_permissions": list(secret_permissions),
        },
    )


class AzureAppServiceKeyVaultSecretManagementPathTests(unittest.TestCase):
    def test_active_rbac_models_exact_secret_lifecycle_paths(self) -> None:
        conditioned = _azure_role_assignment(
            "user_secret_integrity",
            principal_id=_AZURE_RUNTIME_PRINCIPAL_ID,
            role_definition_id=("azurerm_role_definition.secret_integrity.role_definition_resource_id"),
            role_definition_name="Orders Secret Integrity",
            condition=("@Resource[Microsoft.KeyVault/vaults/secrets:Name] StringEqualsIgnoreCase 'orders'"),
        )
        inventory = _normalize(
            [
                _azure_vault(),
                _azure_secret(),
                _runtime_identity(),
                _azure_identity(
                    "reference_reader",
                    identity_id=_AZURE_REFERENCE_IDENTITY_ID,
                    principal_id=_AZURE_REFERENCE_PRINCIPAL_ID,
                ),
                _azure_web_app(),
                _azure_secret_admin_role(),
                _system_secret_assignment(scope=("azurerm_key_vault_secret.orders.resource_versionless_id")),
                conditioned,
                _azure_reference_reader_assignment(),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        secret = inventory.get_by_address("azurerm_key_vault_secret.orders")
        assert workload is not None
        assert secret is not None

        secret_facts = azure_facts(secret)
        system_grant = next(
            grant
            for grant in secret_facts.key_vault_secret_authorization_grants
            if grant["principal_id"] == _AZURE_SYSTEM_PRINCIPAL_ID
        )
        self.assertEqual(system_grant["authorization_state"], "granted")
        self.assertEqual(system_grant["grant_scope_type"], "secret")
        self.assertEqual(
            system_grant["grant_scope"],
            "azurerm_key_vault_secret.orders.resource_versionless_id",
        )
        self.assertEqual(
            system_grant["matched_operations"],
            ["set", "delete", "purge"],
        )
        self.assertEqual(
            system_grant["matched_data_actions"],
            [
                "Microsoft.KeyVault/vaults/secrets/setSecret/action",
                "Microsoft.KeyVault/vaults/secrets/delete",
                "Microsoft.KeyVault/vaults/secrets/purge/action",
            ],
        )

        facts = azure_facts(workload)
        paths = facts.app_service_key_vault_secret_management_paths
        self.assertEqual(
            {path["operation"] for path in paths},
            {"set", "delete", "delete_plus_purge"},
        )
        self.assertEqual(
            {path["identity_address"] for path in paths},
            {"azurerm_linux_web_app.orders"},
        )
        for path in paths:
            self.assertEqual(path["identity_kind"], "system_assigned")
            self.assertEqual(path["principal_id"], _AZURE_SYSTEM_PRINCIPAL_ID)
            self.assertEqual(path["credential_context"], "workload_runtime")
            self.assertEqual(path["target_type"], "secret")
            self.assertEqual(
                path["target_address"],
                "azurerm_key_vault_secret.orders",
            )
            self.assertEqual(path["target_resource_id"], _AZURE_SECRET_RESOURCE_ID)
            self.assertEqual(path["scope_types"], ["secret"])
            self.assertEqual(path["scope_arm_ids"], [_AZURE_SECRET_RESOURCE_ID])
            self.assertEqual(path["secret_uri"], _AZURE_SECRET_URI)
            self.assertEqual(
                path["secret_versionless_uri"],
                _AZURE_SECRET_VERSIONLESS_URI,
            )
            self.assertEqual(path["secret_version"], _AZURE_SECRET_VERSION)
            self.assertEqual(path["authorization_model"], "azure_rbac")
            self.assertEqual(path["authorization_state"], "granted")
            self.assertIsNone(path["condition"])
            self.assertEqual(path["condition_state"], "not_configured")
        sequence = next(path for path in paths if path["operation"] == "delete_plus_purge")
        self.assertEqual(sequence["step_operations"], ["delete", "purge"])
        self.assertEqual(
            sequence["operation_class"],
            "destructive_administration",
        )
        self.assertEqual(sequence["management_effect"], "disruption")
        self.assertTrue(
            any(
                "condition applicability is unsupported" in uncertainty
                for uncertainty in (facts.app_service_key_vault_secret_management_path_uncertainties)
            )
        )
        self.assertNotIn(
            _SECRET_PAYLOAD_SENTINEL,
            json.dumps(workload.metadata, sort_keys=True, default=str),
        )

    def test_legacy_policy_uses_attached_runtime_identity_not_reference_selection(
        self,
    ) -> None:
        inventory = _normalize(
            [
                _azure_vault(rbac_enabled=False),
                _azure_secret(),
                _runtime_identity(),
                _azure_identity(
                    "reference_reader",
                    identity_id=_AZURE_REFERENCE_IDENTITY_ID,
                    principal_id=_AZURE_REFERENCE_PRINCIPAL_ID,
                ),
                _azure_web_app(public=False),
                _azure_access_policy(),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None

        facts = azure_facts(workload)
        self.assertFalse(workload.public_access_configured)
        self.assertEqual(
            {path["operation"] for path in facts.app_service_key_vault_secret_management_paths},
            {"set", "delete", "delete_plus_purge"},
        )
        for path in facts.app_service_key_vault_secret_management_paths:
            self.assertEqual(
                path["identity_address"],
                "azurerm_user_assigned_identity.runtime",
            )
            self.assertEqual(path["identity_kind"], "user_assigned")
            self.assertEqual(path["principal_id"], _AZURE_RUNTIME_PRINCIPAL_ID)
            self.assertEqual(path["authorization_model"], "access_policy")
            self.assertEqual(path["scope_types"], ["vault"])
        self.assertNotIn(
            _AZURE_REFERENCE_PRINCIPAL_ID,
            {path["principal_id"] for path in facts.app_service_key_vault_secret_management_paths},
        )

    def test_delete_and_purge_do_not_combine_across_runtime_identities(
        self,
    ) -> None:
        inventory = _normalize(
            [
                _azure_vault(rbac_enabled=False),
                _azure_secret(),
                _runtime_identity(),
                _azure_web_app(),
                _access_policy(
                    "system_delete",
                    principal_id=_AZURE_SYSTEM_PRINCIPAL_ID,
                    secret_permissions=("Delete",),
                ),
                _access_policy(
                    "user_purge",
                    principal_id=_AZURE_RUNTIME_PRINCIPAL_ID,
                    secret_permissions=("Purge",),
                ),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None

        paths = azure_facts(workload).app_service_key_vault_secret_management_paths
        self.assertEqual([path["operation"] for path in paths], ["delete"])
        self.assertEqual(paths[0]["principal_id"], _AZURE_SYSTEM_PRINCIPAL_ID)

    def test_purge_protection_controls_only_permanent_delete_sequence(
        self,
    ) -> None:
        protected = _normalize(
            [
                _azure_vault(purge_protection_enabled=True),
                _azure_secret(),
                _azure_web_app(),
                _azure_secret_admin_role(),
                _system_secret_assignment(),
            ]
        )
        unknown = _normalize(
            [
                _azure_vault(purge_protection_enabled=None),
                _azure_secret(),
                _azure_web_app(),
                _azure_secret_admin_role(),
                _system_secret_assignment(),
            ]
        )
        protected_workload = protected.get_by_address("azurerm_linux_web_app.orders")
        unknown_workload = unknown.get_by_address("azurerm_linux_web_app.orders")
        assert protected_workload is not None
        assert unknown_workload is not None

        protected_facts = azure_facts(protected_workload)
        unknown_facts = azure_facts(unknown_workload)
        self.assertEqual(
            {path["operation"] for path in protected_facts.app_service_key_vault_secret_management_paths},
            {"set", "delete"},
        )
        self.assertTrue(
            all(
                path["purge_protection_enabled"] is True
                for path in (protected_facts.app_service_key_vault_secret_management_paths)
            )
        )
        self.assertEqual(
            {path["operation"] for path in unknown_facts.app_service_key_vault_secret_management_paths},
            {"set", "delete"},
        )
        self.assertTrue(
            any(
                "delete-plus-purge compatibility" in uncertainty
                for uncertainty in (unknown_facts.app_service_key_vault_secret_management_path_uncertainties)
            )
        )

    def test_active_authorization_model_filters_inactive_grants(self) -> None:
        rbac = _normalize(
            [
                _azure_vault(rbac_enabled=True),
                _azure_secret(),
                _runtime_identity(),
                _azure_web_app(),
                _azure_access_policy(),
            ]
        )
        legacy = _normalize(
            [
                _azure_vault(rbac_enabled=False),
                _azure_secret(),
                _azure_web_app(),
                _azure_secret_admin_role(),
                _system_secret_assignment(),
            ]
        )
        rbac_workload = rbac.get_by_address("azurerm_linux_web_app.orders")
        legacy_workload = legacy.get_by_address("azurerm_linux_web_app.orders")
        assert rbac_workload is not None
        assert legacy_workload is not None

        self.assertEqual(
            azure_facts(rbac_workload).app_service_key_vault_secret_management_paths,
            [],
        )
        self.assertEqual(
            azure_facts(legacy_workload).app_service_key_vault_secret_management_paths,
            [],
        )

    def test_conditions_not_data_actions_and_unknown_roles_fail_closed(
        self,
    ) -> None:
        conditioned = _normalize(
            [
                _azure_vault(),
                _azure_secret(),
                _azure_web_app(),
                _azure_secret_admin_role(),
                _system_secret_assignment(
                    condition=("@Resource[Microsoft.KeyVault/vaults/secrets:Name] StringEqualsIgnoreCase 'orders'")
                ),
            ]
        )

        excluded_role = _azure_secret_admin_role()
        excluded_role.values["permissions"][0]["not_data_actions"] = [
            "Microsoft.KeyVault/vaults/secrets/delete",
            "Microsoft.KeyVault/vaults/secrets/purge/action",
        ]
        excluded = _normalize(
            [
                _azure_vault(),
                _azure_secret(),
                _azure_web_app(),
                excluded_role,
                _system_secret_assignment(),
            ]
        )

        unknown_role = _normalize(
            [
                _azure_vault(),
                _azure_secret(),
                _azure_web_app(),
                _azure_secret_admin_role(permissions_unknown=True),
                _system_secret_assignment(),
            ]
        )
        conditioned_workload = conditioned.get_by_address("azurerm_linux_web_app.orders")
        excluded_workload = excluded.get_by_address("azurerm_linux_web_app.orders")
        unknown_workload = unknown_role.get_by_address("azurerm_linux_web_app.orders")
        assert conditioned_workload is not None
        assert excluded_workload is not None
        assert unknown_workload is not None

        conditioned_facts = azure_facts(conditioned_workload)
        excluded_facts = azure_facts(excluded_workload)
        unknown_facts = azure_facts(unknown_workload)
        self.assertEqual(
            conditioned_facts.app_service_key_vault_secret_management_paths,
            [],
        )
        self.assertTrue(conditioned_facts.app_service_key_vault_secret_management_path_uncertainties)
        self.assertEqual(
            [path["operation"] for path in excluded_facts.app_service_key_vault_secret_management_paths],
            ["set"],
        )
        self.assertEqual(
            unknown_facts.app_service_key_vault_secret_management_paths,
            [],
        )
        self.assertTrue(unknown_facts.app_service_key_vault_secret_management_path_uncertainties)

    def test_secret_scope_requires_versionless_resource_identity(self) -> None:
        cases = (
            (
                "symbolic_versionless",
                "azurerm_key_vault_secret.orders.resource_versionless_id",
                True,
            ),
            ("symbolic_versioned", "azurerm_key_vault_secret.orders.resource_id", False),
            ("literal_versionless", _AZURE_SECRET_RESOURCE_ID, True),
            (
                "literal_versioned",
                f"{_AZURE_SECRET_RESOURCE_ID}/{_AZURE_SECRET_VERSION}",
                False,
            ),
        )

        for name, scope, expected in cases:
            with self.subTest(name=name):
                assignment = _azure_role_assignment(
                    f"{name}_secret_scope",
                    principal_id=_AZURE_SYSTEM_PRINCIPAL_ID,
                    role_definition_id=_SECRETS_OFFICER_ID,
                    role_definition_name="Key Vault Secrets Officer",
                )
                assignment.values["scope"] = scope
                inventory = _normalize(
                    [
                        _azure_vault(),
                        _azure_secret(),
                        _azure_web_app(),
                        assignment,
                    ]
                )
                workload = inventory.get_by_address("azurerm_linux_web_app.orders")
                assert workload is not None
                facts = azure_facts(workload)

                if expected:
                    self.assertEqual(
                        {path["operation"] for path in facts.app_service_key_vault_secret_management_paths},
                        {"set", "delete", "delete_plus_purge"},
                    )
                else:
                    self.assertEqual(
                        facts.app_service_key_vault_secret_management_paths,
                        [],
                    )
                    self.assertTrue(facts.app_service_key_vault_secret_management_path_uncertainties)

    def test_symbolic_addresses_never_enter_arm_identity_fields(self) -> None:
        derivable_vault = _azure_vault()
        derivable_vault.values["id"] = "azurerm_key_vault.orders.id"
        resolved = _normalize(
            [
                derivable_vault,
                _azure_secret(),
                _azure_web_app(),
                _azure_secret_admin_role(),
                _system_secret_assignment(),
            ]
        )
        resolved_workload = resolved.get_by_address("azurerm_linux_web_app.orders")
        assert resolved_workload is not None
        paths = azure_facts(resolved_workload).app_service_key_vault_secret_management_paths
        self.assertTrue(paths)
        self.assertEqual(
            {path["key_vault_id"] for path in paths},
            {_AZURE_SECRET_RESOURCE_ID.rsplit("/secrets/", 1)[0]},
        )
        self.assertNotIn(
            "azurerm_key_vault.orders.id",
            {path["key_vault_id"] for path in paths},
        )

        unresolved_secret = _azure_secret()
        unresolved_secret.values["resource_versionless_id"] = "azurerm_key_vault_secret.orders.resource_versionless_id"
        unresolved = _normalize(
            [
                _azure_vault(),
                unresolved_secret,
                _azure_web_app(),
                _azure_secret_admin_role(),
                _system_secret_assignment(),
            ]
        )
        unresolved_workload = unresolved.get_by_address("azurerm_linux_web_app.orders")
        assert unresolved_workload is not None
        unresolved_facts = azure_facts(unresolved_workload)
        self.assertEqual(
            unresolved_facts.app_service_key_vault_secret_management_paths,
            [],
        )
        self.assertTrue(unresolved_facts.app_service_key_vault_secret_management_path_uncertainties)

    def test_secret_stages_follow_identity_and_authorization_inputs(self) -> None:
        names = [stage.name for stage in default_azure_decoration_stages()]
        authorization = names.index("normalize_key_vault_secret_authorization_posture")
        paths = names.index("model_app_service_key_vault_secret_management_paths")
        for stage_name in (
            "resolve_azure_symbolic_relationships",
            "decorate_key_vault_relationships",
            "decorate_managed_identity_role_assignments",
        ):
            with self.subTest(stage_name=stage_name):
                self.assertLess(names.index(stage_name), authorization)
        self.assertLess(authorization, paths)


if __name__ == "__main__":
    unittest.main()

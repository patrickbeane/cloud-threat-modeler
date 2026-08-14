from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _ACCOUNT_ID,
    _CUSTOM_ROLE_ID,
    _ITEM_CREATE,
    _ITEM_DELETE,
    _ITEM_WILDCARD,
    _SYSTEM_PRINCIPAL_ID,
    _USER_PRINCIPAL_ID,
    _account,
    _container,
    _custom_role,
    _database,
    _function_app,
    _native_assignment,
    _user_assigned_identity,
    _web_app,
)
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_decoration_stages import (
    default_azure_decoration_stages,
)
from tfstride.providers.azure.resource_facts import azure_facts


def _backup_account(
    *,
    backup_type: str | None = None,
    backup_tier: str | None = None,
    interval_minutes: int | None = None,
    retention_hours: int | None = None,
    storage_redundancy: str | None = None,
    unknown_backup: bool = False,
) -> TerraformResource:
    account = _account()
    if backup_type is not None:
        backup: dict[str, object] = {"type": backup_type}
        if backup_tier is not None:
            backup["tier"] = backup_tier
        if interval_minutes is not None:
            backup["interval_in_minutes"] = interval_minutes
        if retention_hours is not None:
            backup["retention_in_hours"] = retention_hours
        if storage_redundancy is not None:
            backup["storage_redundancy"] = storage_redundancy
        account.values["backup"] = [backup]
    if unknown_backup:
        account.unknown_values["backup"] = True
    return account


def _workload(
    resources: list[TerraformResource],
    *,
    address: str = "azurerm_linux_web_app.orders",
):
    inventory = AzureNormalizer().normalize(resources)
    workload = inventory.get_by_address(address)
    assert workload is not None
    return azure_facts(workload)


class AzureAppServiceCosmosDbItemDeletionPathTests(unittest.TestCase):
    def test_account_database_and_container_scopes_preserve_exact_ancestry(
        self,
    ) -> None:
        cases = (
            (
                "account",
                [_account(), _web_app(), _native_assignment()],
                "azurerm_cosmosdb_account.orders",
                "account_item_namespace",
                ["azurerm_cosmosdb_account.orders"],
            ),
            (
                "database",
                [
                    _account(),
                    _database(),
                    _web_app(),
                    _custom_role(
                        data_actions=[_ITEM_DELETE],
                        assignable_scopes=[f"{_ACCOUNT_ID}/dbs/app"],
                    ),
                    _native_assignment(
                        role_definition_id=_CUSTOM_ROLE_ID,
                        scope="/dbs/app",
                    ),
                ],
                "azurerm_cosmosdb_sql_database.app",
                "database_item_namespace",
                [
                    "azurerm_cosmosdb_account.orders",
                    "azurerm_cosmosdb_sql_database.app",
                ],
            ),
            (
                "container",
                [
                    _account(),
                    _database(),
                    _container(),
                    _web_app(),
                    _custom_role(
                        data_actions=[_ITEM_DELETE],
                        assignable_scopes=[f"{_ACCOUNT_ID}/dbs/app/colls/events"],
                    ),
                    _native_assignment(
                        role_definition_id=_CUSTOM_ROLE_ID,
                        scope="/dbs/app/colls/events",
                    ),
                ],
                "azurerm_cosmosdb_sql_container.events",
                "container_item_namespace",
                [
                    "azurerm_cosmosdb_account.orders",
                    "azurerm_cosmosdb_sql_database.app",
                    "azurerm_cosmosdb_sql_container.events",
                ],
            ),
        )

        for scope_type, resources, target_address, granularity, ancestry in cases:
            with self.subTest(scope_type=scope_type):
                facts = _workload(resources)
                self.assertEqual(
                    len(facts.app_service_cosmosdb_item_deletion_paths),
                    1,
                )
                path = facts.app_service_cosmosdb_item_deletion_paths[0]
                self.assertEqual(path["operation"], _ITEM_DELETE)
                self.assertEqual(path["matched_data_actions"], [_ITEM_DELETE])
                self.assertEqual(path["operation_class"], "item_deletion")
                self.assertEqual(path["management_effect"], "disruption")
                self.assertEqual(path["scope_type"], scope_type)
                self.assertEqual(path["target_granularity"], granularity)
                self.assertEqual(
                    path["cosmosdb_resource_address"],
                    target_address,
                )
                self.assertEqual(
                    path["target_model_evidence_addresses"],
                    ancestry,
                )
                self.assertNotIn("item_id", path)

    def test_user_assigned_runtime_identity_and_custom_role_lineage_are_retained(
        self,
    ) -> None:
        facts = _workload(
            [
                _account(),
                _database(),
                _container(),
                _user_assigned_identity(),
                _function_app(),
                _custom_role(
                    data_actions=[_ITEM_CREATE, _ITEM_DELETE],
                    assignable_scopes=[f"{_ACCOUNT_ID}/dbs/app/colls/events"],
                ),
                _native_assignment(
                    principal_id=_USER_PRINCIPAL_ID,
                    role_definition_id=_CUSTOM_ROLE_ID,
                    scope="/dbs/app/colls/events",
                ),
            ],
            address="azurerm_linux_function_app.orders_worker",
        )

        path = facts.app_service_cosmosdb_item_deletion_paths[0]
        self.assertEqual(path["identity_kind"], "user_assigned")
        self.assertEqual(
            path["identity_address"],
            "azurerm_user_assigned_identity.orders_runtime",
        )
        self.assertEqual(path["principal_id"], _USER_PRINCIPAL_ID)
        self.assertEqual(path["role_kind"], "custom")
        self.assertEqual(
            path["authorization_source_addresses"],
            [
                "azurerm_cosmosdb_sql_role_assignment.workload",
                "azurerm_cosmosdb_sql_role_definition.workload",
            ],
        )
        self.assertEqual(path["matched_data_actions"], [_ITEM_DELETE])
        self.assertEqual(
            path["role_data_actions"],
            [_ITEM_CREATE, _ITEM_DELETE],
        )

    def test_item_wildcard_grants_delete_but_other_actions_stay_quiet(self) -> None:
        wildcard = _workload(
            [
                _account(),
                _web_app(),
                _custom_role(data_actions=[_ITEM_WILDCARD]),
                _native_assignment(role_definition_id=_CUSTOM_ROLE_ID),
            ]
        )
        create_only = _workload(
            [
                _account(),
                _web_app(),
                _custom_role(data_actions=[_ITEM_CREATE]),
                _native_assignment(role_definition_id=_CUSTOM_ROLE_ID),
            ]
        )

        self.assertEqual(
            wildcard.app_service_cosmosdb_item_deletion_paths[0]["matched_data_actions"],
            [_ITEM_DELETE],
        )
        self.assertEqual(
            create_only.app_service_cosmosdb_item_deletion_paths,
            [],
        )
        self.assertEqual(
            create_only.app_service_cosmosdb_item_deletion_path_uncertainties,
            [],
        )

    def test_backup_recovery_evidence_preserves_native_posture(self) -> None:
        cases = (
            (
                "continuous",
                _backup_account(
                    backup_type="Continuous",
                    backup_tier="Continuous30Days",
                ),
                ("continuous", "configured", "Continuous30Days", None, None),
            ),
            (
                "periodic",
                _backup_account(
                    backup_type="Periodic",
                    interval_minutes=240,
                    retention_hours=168,
                    storage_redundancy="Geo",
                ),
                ("periodic", "configured", None, 240, 168),
            ),
            (
                "provider-default",
                _backup_account(),
                (
                    "provider_default_periodic",
                    "not_configured",
                    None,
                    240,
                    8,
                ),
            ),
            (
                "unknown",
                _backup_account(unknown_backup=True),
                ("unknown", "unknown", None, None, None),
            ),
        )

        for case, account, expected in cases:
            with self.subTest(case=case):
                facts = _workload(
                    [
                        account,
                        _web_app(),
                        _native_assignment(),
                    ]
                )
                recovery = facts.app_service_cosmosdb_item_deletion_paths[0]["recovery_evidence"]
                self.assertEqual(
                    (
                        recovery["backup_posture_state"],
                        recovery["backup_configuration_state"],
                        recovery["backup_tier"],
                        recovery["backup_interval_minutes"],
                        recovery["backup_retention_hours"],
                    ),
                    expected,
                )
                if case == "unknown":
                    self.assertTrue(recovery["uncertainties"])
                    self.assertEqual(
                        facts.app_service_cosmosdb_item_deletion_paths[0]["posture_uncertainties"],
                        recovery["uncertainties"],
                    )

    def test_unresolved_authorization_remains_uncertain_without_a_path(self) -> None:
        facts = _workload(
            [
                _account(),
                _web_app(),
                _custom_role(
                    data_actions=[_ITEM_DELETE],
                    unknown_permissions=True,
                ),
                _native_assignment(role_definition_id=_CUSTOM_ROLE_ID),
            ]
        )

        self.assertEqual(facts.app_service_cosmosdb_item_deletion_paths, [])
        self.assertTrue(
            any(
                "permissions are unresolved" in uncertainty
                for uncertainty in facts.app_service_cosmosdb_item_deletion_path_uncertainties
            )
        )

    def test_private_workload_retains_item_deletion_path(self) -> None:
        workload = _web_app()
        workload.values["public_network_access_enabled"] = False
        facts = _workload([_account(), workload, _native_assignment()])

        self.assertEqual(
            len(facts.app_service_cosmosdb_item_deletion_paths),
            1,
        )
        self.assertEqual(
            facts.app_service_cosmosdb_item_deletion_paths[0]["principal_id"],
            _SYSTEM_PRINCIPAL_ID,
        )

    def test_deletion_stage_follows_cosmosdb_relationships_and_access_paths(
        self,
    ) -> None:
        names = [stage.name for stage in default_azure_decoration_stages()]
        deletion = names.index("model_app_service_cosmosdb_item_deletion_paths")
        for stage_name in (
            "decorate_cosmosdb_nosql_relationships",
            "decorate_managed_identity_role_assignments",
            "model_app_service_cosmosdb_access_paths",
        ):
            with self.subTest(stage_name=stage_name):
                self.assertLess(names.index(stage_name), deletion)


if __name__ == "__main__":
    unittest.main()

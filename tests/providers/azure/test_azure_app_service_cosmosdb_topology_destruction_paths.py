from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _SYSTEM_PRINCIPAL_ID as SYSTEM_PRINCIPAL_ID,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _USER_PRINCIPAL_ID as USER_PRINCIPAL_ID,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _function_app,
    _user_assigned_identity,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _resource,
)
from tests.providers.test_public_workload_structured_data_deletion_boundaries import (
    _azure_account,
)
from tests.providers.test_public_workload_structured_data_topology_destruction_boundaries import (
    _AZURE_DELETE_ACCOUNT,
    _AZURE_DELETE_CONTAINER,
    _AZURE_DELETE_DATABASE,
    _azure_control_assignment,
    _azure_control_role,
    _azure_inventory_and_context,
    _azure_management_lock,
    _azure_workload,
    azure_container,
    azure_database,
)
from tfstride.models import TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_decoration.app_service_cosmosdb_topology_destruction_paths import (
    current_app_service_cosmosdb_topology_destruction_paths,
)
from tfstride.providers.azure.resource_decoration_stages import (
    default_azure_decoration_stages,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import (
    AzureDecorationContext,
    AzureResourceIndexBuilder,
)
from tfstride.providers.azure.resource_types import AzureResourceType

_ACCOUNT_ID = "/subscriptions/sub-0001/resourceGroups/data/providers/Microsoft.DocumentDB/databaseAccounts/orders"
_DATABASE_ID = f"{_ACCOUNT_ID}/sqlDatabases/app"
_CONTAINER_ID = f"{_DATABASE_ID}/containers/events"
_COSMOS_OPERATOR_ID = "230815da-be43-4aae-9cb4-875f7bd000aa"
_DOCUMENTDB_CONTRIBUTOR_ID = "5bd9cd88-fe45-4216-938b-f97437e15450"
_READER_ID = "fbdf93bf-df7d-467e-a4d2-9458aa1360c8"


def _built_in_assignment(
    *,
    role_name: str | None,
    role_id: str | None,
    scope: str = _ACCOUNT_ID,
    principal_id: str = SYSTEM_PRINCIPAL_ID,
    name: str = "cosmos_builtin",
) -> TerraformResource:
    values: dict[str, object] = {
        "scope": scope,
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if role_name is not None:
        values["role_definition_name"] = role_name
    if role_id is not None:
        values["role_definition_id"] = (
            f"/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/{role_id}"
        )
    return _resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        values,
        name=name,
    )


def _workload_facts(resources: list[TerraformResource]):
    inventory = AzureNormalizer().normalize(resources)
    workload = inventory.get_by_address("azurerm_linux_web_app.orders")
    assert workload is not None
    return azure_facts(workload)


class AzureAppServiceCosmosDbTopologyDestructionPathTests(unittest.TestCase):
    def test_account_scope_fans_out_to_exact_modeled_cosmos_hierarchy(self) -> None:
        facts = _workload_facts(
            [
                _azure_account(),
                azure_database(),
                azure_container(),
                _azure_workload(),
                _azure_control_role(
                    actions=[
                        _AZURE_DELETE_ACCOUNT,
                        _AZURE_DELETE_DATABASE,
                        _AZURE_DELETE_CONTAINER,
                    ]
                ),
                _azure_control_assignment(),
            ]
        )

        paths = facts.app_service_cosmosdb_topology_destruction_paths
        self.assertEqual(len(paths), 3)
        by_kind = {path["cosmosdb_resource_kind"]: path for path in paths}
        self.assertEqual(
            set(by_kind),
            {"account", "database", "container"},
        )
        self.assertEqual(
            by_kind["account"]["target_model_evidence_addresses"],
            ["azurerm_cosmosdb_account.orders"],
        )
        self.assertEqual(
            by_kind["database"]["target_model_evidence_addresses"],
            [
                "azurerm_cosmosdb_account.orders",
                "azurerm_cosmosdb_sql_database.app",
            ],
        )
        self.assertEqual(
            by_kind["container"]["target_model_evidence_addresses"],
            [
                "azurerm_cosmosdb_account.orders",
                "azurerm_cosmosdb_sql_database.app",
                "azurerm_cosmosdb_sql_container.events",
            ],
        )
        self.assertEqual(
            by_kind["account"]["authorization_grant"]["matched_actions"],
            [_AZURE_DELETE_ACCOUNT],
        )
        self.assertEqual(
            by_kind["database"]["authorization_grant"]["matched_actions"],
            [_AZURE_DELETE_DATABASE],
        )
        self.assertEqual(
            by_kind["container"]["authorization_grant"]["matched_actions"],
            [_AZURE_DELETE_CONTAINER],
        )
        for path in paths:
            with self.subTest(kind=path["cosmosdb_resource_kind"]):
                self.assertEqual(path["principal_id"], SYSTEM_PRINCIPAL_ID)
                self.assertEqual(path["credential_context"], "workload_runtime")
                self.assertEqual(
                    path["authorization_grant"]["cosmosdb_native_data_actions_authorization_effect"],
                    "not_used_for_arm_topology_deletion",
                )
                self.assertFalse(path["descendant_impact_evaluated"])
                self.assertFalse(path["out_of_plan_topology_evaluated"])
                self.assertFalse(path["recovery_evidence"]["successful_deletion_observed"])
                self.assertFalse(path["recovery_evidence"]["restoration_observed"])

    def test_exact_resource_scopes_fan_out_only_to_descendants(self) -> None:
        database_facts = _workload_facts(
            [
                _azure_account(),
                azure_database(),
                azure_container(),
                _azure_workload(),
                _azure_control_role(
                    actions=[
                        _AZURE_DELETE_ACCOUNT,
                        _AZURE_DELETE_DATABASE,
                        _AZURE_DELETE_CONTAINER,
                    ]
                ),
                _azure_control_assignment(scope=_DATABASE_ID),
            ]
        )
        self.assertEqual(
            {path["cosmosdb_resource_kind"] for path in database_facts.app_service_cosmosdb_topology_destruction_paths},
            {"database", "container"},
        )

        container_facts = _workload_facts(
            [
                _azure_account(),
                azure_database(),
                azure_container(),
                _azure_workload(),
                _azure_control_role(
                    actions=[
                        _AZURE_DELETE_ACCOUNT,
                        _AZURE_DELETE_DATABASE,
                        _AZURE_DELETE_CONTAINER,
                    ]
                ),
                _azure_control_assignment(
                    scope="azurerm_cosmosdb_sql_container.events.id",
                ),
            ]
        )
        paths = container_facts.app_service_cosmosdb_topology_destruction_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["cosmosdb_resource_kind"], "container")
        self.assertEqual(paths[0]["cosmosdb_resource_id"], _CONTAINER_ID)

    def test_control_plane_actions_never_use_cosmos_native_data_actions(self) -> None:
        data_only = _workload_facts(
            [
                _azure_account(),
                azure_database(),
                azure_container(),
                _azure_workload(),
                _azure_control_role(
                    actions=[],
                    data_actions=[_AZURE_DELETE_CONTAINER],
                ),
                _azure_control_assignment(
                    scope="azurerm_cosmosdb_sql_container.events.id",
                ),
            ]
        )
        self.assertEqual(
            data_only.app_service_cosmosdb_topology_destruction_paths,
            [],
        )

        excluded = _workload_facts(
            [
                _azure_account(),
                azure_database(),
                azure_container(),
                _azure_workload(),
                _azure_control_role(
                    actions=["Microsoft.DocumentDB/databaseAccounts/*"],
                    not_actions=[_AZURE_DELETE_CONTAINER],
                ),
                _azure_control_assignment(
                    scope="azurerm_cosmosdb_sql_container.events.id",
                ),
            ]
        )
        self.assertEqual(
            excluded.app_service_cosmosdb_topology_destruction_paths,
            [],
        )

    def test_cosmos_management_built_in_roles_resolve_by_name_and_id(self) -> None:
        cases = (
            (
                "operator-name",
                "Cosmos DB Operator",
                None,
            ),
            (
                "operator-id",
                None,
                _COSMOS_OPERATOR_ID,
            ),
            (
                "contributor-name",
                "DocumentDB Account Contributor",
                None,
            ),
            (
                "contributor-id",
                None,
                _DOCUMENTDB_CONTRIBUTOR_ID,
            ),
        )
        for case, role_name, role_id in cases:
            with self.subTest(case=case):
                facts = _workload_facts(
                    [
                        _azure_account(),
                        azure_database(),
                        azure_container(),
                        _azure_workload(),
                        _built_in_assignment(
                            role_name=role_name,
                            role_id=role_id,
                        ),
                    ]
                )
                paths = facts.app_service_cosmosdb_topology_destruction_paths
                self.assertEqual(len(paths), 3)
                self.assertTrue(
                    all(path["authorization_grant"]["role_evidence"]["role_kind"] == "built_in" for path in paths)
                )

        reader = _workload_facts(
            [
                _azure_account(),
                azure_database(),
                azure_container(),
                _azure_workload(),
                _built_in_assignment(
                    role_name="Cosmos DB Account Reader Role",
                    role_id=_READER_ID,
                ),
            ]
        )
        self.assertEqual(
            reader.app_service_cosmosdb_topology_destruction_paths,
            [],
        )

    def test_conditional_unresolved_and_incompatible_authority_fails_closed(
        self,
    ) -> None:
        cases = (
            (
                "condition",
                _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
                _azure_control_assignment(
                    scope="azurerm_cosmosdb_sql_container.events.id",
                    condition=(
                        "@Resource[Microsoft.DocumentDB/databaseAccounts/"
                        "sqlDatabases/containers:Name] StringEquals events"
                    ),
                ),
            ),
            (
                "unknown-condition-version",
                _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
                _azure_control_assignment(
                    scope="azurerm_cosmosdb_sql_container.events.id",
                    unknown_values={"condition_version": True},
                ),
            ),
            (
                "outside-assignable-scope",
                _azure_control_role(
                    actions=[_AZURE_DELETE_CONTAINER],
                    assignable_scopes=["/subscriptions/other-subscription"],
                ),
                _azure_control_assignment(
                    scope="azurerm_cosmosdb_sql_container.events.id",
                ),
            ),
        )
        for case, role, assignment in cases:
            with self.subTest(case=case):
                facts = _workload_facts(
                    [
                        _azure_account(),
                        azure_database(),
                        azure_container(),
                        _azure_workload(),
                        role,
                        assignment,
                    ]
                )
                self.assertEqual(
                    facts.app_service_cosmosdb_topology_destruction_paths,
                    [],
                )
                self.assertTrue(facts.app_service_cosmosdb_topology_destruction_path_uncertainties)

    def test_incoherent_container_ancestry_is_not_promoted(self) -> None:
        container = azure_container()
        container.values["id"] = f"{_DATABASE_ID}/containers/other"

        facts = _workload_facts(
            [
                _azure_account(),
                azure_database(),
                container,
                _azure_workload(),
                _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
                _azure_control_assignment(scope=_CONTAINER_ID),
            ]
        )

        self.assertEqual(
            facts.app_service_cosmosdb_topology_destruction_paths,
            [],
        )
        self.assertTrue(facts.app_service_cosmosdb_topology_destruction_path_uncertainties)

    def test_system_and_attached_user_assigned_identities_remain_distinct(self) -> None:
        function = _function_app()
        function.values["public_network_access_enabled"] = False
        inventory = AzureNormalizer().normalize(
            [
                _azure_account(),
                _user_assigned_identity(),
                function,
                _azure_control_role(actions=[_AZURE_DELETE_ACCOUNT]),
                _azure_control_assignment(
                    principal_id=USER_PRINCIPAL_ID,
                    name="user_cosmos_topology",
                ),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_function_app.orders_worker")
        assert workload is not None
        paths = azure_facts(workload).app_service_cosmosdb_topology_destruction_paths

        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["identity_kind"], "user_assigned")
        self.assertEqual(
            paths[0]["identity_address"],
            "azurerm_user_assigned_identity.orders_runtime",
        )
        self.assertEqual(paths[0]["principal_id"], USER_PRINCIPAL_ID)

    def test_inherited_management_locks_gate_only_applicable_targets(self) -> None:
        base = [
            _azure_account(),
            azure_database(),
            azure_container(),
            _azure_workload(),
            _azure_control_role(
                actions=[
                    _AZURE_DELETE_ACCOUNT,
                    _AZURE_DELETE_DATABASE,
                    _AZURE_DELETE_CONTAINER,
                ]
            ),
            _azure_control_assignment(),
        ]

        account_lock = _workload_facts(
            [
                *base,
                _azure_management_lock(scope=_ACCOUNT_ID),
            ]
        )
        self.assertEqual(
            account_lock.app_service_cosmosdb_topology_destruction_paths,
            [],
        )

        database_lock = _workload_facts(
            [
                *base,
                _azure_management_lock(scope=_DATABASE_ID),
            ]
        )
        self.assertEqual(
            {path["cosmosdb_resource_kind"] for path in database_lock.app_service_cosmosdb_topology_destruction_paths},
            {"account"},
        )

        container_lock = _workload_facts(
            [
                *base,
                _azure_management_lock(scope=_CONTAINER_ID),
            ]
        )
        self.assertEqual(
            {path["cosmosdb_resource_kind"] for path in container_lock.app_service_cosmosdb_topology_destruction_paths},
            {"account", "database"},
        )

        unrelated_lock = _workload_facts(
            [
                *base,
                _azure_management_lock(
                    scope=(
                        "/subscriptions/sub-0001/resourceGroups/other/providers/"
                        "Microsoft.DocumentDB/databaseAccounts/archive"
                    )
                ),
            ]
        )
        self.assertEqual(
            len(unrelated_lock.app_service_cosmosdb_topology_destruction_paths),
            3,
        )

    def test_unknown_management_lock_fails_closed_with_uncertainty(self) -> None:
        facts = _workload_facts(
            [
                _azure_account(),
                azure_database(),
                azure_container(),
                _azure_workload(),
                _azure_control_role(
                    actions=[
                        _AZURE_DELETE_ACCOUNT,
                        _AZURE_DELETE_DATABASE,
                        _AZURE_DELETE_CONTAINER,
                    ]
                ),
                _azure_control_assignment(),
                _azure_management_lock(
                    scope=_ACCOUNT_ID,
                    unknown_scope=True,
                    unknown_level=True,
                ),
            ]
        )

        self.assertEqual(
            facts.app_service_cosmosdb_topology_destruction_paths,
            [],
        )
        self.assertTrue(facts.app_service_cosmosdb_topology_destruction_path_uncertainties)

    def test_backup_posture_qualifies_but_does_not_suppress_authority(self) -> None:
        unknown_account = _azure_account(unknown_backup=True)
        facts = _workload_facts(
            [
                unknown_account,
                _azure_workload(),
                _azure_control_role(actions=[_AZURE_DELETE_ACCOUNT]),
                _azure_control_assignment(),
            ]
        )

        paths = facts.app_service_cosmosdb_topology_destruction_paths
        self.assertEqual(len(paths), 1)
        recovery = paths[0]["recovery_evidence"]
        self.assertEqual(recovery["backup_posture_state"], "unknown")
        self.assertEqual(recovery["topology_recovery_state"], "unknown")
        self.assertFalse(recovery["immediate_restoration_established"])
        self.assertTrue(paths[0]["posture_uncertainties"])

        default = _workload_facts(
            [
                _azure_account(),
                _azure_workload(),
                _azure_control_role(actions=[_AZURE_DELETE_ACCOUNT]),
                _azure_control_assignment(),
            ]
        )
        default_recovery = default.app_service_cosmosdb_topology_destruction_paths[0]["recovery_evidence"]
        self.assertEqual(
            default_recovery["backup_posture_state"],
            "provider_default_periodic",
        )
        self.assertEqual(default_recovery["backup_interval_minutes"], 240)
        self.assertEqual(default_recovery["backup_retention_hours"], 8)

    def test_current_helper_revalidates_authority_and_management_locks(self) -> None:
        inventory, context = _azure_inventory_and_context(
            [
                _azure_account(),
                azure_database(),
                azure_container(),
                _azure_workload(),
                _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
                _azure_control_assignment(
                    scope="azurerm_cosmosdb_sql_container.events.id",
                ),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        container = inventory.get_by_address("azurerm_cosmosdb_sql_container.events")
        role = inventory.get_by_address("azurerm_role_definition.cosmos_topology")
        assert workload is not None
        assert container is not None
        assert role is not None

        resources = list(inventory.resources)
        current = current_app_service_cosmosdb_topology_destruction_paths(
            workload,
            container,
            resources,
            context,
        )
        self.assertEqual(len(current), 1)

        role.set_metadata_field(
            AzureResourceMetadata.ROLE_DEFINITION_ACTIONS,
            [],
        )
        self.assertEqual(
            current_app_service_cosmosdb_topology_destruction_paths(
                workload,
                container,
                resources,
                context,
            ),
            [],
        )

        role.set_metadata_field(
            AzureResourceMetadata.ROLE_DEFINITION_ACTIONS,
            [_AZURE_DELETE_CONTAINER],
        )
        lock_inventory = AzureNormalizer().normalize([_azure_management_lock(scope=_CONTAINER_ID)])
        resources_with_lock = [*resources, *lock_inventory.resources]
        lock_context = AzureDecorationContext(index=AzureResourceIndexBuilder().build(resources_with_lock))
        self.assertEqual(
            current_app_service_cosmosdb_topology_destruction_paths(
                workload,
                container,
                resources_with_lock,
                lock_context,
            ),
            [],
        )

    def test_stage_runs_after_cosmos_relationships_and_identity_decoration(
        self,
    ) -> None:
        names = [stage.name for stage in default_azure_decoration_stages()]
        topology = names.index("model_app_service_cosmosdb_topology_destruction_paths")

        self.assertGreater(
            topology,
            names.index("decorate_cosmosdb_nosql_relationships"),
        )
        self.assertGreater(
            topology,
            names.index("decorate_managed_identity_role_assignments"),
        )
        self.assertGreater(
            topology,
            names.index("model_app_service_cosmosdb_item_deletion_paths"),
        )


if __name__ == "__main__":
    unittest.main()

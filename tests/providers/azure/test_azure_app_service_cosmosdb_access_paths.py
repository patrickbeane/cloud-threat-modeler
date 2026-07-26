from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_ACCOUNT_ID = "/subscriptions/sub-0001/resourceGroups/data/providers/Microsoft.DocumentDB/databaseAccounts/orders"
_DATABASE_ID = f"{_ACCOUNT_ID}/sqlDatabases/app"
_CONTAINER_ID = f"{_DATABASE_ID}/containers/events"
_READER_ROLE_ID = f"{_ACCOUNT_ID}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000001"
_CONTRIBUTOR_ROLE_ID = f"{_ACCOUNT_ID}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
_CUSTOM_ROLE_GUID = "11111111-2222-3333-4444-555555555555"
_CUSTOM_ROLE_ID = f"{_ACCOUNT_ID}/sqlRoleDefinitions/{_CUSTOM_ROLE_GUID}"
_SYSTEM_PRINCIPAL_ID = "app-system-principal-id"
_USER_PRINCIPAL_ID = "app-user-principal-id"
_USER_IDENTITY_ID = (
    "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ManagedIdentity/"
    "userAssignedIdentities/orders-runtime"
)
_CONTAINER_WILDCARD = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/*"
_ITEM_WILDCARD = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/*"
_ITEM_CREATE = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/create"
_ITEM_DELETE = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/delete"
_STORED_PROCEDURE = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/executeStoredProcedure"


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


def _account() -> TerraformResource:
    return _resource(
        AzureResourceType.COSMOSDB_ACCOUNT,
        "orders",
        {
            "id": _ACCOUNT_ID,
            "name": "orders",
            "resource_group_name": "data",
            "location": "eastus",
            "offer_type": "Standard",
        },
    )


def _database() -> TerraformResource:
    return _resource(
        AzureResourceType.COSMOSDB_SQL_DATABASE,
        "app",
        {
            "id": _DATABASE_ID,
            "name": "app",
            "resource_group_name": "data",
            "account_name": "orders",
        },
    )


def _container() -> TerraformResource:
    return _resource(
        AzureResourceType.COSMOSDB_SQL_CONTAINER,
        "events",
        {
            "id": _CONTAINER_ID,
            "name": "events",
            "database_name": "app",
            "resource_group_name": "data",
            "account_name": "orders",
            "partition_key_paths": ["/tenant"],
        },
    )


def _web_app(
    *,
    principal_id: object = _SYSTEM_PRINCIPAL_ID,
) -> TerraformResource:
    return _resource(
        AzureResourceType.LINUX_WEB_APP,
        "orders",
        {
            "id": ("/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/orders"),
            "name": "orders",
            "identity": [
                {
                    "type": "SystemAssigned",
                    "principal_id": principal_id,
                    "tenant_id": "tenant-id",
                    "identity_ids": [],
                }
            ],
        },
    )


def _function_app() -> TerraformResource:
    return _resource(
        AzureResourceType.LINUX_FUNCTION_APP,
        "orders_worker",
        {
            "id": ("/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/orders-worker"),
            "name": "orders-worker",
            "identity": [
                {
                    "type": "UserAssigned",
                    "identity_ids": ["azurerm_user_assigned_identity.orders_runtime.id"],
                }
            ],
        },
    )


def _user_assigned_identity(
    *,
    principal_id: object = _USER_PRINCIPAL_ID,
) -> TerraformResource:
    return _resource(
        AzureResourceType.USER_ASSIGNED_IDENTITY,
        "orders_runtime",
        {
            "id": _USER_IDENTITY_ID,
            "name": "orders-runtime",
            "principal_id": principal_id,
            "client_id": "orders-runtime-client-id",
            "tenant_id": "tenant-id",
        },
    )


def _custom_role(
    *,
    data_actions: list[str],
    assignable_scopes: list[str] | None = None,
    unknown_permissions: bool = False,
    unknown_assignable_scopes: bool = False,
) -> TerraformResource:
    unknown_values: dict[str, object] = {}
    if unknown_permissions:
        unknown_values["permissions"] = [{"data_actions": True}]
    if unknown_assignable_scopes:
        unknown_values["assignable_scopes"] = True
    return _resource(
        AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION,
        "workload",
        {
            "id": _CUSTOM_ROLE_ID,
            "role_definition_id": _CUSTOM_ROLE_GUID,
            "name": "Workload data role",
            "type": "CustomRole",
            "resource_group_name": "data",
            "account_name": "orders",
            "assignable_scopes": (assignable_scopes if assignable_scopes is not None else [_ACCOUNT_ID]),
            "permissions": [{"data_actions": data_actions}],
        },
        unknown_values=unknown_values,
    )


def _native_assignment(
    *,
    principal_id: object = _SYSTEM_PRINCIPAL_ID,
    role_definition_id: object = _CONTRIBUTOR_ROLE_ID,
    scope: object = "/",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.COSMOSDB_SQL_ROLE_ASSIGNMENT,
        "workload",
        {
            "id": f"{_ACCOUNT_ID}/sqlRoleAssignments/workload",
            "name": "workload",
            "resource_group_name": "data",
            "account_name": "orders",
            "principal_id": principal_id,
            "role_definition_id": role_definition_id,
            "scope": scope,
        },
        unknown_values=unknown_values,
    )


def _ordinary_role_assignment() -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        "workload",
        {
            "scope": "azurerm_cosmosdb_account.orders.id",
            "role_definition_name": "Cosmos DB Operator",
            "role_definition_id": (
                "/subscriptions/sub-0001/providers/Microsoft.Authorization/"
                "roleDefinitions/230815da-be43-4aae-9cb4-875f7bd000aa"
            ),
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


class AzureAppServiceCosmosDbAccessPathTests(unittest.TestCase):
    def test_system_identity_contributor_account_path_expands_exact_actions(self) -> None:
        facts = _workload_facts(
            [
                _account(),
                _web_app(),
                _native_assignment(),
            ]
        )

        self.assertEqual(len(facts.app_service_cosmosdb_access_paths), 1)
        path = facts.app_service_cosmosdb_access_paths[0]
        self.assertEqual(path["identity_kind"], "system_assigned")
        self.assertEqual(path["identity_address"], "azurerm_linux_web_app.orders")
        self.assertEqual(path["principal_id"], _SYSTEM_PRINCIPAL_ID)
        self.assertEqual(
            path["cosmosdb_resource_address"],
            "azurerm_cosmosdb_account.orders",
        )
        self.assertEqual(path["cosmosdb_resource_id"], _ACCOUNT_ID)
        self.assertEqual(path["cosmosdb_account_id"], _ACCOUNT_ID)
        self.assertIsNone(path["cosmosdb_database_address"])
        self.assertIsNone(path["cosmosdb_container_address"])
        self.assertEqual(path["role_kind"], "built_in_data_contributor")
        self.assertEqual(
            path["access_classes"],
            [
                "metadata_read",
                "read",
                "entity_write",
                "entity_delete",
                "stored_procedure_execution",
                "conflict_management",
            ],
        )
        self.assertEqual(len(path["matched_data_actions"]), 11)
        self.assertIn(_ITEM_CREATE, path["matched_data_actions"])
        self.assertIn(_ITEM_DELETE, path["matched_data_actions"])
        self.assertEqual(path["scope_type"], "account")
        self.assertEqual(
            path["resource_scope"],
            "exact_cosmosdb_for_nosql_account",
        )
        self.assertEqual(path["access_state"], "granted")
        self.assertEqual(
            path["authorization_model"],
            "cosmosdb_for_nosql_native_rbac",
        )
        self.assertEqual(facts.app_service_cosmosdb_access_path_uncertainties, [])

    def test_user_identity_reader_container_path_retains_exact_ancestry(self) -> None:
        facts = _workload_facts(
            [
                _account(),
                _database(),
                _container(),
                _user_assigned_identity(),
                _function_app(),
                _native_assignment(
                    principal_id=_USER_PRINCIPAL_ID,
                    role_definition_id=_READER_ROLE_ID,
                    scope="/dbs/app/colls/events",
                ),
            ],
            address="azurerm_linux_function_app.orders_worker",
        )

        path = facts.app_service_cosmosdb_access_paths[0]
        self.assertEqual(path["identity_kind"], "user_assigned")
        self.assertEqual(
            path["identity_address"],
            "azurerm_user_assigned_identity.orders_runtime",
        )
        self.assertEqual(
            path["cosmosdb_resource_address"],
            "azurerm_cosmosdb_sql_container.events",
        )
        self.assertEqual(
            path["cosmosdb_account_address"],
            "azurerm_cosmosdb_account.orders",
        )
        self.assertEqual(
            path["cosmosdb_database_address"],
            "azurerm_cosmosdb_sql_database.app",
        )
        self.assertEqual(
            path["cosmosdb_container_address"],
            "azurerm_cosmosdb_sql_container.events",
        )
        self.assertEqual(path["cosmosdb_database_name"], "app")
        self.assertEqual(path["cosmosdb_container_name"], "events")
        self.assertEqual(path["role_kind"], "built_in_data_reader")
        self.assertEqual(path["access_classes"], ["metadata_read", "read"])
        self.assertEqual(path["scope_type"], "container")
        self.assertEqual(
            path["resource_scope"],
            "exact_cosmosdb_for_nosql_container",
        )

    def test_custom_database_role_preserves_role_and_action_evidence(self) -> None:
        facts = _workload_facts(
            [
                _account(),
                _database(),
                _web_app(),
                _custom_role(
                    data_actions=[
                        _ITEM_CREATE,
                        _ITEM_DELETE,
                        _STORED_PROCEDURE,
                    ],
                    assignable_scopes=[f"{_ACCOUNT_ID}/dbs/app"],
                ),
                _native_assignment(
                    role_definition_id=_CUSTOM_ROLE_ID,
                    scope="/dbs/app",
                ),
            ]
        )

        path = facts.app_service_cosmosdb_access_paths[0]
        self.assertEqual(path["role_kind"], "custom")
        self.assertEqual(
            path["role_definition_address"],
            "azurerm_cosmosdb_sql_role_definition.workload",
        )
        self.assertEqual(
            path["matched_data_actions"],
            [_ITEM_CREATE, _ITEM_DELETE, _STORED_PROCEDURE],
        )
        self.assertEqual(
            path["access_classes"],
            ["entity_write", "entity_delete", "stored_procedure_execution"],
        )
        self.assertEqual(path["scope_type"], "database")
        self.assertEqual(
            path["cosmosdb_resource_address"],
            "azurerm_cosmosdb_sql_database.app",
        )
        self.assertEqual(
            path["grant_basis"],
            "cosmosdb_for_nosql_native_role_assignment",
        )

    def test_documented_wildcards_do_not_cross_action_levels(self) -> None:
        container_facts = _workload_facts(
            [
                _account(),
                _database(),
                _container(),
                _web_app(),
                _custom_role(data_actions=[_CONTAINER_WILDCARD]),
                _native_assignment(
                    role_definition_id=_CUSTOM_ROLE_ID,
                    scope="/dbs/app/colls/events",
                ),
            ]
        )
        item_facts = _workload_facts(
            [
                _account(),
                _database(),
                _container(),
                _web_app(),
                _custom_role(data_actions=[_ITEM_WILDCARD]),
                _native_assignment(
                    role_definition_id=_CUSTOM_ROLE_ID,
                    scope="/dbs/app/colls/events",
                ),
            ]
        )

        container_path = container_facts.app_service_cosmosdb_access_paths[0]
        item_path = item_facts.app_service_cosmosdb_access_paths[0]
        self.assertEqual(
            container_path["access_classes"],
            ["read", "stored_procedure_execution", "conflict_management"],
        )
        self.assertNotIn(_ITEM_CREATE, container_path["matched_data_actions"])
        self.assertNotIn(_ITEM_DELETE, container_path["matched_data_actions"])
        self.assertEqual(
            item_path["access_classes"],
            ["read", "entity_write", "entity_delete"],
        )
        self.assertIn(_ITEM_CREATE, item_path["matched_data_actions"])
        self.assertIn(_ITEM_DELETE, item_path["matched_data_actions"])
        self.assertNotIn(_STORED_PROCEDURE, item_path["matched_data_actions"])

    def test_other_principals_and_ordinary_azure_rbac_do_not_create_paths(self) -> None:
        other_principal_facts = _workload_facts(
            [
                _account(),
                _web_app(),
                _native_assignment(principal_id="other-principal-id"),
            ]
        )
        ordinary_rbac_facts = _workload_facts(
            [
                _account(),
                _web_app(),
                _ordinary_role_assignment(),
            ]
        )

        self.assertEqual(other_principal_facts.app_service_cosmosdb_access_paths, [])
        self.assertEqual(ordinary_rbac_facts.app_service_cosmosdb_access_paths, [])

    def test_unmodeled_or_case_mismatched_scopes_do_not_create_paths(self) -> None:
        external_facts = _workload_facts(
            [
                _account(),
                _web_app(),
                _native_assignment(scope="/dbs/external"),
            ]
        )
        case_mismatch_facts = _workload_facts(
            [
                _account(),
                _database(),
                _web_app(),
                _native_assignment(scope="/dbs/App"),
            ]
        )

        self.assertEqual(external_facts.app_service_cosmosdb_access_paths, [])
        self.assertTrue(
            any(
                "does not resolve to an exact modeled Cosmos DB for NoSQL target" in value
                for value in external_facts.app_service_cosmosdb_access_path_uncertainties
            )
        )
        self.assertEqual(case_mismatch_facts.app_service_cosmosdb_access_paths, [])
        self.assertTrue(
            any(
                "does not resolve to an exact modeled Cosmos DB for NoSQL target" in value
                for value in case_mismatch_facts.app_service_cosmosdb_access_path_uncertainties
            )
        )

    def test_outside_or_unknown_assignable_scope_does_not_materialize_paths(self) -> None:
        outside_facts = _workload_facts(
            [
                _account(),
                _database(),
                _container(),
                _web_app(),
                _custom_role(
                    data_actions=[_ITEM_CREATE],
                    assignable_scopes=[f"{_ACCOUNT_ID}/dbs/app/colls/events"],
                ),
                _native_assignment(
                    role_definition_id=_CUSTOM_ROLE_ID,
                    scope="/dbs/app",
                ),
            ]
        )
        unknown_facts = _workload_facts(
            [
                _account(),
                _database(),
                _web_app(),
                _custom_role(
                    data_actions=[_ITEM_CREATE],
                    unknown_assignable_scopes=True,
                ),
                _native_assignment(
                    role_definition_id=_CUSTOM_ROLE_ID,
                    scope="/dbs/app",
                ),
            ]
        )

        self.assertEqual(outside_facts.app_service_cosmosdb_access_paths, [])
        self.assertTrue(
            any(
                "assignable-scope compatibility" in value
                for value in outside_facts.app_service_cosmosdb_access_path_uncertainties
            )
        )
        self.assertEqual(unknown_facts.app_service_cosmosdb_access_paths, [])
        self.assertTrue(
            any(
                "assignable-scope compatibility" in value
                for value in unknown_facts.app_service_cosmosdb_access_path_uncertainties
            )
        )

    def test_unresolved_permissions_principal_and_identity_remain_uncertain(self) -> None:
        permissions_facts = _workload_facts(
            [
                _account(),
                _web_app(),
                _custom_role(
                    data_actions=[_ITEM_CREATE],
                    unknown_permissions=True,
                ),
                _native_assignment(role_definition_id=_CUSTOM_ROLE_ID),
            ]
        )
        principal_facts = _workload_facts(
            [
                _account(),
                _web_app(),
                _native_assignment(
                    principal_id="",
                    unknown_values={"principal_id": True},
                ),
            ]
        )
        identity_facts = _workload_facts(
            [
                _account(),
                _web_app(principal_id=None),
                _native_assignment(),
            ]
        )

        self.assertEqual(permissions_facts.app_service_cosmosdb_access_paths, [])
        self.assertTrue(
            any(
                "permissions are unresolved" in value
                for value in permissions_facts.app_service_cosmosdb_access_path_uncertainties
            )
        )
        self.assertEqual(principal_facts.app_service_cosmosdb_access_paths, [])
        self.assertTrue(
            any(
                "native RBAC principal is unresolved" in value
                for value in principal_facts.app_service_cosmosdb_access_path_uncertainties
            )
        )
        self.assertEqual(identity_facts.app_service_cosmosdb_access_paths, [])
        self.assertTrue(
            any(
                "system-assigned identity principal_id is unresolved" in value
                for value in identity_facts.app_service_cosmosdb_access_path_uncertainties
            )
        )

    def test_unrelated_custom_data_action_is_deterministically_quiet(self) -> None:
        facts = _workload_facts(
            [
                _account(),
                _web_app(),
                _custom_role(data_actions=["Microsoft.DocumentDB/databaseAccounts/unknownAction"]),
                _native_assignment(role_definition_id=_CUSTOM_ROLE_ID),
            ]
        )

        self.assertEqual(facts.app_service_cosmosdb_access_paths, [])
        self.assertEqual(facts.app_service_cosmosdb_access_path_uncertainties, [])


if __name__ == "__main__":
    unittest.main()

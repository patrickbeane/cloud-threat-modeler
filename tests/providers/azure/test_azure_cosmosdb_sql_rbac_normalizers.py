from __future__ import annotations

import unittest

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.catalog import default_resource_capability_registry
from tfstride.providers.resource_capabilities import ResourceCapability

_ACCOUNT_ID = "/subscriptions/sub-1/resourceGroups/data/providers/Microsoft.DocumentDB/databaseAccounts/orders"
_OTHER_ACCOUNT_ID = "/subscriptions/sub-1/resourceGroups/other/providers/Microsoft.DocumentDB/databaseAccounts/orders"
_FOREIGN_SUBSCRIPTION_ACCOUNT_ID = (
    "/subscriptions/foreign-sub/resourceGroups/data/providers/Microsoft.DocumentDB/databaseAccounts/orders"
)
_DATABASE_ID = f"{_ACCOUNT_ID}/sqlDatabases/app"
_CONTAINER_ID = f"{_DATABASE_ID}/containers/events"
_CUSTOM_ROLE_GUID = "11111111-2222-3333-4444-555555555555"
_CUSTOM_ROLE_ID = f"{_ACCOUNT_ID}/sqlRoleDefinitions/{_CUSTOM_ROLE_GUID}"
_READER_ROLE_ID = f"{_ACCOUNT_ID}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000001"
_CONTRIBUTOR_ROLE_ID = f"{_ACCOUNT_ID}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
_READER_ACTIONS = [
    "Microsoft.DocumentDB/databaseAccounts/readMetadata",
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/read",
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/executeQuery",
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/readChangeFeed",
]
_CONTRIBUTOR_ACTIONS = [
    "Microsoft.DocumentDB/databaseAccounts/readMetadata",
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/*",
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/*",
]


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


def _account(
    *,
    terraform_name: str = "orders",
    resource_group: str = "data",
    account_id: str | None = _ACCOUNT_ID,
    unknown_id: bool = False,
) -> TerraformResource:
    return _resource(
        AzureResourceType.COSMOSDB_ACCOUNT,
        terraform_name,
        {
            "id": account_id,
            "name": "orders",
            "resource_group_name": resource_group,
            "location": "eastus",
            "offer_type": "Standard",
        },
        unknown_values={"id": True} if unknown_id else None,
    )


def _database(
    *,
    terraform_name: str = "app",
    database_name: str = "app",
    resource_group: str = "data",
    database_id: str | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.COSMOSDB_SQL_DATABASE,
        terraform_name,
        {
            "id": database_id or f"{_ACCOUNT_ID}/sqlDatabases/{database_name}",
            "name": database_name,
            "resource_group_name": resource_group,
            "account_name": "orders",
        },
    )


def _container(
    *,
    terraform_name: str = "events",
    resource_group: str = "data",
    database_name: str = "app",
    container_name: str = "events",
    container_id: str = _CONTAINER_ID,
) -> TerraformResource:
    return _resource(
        AzureResourceType.COSMOSDB_SQL_CONTAINER,
        terraform_name,
        {
            "id": container_id,
            "name": container_name,
            "database_name": database_name,
            "resource_group_name": resource_group,
            "account_name": "orders",
            "partition_key_paths": ["/tenant"],
        },
    )


def _custom_role(
    *,
    role_id: str | None = _CUSTOM_ROLE_ID,
    unknown_id: bool = False,
    data_actions: list[str] | None = None,
    unknown_permissions: bool = False,
    assignable_scopes: list[str] | None = None,
    unknown_assignable_scopes: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": role_id,
        "role_definition_id": _CUSTOM_ROLE_GUID,
        "name": "Orders item writer",
        "type": "CustomRole",
        "resource_group_name": "data",
        "account_name": "orders",
        "assignable_scopes": assignable_scopes
        if assignable_scopes is not None
        else [
            _ACCOUNT_ID,
            f"{_ACCOUNT_ID}/dbs/app",
            f"{_ACCOUNT_ID}/dbs/app/colls/events",
            f"{_ACCOUNT_ID}/dbs/future",
        ],
        "permissions": [
            {
                "data_actions": data_actions
                or [
                    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/delete",
                    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/create",
                ]
            }
        ],
    }
    unknown_values: dict[str, object] = {}
    if unknown_id:
        unknown_values["id"] = True
    if unknown_permissions:
        unknown_values["permissions"] = [{"data_actions": True}]
    if unknown_assignable_scopes:
        unknown_values["assignable_scopes"] = True
    return _resource(
        AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION,
        "writer",
        values,
        unknown_values=unknown_values,
    )


def _assignment(
    *,
    terraform_name: str = "workload",
    role_definition_id: str = _CUSTOM_ROLE_ID,
    scope: str = f"{_ACCOUNT_ID}/dbs/app/colls/events",
    resource_group: str = "data",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.COSMOSDB_SQL_ROLE_ASSIGNMENT,
        terraform_name,
        {
            "id": f"{_ACCOUNT_ID}/sqlRoleAssignments/{terraform_name}",
            "name": terraform_name,
            "resource_group_name": resource_group,
            "account_name": "orders",
            "principal_id": "principal-123",
            "role_definition_id": role_definition_id,
            "scope": scope,
        },
        unknown_values=unknown_values,
    )


class AzureCosmosDbSqlRbacNormalizerTests(unittest.TestCase):
    def test_custom_role_and_assignment_preserve_exact_container_ancestry(self) -> None:
        inventory = AzureNormalizer().normalize([_account(), _database(), _container(), _custom_role(), _assignment()])
        database = inventory.get_by_address("azurerm_cosmosdb_sql_database.app")
        container = inventory.get_by_address("azurerm_cosmosdb_sql_container.events")
        role = inventory.get_by_address("azurerm_cosmosdb_sql_role_definition.writer")
        assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert database is not None
        assert container is not None
        assert role is not None
        assert assignment is not None

        database_facts = azure_facts(database)
        self.assertEqual(database.category, ResourceCategory.DATA)
        self.assertEqual(database.identifier, _DATABASE_ID)
        self.assertEqual(database_facts.cosmosdb_account_name, "orders")
        self.assertEqual(database_facts.cosmosdb_sql_database_name, "app")
        self.assertEqual(
            database_facts.resolved_cosmosdb_account_address,
            "azurerm_cosmosdb_account.orders",
        )

        container_facts = azure_facts(container)
        self.assertEqual(container.identifier, _CONTAINER_ID)
        self.assertEqual(container_facts.cosmosdb_sql_database_name, "app")
        self.assertEqual(container_facts.cosmosdb_sql_container_name, "events")
        self.assertEqual(
            container_facts.resolved_cosmosdb_account_address,
            "azurerm_cosmosdb_account.orders",
        )
        self.assertEqual(
            container_facts.resolved_cosmosdb_database_address,
            "azurerm_cosmosdb_sql_database.app",
        )

        role_facts = azure_facts(role)
        self.assertEqual(role.category, ResourceCategory.IAM)
        self.assertEqual(role_facts.cosmosdb_sql_role_definition_resource_id, _CUSTOM_ROLE_ID)
        self.assertEqual(role_facts.cosmosdb_sql_role_definition_guid, _CUSTOM_ROLE_GUID)
        self.assertEqual(role_facts.cosmosdb_sql_role_definition_name, "Orders item writer")
        self.assertEqual(role_facts.cosmosdb_sql_role_definition_type, "CustomRole")
        self.assertEqual(role_facts.cosmosdb_sql_role_kind, "custom")
        self.assertEqual(
            role_facts.cosmosdb_sql_role_definition_data_actions,
            [
                "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/create",
                "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/delete",
            ],
        )
        self.assertEqual(
            [record["scope_kind"] for record in role_facts.cosmosdb_sql_assignable_scope_records],
            ["account", "database", "container", "database"],
        )
        self.assertEqual(
            [record["resolution_state"] for record in role_facts.cosmosdb_sql_assignable_scope_records],
            ["resolved", "resolved", "resolved", "external_or_unmodeled"],
        )
        self.assertEqual(role_facts.cosmosdb_sql_rbac_uncertainties, [])

        assignment_facts = azure_facts(assignment)
        self.assertEqual(assignment.category, ResourceCategory.IAM)
        self.assertEqual(assignment_facts.cosmosdb_sql_principal_id, "principal-123")
        self.assertEqual(assignment_facts.cosmosdb_sql_role_assignment_scope_kind, "container")
        self.assertEqual(assignment_facts.cosmosdb_sql_role_assignment_scope_state, "resolved")
        self.assertEqual(
            assignment_facts.cosmosdb_sql_assignable_scope_compatibility_state,
            "resolved",
        )
        self.assertEqual(
            assignment_facts.resolved_cosmosdb_account_address,
            "azurerm_cosmosdb_account.orders",
        )
        self.assertEqual(
            assignment_facts.resolved_cosmosdb_database_address,
            "azurerm_cosmosdb_sql_database.app",
        )
        self.assertEqual(
            assignment_facts.resolved_cosmosdb_container_address,
            "azurerm_cosmosdb_sql_container.events",
        )
        self.assertEqual(
            assignment_facts.resolved_cosmosdb_sql_role_definition_address,
            "azurerm_cosmosdb_sql_role_definition.writer",
        )
        self.assertEqual(assignment_facts.cosmosdb_sql_role_kind, "custom")
        self.assertEqual(
            assignment_facts.cosmosdb_sql_role_data_actions,
            role_facts.cosmosdb_sql_role_definition_data_actions,
        )
        self.assertEqual(assignment_facts.cosmosdb_sql_rbac_uncertainties, [])
        self.assertIsNone(assignment_facts.role_assignment_scope)
        self.assertIsNone(assignment_facts.role_definition_id)

    def test_built_in_reader_resolves_exact_container_scope(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _account(),
                _database(),
                _container(),
                _assignment(role_definition_id=_READER_ROLE_ID),
            ]
        )
        assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert assignment is not None
        facts = azure_facts(assignment)

        self.assertEqual(facts.cosmosdb_sql_role_kind, "built_in_data_reader")
        self.assertEqual(
            facts.cosmosdb_sql_role_definition_name,
            "Cosmos DB Built-in Data Reader",
        )
        self.assertEqual(facts.cosmosdb_sql_role_data_actions, _READER_ACTIONS)
        self.assertEqual(facts.cosmosdb_sql_role_assignment_scope_kind, "container")
        self.assertEqual(facts.cosmosdb_sql_role_assignment_scope_state, "resolved")
        self.assertEqual(
            facts.cosmosdb_sql_assignable_scope_compatibility_state,
            "resolved",
        )
        self.assertEqual(
            facts.resolved_cosmosdb_container_address,
            "azurerm_cosmosdb_sql_container.events",
        )
        self.assertEqual(facts.cosmosdb_sql_rbac_uncertainties, [])

    def test_built_in_contributor_resolves_relative_account_scope(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _account(),
                _assignment(
                    role_definition_id=_CONTRIBUTOR_ROLE_ID,
                    scope="/",
                ),
            ]
        )
        assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert assignment is not None
        facts = azure_facts(assignment)

        self.assertEqual(facts.cosmosdb_sql_role_kind, "built_in_data_contributor")
        self.assertEqual(facts.cosmosdb_sql_role_data_actions, _CONTRIBUTOR_ACTIONS)
        self.assertEqual(facts.cosmosdb_sql_role_assignment_scope_kind, "account")
        self.assertEqual(facts.cosmosdb_sql_role_assignment_scope_state, "resolved")
        self.assertEqual(
            facts.cosmosdb_sql_assignable_scope_compatibility_state,
            "resolved",
        )
        self.assertEqual(
            facts.resolved_cosmosdb_account_address,
            "azurerm_cosmosdb_account.orders",
        )
        self.assertIsNone(facts.resolved_cosmosdb_database_address)
        self.assertIsNone(facts.resolved_cosmosdb_container_address)

    def test_computed_custom_role_id_resolves_independently_of_resource_order(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _account(),
                _database(),
                _assignment(role_definition_id=_CUSTOM_ROLE_ID, scope="/dbs/app"),
                _custom_role(role_id=None, unknown_id=True),
            ]
        )
        role = inventory.get_by_address("azurerm_cosmosdb_sql_role_definition.writer")
        assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert role is not None
        assert assignment is not None

        self.assertEqual(
            azure_facts(role).cosmosdb_sql_role_definition_resource_id,
            _CUSTOM_ROLE_ID,
        )
        self.assertEqual(
            azure_facts(assignment).resolved_cosmosdb_sql_role_definition_address,
            role.address,
        )
        self.assertEqual(
            azure_facts(assignment).cosmosdb_sql_role_assignment_scope_kind,
            "database",
        )
        self.assertEqual(
            azure_facts(assignment).cosmosdb_sql_assignable_scope_compatibility_state,
            "resolved",
        )

    def test_container_assignable_scope_rejects_database_assignment(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _account(),
                _database(),
                _container(),
                _custom_role(assignable_scopes=[f"{_ACCOUNT_ID}/dbs/app/colls/events"]),
                _assignment(scope=f"{_ACCOUNT_ID}/dbs/app"),
            ]
        )
        assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert assignment is not None
        facts = azure_facts(assignment)

        self.assertEqual(facts.cosmosdb_sql_role_assignment_scope_state, "resolved")
        self.assertEqual(
            facts.cosmosdb_sql_assignable_scope_compatibility_state,
            "outside_assignable_scope",
        )
        self.assertEqual(
            facts.resolved_cosmosdb_sql_role_definition_address,
            "azurerm_cosmosdb_sql_role_definition.writer",
        )
        self.assertEqual(facts.cosmosdb_sql_role_data_actions, [])
        self.assertTrue(
            any("outside the assignable scopes" in value for value in facts.cosmosdb_sql_rbac_uncertainties)
        )

    def test_database_assignable_scope_covers_child_container(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _account(),
                _database(),
                _container(),
                _custom_role(assignable_scopes=[f"{_ACCOUNT_ID}/dbs/app"]),
                _assignment(scope=f"{_ACCOUNT_ID}/dbs/app/colls/events"),
            ]
        )
        assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert assignment is not None
        facts = azure_facts(assignment)

        self.assertEqual(
            facts.cosmosdb_sql_assignable_scope_compatibility_state,
            "resolved",
        )
        self.assertNotEqual(facts.cosmosdb_sql_role_data_actions, [])

    def test_database_assignable_scope_rejects_sibling_database(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _account(),
                _database(),
                _database(
                    terraform_name="audit",
                    database_name="audit",
                ),
                _custom_role(assignable_scopes=[f"{_ACCOUNT_ID}/dbs/app"]),
                _assignment(scope=f"{_ACCOUNT_ID}/dbs/audit"),
            ]
        )
        assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert assignment is not None
        facts = azure_facts(assignment)

        self.assertEqual(
            facts.cosmosdb_sql_assignable_scope_compatibility_state,
            "outside_assignable_scope",
        )
        self.assertEqual(facts.cosmosdb_sql_role_data_actions, [])

    def test_database_scope_name_matching_is_case_sensitive(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _account(),
                _database(database_name="app"),
                _assignment(
                    role_definition_id=_READER_ROLE_ID,
                    scope="/dbs/App",
                ),
            ]
        )
        assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert assignment is not None
        facts = azure_facts(assignment)

        self.assertEqual(
            facts.cosmosdb_sql_role_assignment_scope_state,
            "external_or_unmodeled",
        )
        self.assertIsNone(facts.resolved_cosmosdb_database_address)

    def test_database_assignable_scope_name_matching_is_case_sensitive(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _account(),
                _database(database_name="app"),
                _custom_role(
                    assignable_scopes=[f"{_ACCOUNT_ID}/dbs/App"],
                ),
                _assignment(scope="/dbs/app"),
            ]
        )
        assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert assignment is not None
        facts = azure_facts(assignment)

        self.assertEqual(
            facts.cosmosdb_sql_assignable_scope_compatibility_state,
            "outside_assignable_scope",
        )
        self.assertEqual(facts.cosmosdb_sql_role_data_actions, [])

    def test_container_scope_name_matching_is_case_sensitive(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _account(),
                _database(),
                _container(container_name="events"),
                _assignment(
                    role_definition_id=_CONTRIBUTOR_ROLE_ID,
                    scope="/dbs/app/colls/Events",
                ),
            ]
        )
        assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert assignment is not None
        facts = azure_facts(assignment)

        self.assertEqual(
            facts.cosmosdb_sql_role_assignment_scope_state,
            "external_or_unmodeled",
        )
        self.assertEqual(
            facts.resolved_cosmosdb_database_address,
            "azurerm_cosmosdb_sql_database.app",
        )
        self.assertIsNone(facts.resolved_cosmosdb_container_address)

    def test_unknown_assignable_scopes_do_not_materialize_role_actions(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _account(),
                _database(),
                _custom_role(unknown_assignable_scopes=True),
                _assignment(scope=f"{_ACCOUNT_ID}/dbs/app"),
            ]
        )
        assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert assignment is not None
        facts = azure_facts(assignment)

        self.assertEqual(
            facts.resolved_cosmosdb_sql_role_definition_address,
            "azurerm_cosmosdb_sql_role_definition.writer",
        )
        self.assertEqual(
            facts.cosmosdb_sql_assignable_scope_compatibility_state,
            "unknown",
        )
        self.assertEqual(facts.cosmosdb_sql_role_data_actions, [])
        self.assertTrue(
            any("assignable-scope compatibility" in value for value in facts.cosmosdb_sql_rbac_uncertainties)
        )

    def test_relative_role_assignable_scope_is_rejected(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _account(),
                _database(),
                _custom_role(assignable_scopes=["/dbs/app"]),
                _assignment(scope="/dbs/app"),
            ]
        )
        role = inventory.get_by_address("azurerm_cosmosdb_sql_role_definition.writer")
        assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert role is not None
        assert assignment is not None

        self.assertEqual(
            azure_facts(role).cosmosdb_sql_assignable_scope_records[0]["resolution_state"],
            "unknown",
        )
        self.assertEqual(
            azure_facts(assignment).cosmosdb_sql_assignable_scope_compatibility_state,
            "unknown",
        )
        self.assertEqual(azure_facts(assignment).cosmosdb_sql_role_data_actions, [])

    def test_unknown_account_id_rejects_foreign_full_assignment_scope(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _account(account_id=None, unknown_id=True),
                _custom_role(
                    role_id=None,
                    unknown_id=True,
                    assignable_scopes=["azurerm_cosmosdb_account.orders.id"],
                ),
                _assignment(
                    role_definition_id=("azurerm_cosmosdb_sql_role_definition.writer.id"),
                    scope=f"{_FOREIGN_SUBSCRIPTION_ACCOUNT_ID}/dbs/app",
                ),
            ]
        )
        assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert assignment is not None
        facts = azure_facts(assignment)

        self.assertEqual(
            facts.cosmosdb_sql_role_assignment_scope_state,
            "unknown",
        )
        self.assertIsNone(facts.resolved_cosmosdb_database_address)
        self.assertEqual(
            facts.cosmosdb_sql_assignable_scope_compatibility_state,
            "unknown",
        )
        self.assertEqual(facts.cosmosdb_sql_role_data_actions, [])

    def test_unknown_account_id_rejects_foreign_builtin_role_reference(self) -> None:
        foreign_reader_role = (
            f"{_FOREIGN_SUBSCRIPTION_ACCOUNT_ID}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000001"
        )
        inventory = AzureNormalizer().normalize(
            [
                _account(account_id=None, unknown_id=True),
                _assignment(
                    role_definition_id=foreign_reader_role,
                    scope="/",
                ),
            ]
        )
        assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert assignment is not None
        facts = azure_facts(assignment)

        self.assertEqual(facts.cosmosdb_sql_role_assignment_scope_state, "resolved")
        self.assertIsNone(facts.cosmosdb_sql_role_kind)
        self.assertEqual(
            facts.cosmosdb_sql_assignable_scope_compatibility_state,
            "unknown",
        )
        self.assertEqual(facts.cosmosdb_sql_role_data_actions, [])
        self.assertTrue(
            any(
                "built-in role definition reference is not scoped" in value
                for value in facts.cosmosdb_sql_rbac_uncertainties
            )
        )

    def test_management_plane_database_id_is_not_a_data_plane_scope(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _account(),
                _database(),
                _assignment(
                    role_definition_id=_READER_ROLE_ID,
                    scope="azurerm_cosmosdb_sql_database.app.id",
                ),
            ]
        )
        assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert assignment is not None
        facts = azure_facts(assignment)

        self.assertEqual(facts.cosmosdb_sql_role_assignment_scope_state, "unknown")
        self.assertEqual(
            facts.cosmosdb_sql_assignable_scope_compatibility_state,
            "unknown",
        )
        self.assertEqual(facts.cosmosdb_sql_role_data_actions, [])

    def test_same_names_in_other_resource_group_do_not_cross_resolve(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _account(),
                _database(),
                _account(
                    terraform_name="other",
                    resource_group="other",
                    account_id=_OTHER_ACCOUNT_ID,
                ),
                _database(
                    terraform_name="other",
                    resource_group="other",
                    database_id=f"{_OTHER_ACCOUNT_ID}/sqlDatabases/app",
                ),
                _assignment(role_definition_id=_READER_ROLE_ID, scope=f"{_ACCOUNT_ID}/dbs/app"),
                _assignment(
                    terraform_name="foreign",
                    role_definition_id=_READER_ROLE_ID,
                    scope=f"{_OTHER_ACCOUNT_ID}/dbs/app",
                ),
            ]
        )
        local = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        foreign = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.foreign")
        assert local is not None
        assert foreign is not None

        self.assertEqual(
            azure_facts(local).resolved_cosmosdb_database_address,
            "azurerm_cosmosdb_sql_database.app",
        )
        self.assertEqual(
            azure_facts(local).cosmosdb_sql_role_assignment_scope_state,
            "resolved",
        )
        self.assertEqual(
            azure_facts(foreign).cosmosdb_sql_role_assignment_scope_state,
            "foreign_account",
        )
        self.assertIsNone(azure_facts(foreign).resolved_cosmosdb_database_address)

    def test_exact_database_reference_cannot_cross_account_boundary(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _account(),
                _database(),
                _account(
                    terraform_name="other",
                    resource_group="other",
                    account_id=_OTHER_ACCOUNT_ID,
                ),
                _database(
                    terraform_name="other",
                    resource_group="other",
                    database_id=f"{_OTHER_ACCOUNT_ID}/sqlDatabases/app",
                ),
                _container(database_name="azurerm_cosmosdb_sql_database.other.name"),
            ]
        )
        container = inventory.get_by_address("azurerm_cosmosdb_sql_container.events")
        assert container is not None
        facts = azure_facts(container)

        self.assertEqual(
            facts.resolved_cosmosdb_account_address,
            "azurerm_cosmosdb_account.orders",
        )
        self.assertIsNone(facts.resolved_cosmosdb_database_address)
        self.assertTrue(
            any(
                "parent Azure Cosmos DB for NoSQL database is unresolved" in value
                for value in facts.cosmosdb_sql_rbac_uncertainties
            )
        )

    def test_unmodeled_assignment_target_remains_non_resolved(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _account(),
                _assignment(
                    role_definition_id=_CONTRIBUTOR_ROLE_ID,
                    scope="/dbs/external/colls/events",
                ),
            ]
        )
        assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert assignment is not None
        facts = azure_facts(assignment)

        self.assertEqual(facts.cosmosdb_sql_role_assignment_scope_kind, "container")
        self.assertEqual(
            facts.cosmosdb_sql_role_assignment_scope_state,
            "external_or_unmodeled",
        )
        self.assertIsNone(facts.resolved_cosmosdb_database_address)
        self.assertIsNone(facts.resolved_cosmosdb_container_address)
        self.assertEqual(facts.cosmosdb_sql_role_kind, "built_in_data_contributor")
        self.assertTrue(any("external or unmodeled" in value for value in facts.cosmosdb_sql_rbac_uncertainties))

    def test_unknown_native_rbac_fields_do_not_become_grants(self) -> None:
        role = _custom_role(unknown_permissions=True)
        assignment = _assignment(
            role_definition_id="",
            scope="",
            unknown_values={
                "principal_id": True,
                "role_definition_id": True,
                "scope": True,
            },
        )
        inventory = AzureNormalizer().normalize([_account(), role, assignment])
        normalized_role = inventory.get_by_address("azurerm_cosmosdb_sql_role_definition.writer")
        normalized_assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert normalized_role is not None
        assert normalized_assignment is not None
        role_facts = azure_facts(normalized_role)
        assignment_facts = azure_facts(normalized_assignment)

        self.assertEqual(role_facts.cosmosdb_sql_role_definition_data_actions, [])
        self.assertTrue(any("data_actions is unknown" in value for value in role_facts.cosmosdb_sql_rbac_uncertainties))
        self.assertIsNone(assignment_facts.cosmosdb_sql_principal_id)
        self.assertIsNone(assignment_facts.cosmosdb_sql_role_kind)
        self.assertEqual(assignment_facts.cosmosdb_sql_role_data_actions, [])
        self.assertEqual(assignment_facts.cosmosdb_sql_role_assignment_scope_state, "unknown")
        self.assertEqual(
            assignment_facts.cosmosdb_sql_assignable_scope_compatibility_state,
            "unknown",
        )
        self.assertTrue(any("scope is unknown" in value for value in assignment_facts.cosmosdb_sql_rbac_uncertainties))
        self.assertTrue(
            any(
                "custom native role definition unknown is unresolved" in value
                for value in assignment_facts.cosmosdb_sql_rbac_uncertainties
            )
        )

    def test_entities_and_native_rbac_join_only_provider_local_capabilities(self) -> None:
        inventory = AzureNormalizer().normalize([_account(), _database(), _container(), _custom_role(), _assignment()])
        registry = default_resource_capability_registry()
        database = inventory.get_by_address("azurerm_cosmosdb_sql_database.app")
        container = inventory.get_by_address("azurerm_cosmosdb_sql_container.events")
        role = inventory.get_by_address("azurerm_cosmosdb_sql_role_definition.writer")
        assignment = inventory.get_by_address("azurerm_cosmosdb_sql_role_assignment.workload")
        assert database is not None
        assert container is not None
        assert role is not None
        assert assignment is not None

        self.assertTrue(registry.has_capability(database, ResourceCapability.DATA_STORE))
        self.assertTrue(registry.has_capability(database, ResourceCapability.DATABASE))
        self.assertTrue(registry.has_capability(container, ResourceCapability.DATA_STORE))
        self.assertFalse(registry.has_capability(container, ResourceCapability.DATABASE))
        self.assertTrue(registry.has_capability(role, ResourceCapability.IAM_POLICY))
        self.assertTrue(registry.has_capability(assignment, ResourceCapability.IAM_POLICY))


if __name__ == "__main__":
    unittest.main()

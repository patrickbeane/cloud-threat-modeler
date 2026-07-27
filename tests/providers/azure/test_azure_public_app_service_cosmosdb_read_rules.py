from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _ACCOUNT_ID,
    _CONTRIBUTOR_ROLE_ID,
    _CUSTOM_ROLE_ID,
    _READER_ROLE_ID,
    _SYSTEM_PRINCIPAL_ID,
    _USER_PRINCIPAL_ID,
    _account,
    _container,
    _custom_role,
    _database,
    _function_app,
    _native_assignment,
    _ordinary_role_assignment,
    _resource,
    _user_assigned_identity,
    _web_app,
)
from tests.providers.azure.test_azure_public_app_service_cosmosdb_mutation_rules import (
    _evidence,
    _public,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_RULE_ID = "azure-public-app-service-cosmosdb-read-access"
_ITEM_READ = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/read"
_ITEM_UNMASK = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/unmask"
_EXECUTE_QUERY = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/executeQuery"
_READ_CHANGE_FEED = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/readChangeFeed"
_READ_METADATA = "Microsoft.DocumentDB/databaseAccounts/readMetadata"


def _evaluate(resources: list[TerraformResource]):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _custom_role_grant(
    name: str,
    role_guid: str,
    data_actions: list[str],
    *,
    scope: str = "/",
    principal_id: str = _SYSTEM_PRINCIPAL_ID,
) -> list[TerraformResource]:
    role_definition_id = f"{_ACCOUNT_ID}/sqlRoleDefinitions/{role_guid}"
    return [
        _resource(
            AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION,
            name,
            {
                "id": role_definition_id,
                "role_definition_id": role_guid,
                "name": name,
                "type": "CustomRole",
                "resource_group_name": "data",
                "account_name": "orders",
                "assignable_scopes": [_ACCOUNT_ID],
                "permissions": [{"data_actions": data_actions}],
            },
        ),
        _resource(
            AzureResourceType.COSMOSDB_SQL_ROLE_ASSIGNMENT,
            name,
            {
                "id": f"{_ACCOUNT_ID}/sqlRoleAssignments/{name}",
                "name": name,
                "resource_group_name": "data",
                "account_name": "orders",
                "principal_id": principal_id,
                "role_definition_id": role_definition_id,
                "scope": scope,
            },
        ),
    ]


def _mixed_identity_web_app() -> TerraformResource:
    app = _web_app()
    app.values["identity"] = [
        {
            "type": "SystemAssigned, UserAssigned",
            "principal_id": _SYSTEM_PRINCIPAL_ID,
            "tenant_id": "tenant-id",
            "identity_ids": ["azurerm_user_assigned_identity.orders_runtime.id"],
        }
    ]
    return app


def _database_named(name: str) -> TerraformResource:
    return _resource(
        AzureResourceType.COSMOSDB_SQL_DATABASE,
        name,
        {
            "id": f"{_ACCOUNT_ID}/sqlDatabases/{name}",
            "name": name,
            "resource_group_name": "data",
            "account_name": "orders",
        },
    )


class AzurePublicAppServiceCosmosDbReadRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_public_system_identity_reader_preserves_account_scope(self) -> None:
        findings = _evaluate(
            [
                _account(),
                _public(_web_app()),
                _native_assignment(role_definition_id=_READER_ROLE_ID),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.INFORMATION_DISCLOSURE)
        self.assertEqual(
            finding.affected_resources,
            [
                "azurerm_linux_web_app.orders",
                "azurerm_cosmosdb_account.orders",
                "azurerm_cosmosdb_sql_role_assignment.workload",
            ],
        )
        reasoning = finding.severity_reasoning
        assert reasoning is not None
        self.assertEqual(reasoning.blast_radius, 3)
        self.assertEqual(reasoning.privilege_breadth, 1)
        self.assertEqual(reasoning.data_sensitivity, 2)
        self.assertIn("account-scoped grant", finding.rationale)
        self.assertIn("read specific item data", finding.rationale)
        self.assertIn("execute queries with the required change-feed permission", finding.rationale)
        self.assertIn("read the container change feed", finding.rationale)

        evidence = _evidence(finding)
        self.assertIn("public_network_access_enabled=true", evidence["public_endpoint"])
        self.assertTrue(
            any(
                f"principal_id={_SYSTEM_PRINCIPAL_ID}" in value and "role_kind=built_in_data_reader" in value
                for value in evidence["runtime_identity"]
            )
        )
        path_evidence = evidence["cosmosdb_read_paths"][0]
        self.assertIn("target_address=azurerm_cosmosdb_account.orders", path_evidence)
        self.assertIn("read_capabilities=point_read,query,change_feed_read", path_evidence)
        self.assertIn("scope_type=account", path_evidence)
        self.assertIn("resource_scope=exact_cosmosdb_for_nosql_account", path_evidence)
        self.assertIn("items_unmask_modifier=false", path_evidence)
        self.assertIn(
            "account_scoped_grants=1; database_scoped_grants=0; "
            "container_scoped_grants=0; broadest_scope=account; blast_radius_factor=3",
            evidence["scope_breadth"],
        )
        self.assertIn(
            "query_semantics=executeQuery establishes query retrieval only when readChangeFeed is also granted",
            evidence["assessment_scope"],
        )

    def test_public_function_item_read_preserves_database_scope(self) -> None:
        findings = _evaluate(
            [
                _account(),
                _database(),
                _user_assigned_identity(),
                _public(_function_app()),
                _custom_role(
                    data_actions=[_ITEM_READ],
                    assignable_scopes=[f"{_ACCOUNT_ID}/dbs/app"],
                ),
                _native_assignment(
                    principal_id=_USER_PRINCIPAL_ID,
                    role_definition_id=_CUSTOM_ROLE_ID,
                    scope="/dbs/app",
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        reasoning = finding.severity_reasoning
        assert reasoning is not None
        self.assertEqual(reasoning.blast_radius, 2)
        self.assertEqual(reasoning.data_sensitivity, 2)
        self.assertIn("database-scoped", finding.rationale)
        self.assertIn(
            "azurerm_user_assigned_identity.orders_runtime",
            finding.affected_resources,
        )
        path_evidence = _evidence(finding)["cosmosdb_read_paths"][0]
        self.assertIn("target_address=azurerm_cosmosdb_sql_database.app", path_evidence)
        self.assertIn("database_address=azurerm_cosmosdb_sql_database.app", path_evidence)
        self.assertIn("container_address=not_applicable", path_evidence)
        self.assertIn("read_capabilities=point_read", path_evidence)
        self.assertIn("scope_type=database", path_evidence)

    def test_change_feed_alone_is_retrieval_without_query_capability(self) -> None:
        findings = _evaluate(
            [
                _account(),
                _database(),
                _container(),
                _public(_web_app()),
                _custom_role(
                    data_actions=[_READ_CHANGE_FEED],
                    assignable_scopes=[f"{_ACCOUNT_ID}/dbs/app/colls/events"],
                ),
                _native_assignment(
                    role_definition_id=_CUSTOM_ROLE_ID,
                    scope="/dbs/app/colls/events",
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        reasoning = finding.severity_reasoning
        assert reasoning is not None
        self.assertEqual(reasoning.blast_radius, 1)
        self.assertIn("limited to exact container scopes", finding.rationale)
        self.assertIn("read the container change feed", finding.rationale)
        self.assertNotIn("execute queries", finding.rationale)
        path_evidence = _evidence(finding)["cosmosdb_read_paths"][0]
        self.assertIn("read_capabilities=change_feed_read", path_evidence)
        self.assertNotIn("read_capabilities=query", path_evidence)
        self.assertIn("scope_type=container", path_evidence)

    def test_query_capability_requires_execute_query_and_change_feed(self) -> None:
        execute_only = _evaluate(
            [
                _account(),
                _public(_web_app()),
                _custom_role(data_actions=[_EXECUTE_QUERY]),
                _native_assignment(role_definition_id=_CUSTOM_ROLE_ID),
            ]
        )
        paired = _evaluate(
            [
                _account(),
                _public(_web_app()),
                _custom_role(data_actions=[_EXECUTE_QUERY, _READ_CHANGE_FEED]),
                _native_assignment(role_definition_id=_CUSTOM_ROLE_ID),
            ]
        )

        self.assertEqual(execute_only, [])
        self.assertEqual([finding.rule_id for finding in paired], [_RULE_ID])
        path_evidence = _evidence(paired[0])["cosmosdb_read_paths"][0]
        self.assertIn("read_capabilities=query,change_feed_read", path_evidence)
        self.assertIn(_EXECUTE_QUERY.lower(), path_evidence.lower())
        self.assertIn(_READ_CHANGE_FEED.lower(), path_evidence.lower())

    def test_query_capability_combines_overlapping_role_assignments(self) -> None:
        findings = _evaluate(
            [
                _account(),
                _public(_web_app()),
                *_custom_role_grant(
                    "query",
                    "22222222-2222-2222-2222-222222222222",
                    [_EXECUTE_QUERY],
                ),
                *_custom_role_grant(
                    "change_feed",
                    "33333333-3333-3333-3333-333333333333",
                    [_READ_CHANGE_FEED],
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertIn(
            "execute queries with the required change-feed permission",
            finding.rationale,
        )
        evidence = _evidence(finding)
        self.assertEqual(len(evidence["cosmosdb_read_paths"]), 2)
        self.assertTrue(
            any(
                "read_capabilities=none" in value and _EXECUTE_QUERY.lower() in value.lower()
                for value in evidence["cosmosdb_read_paths"]
            )
        )
        self.assertIn(
            "read_capabilities=query,change_feed_read",
            evidence["capability_profile"][0],
        )

    def test_query_components_do_not_combine_across_runtime_identities(self) -> None:
        findings = _evaluate(
            [
                _account(),
                _user_assigned_identity(),
                _public(_mixed_identity_web_app()),
                *_custom_role_grant(
                    "query",
                    "88888888-8888-8888-8888-888888888888",
                    [_EXECUTE_QUERY],
                ),
                *_custom_role_grant(
                    "change_feed",
                    "99999999-9999-9999-9999-999999999999",
                    [_READ_CHANGE_FEED],
                    principal_id=_USER_PRINCIPAL_ID,
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertIn("read the container change feed", finding.rationale)
        self.assertNotIn("execute queries", finding.rationale)
        evidence = _evidence(finding)
        self.assertEqual(len(evidence["cosmosdb_read_paths"]), 1)
        self.assertIn(
            f"principal_id={_USER_PRINCIPAL_ID}",
            evidence["runtime_identity"][0],
        )
        self.assertIn(
            "read_capabilities=change_feed_read",
            evidence["capability_profile"][0],
        )

    def test_query_components_do_not_combine_across_unrelated_databases(self) -> None:
        findings = _evaluate(
            [
                _account(),
                _database(),
                _database_named("other"),
                _public(_web_app()),
                *_custom_role_grant(
                    "query",
                    "66666666-6666-6666-6666-666666666666",
                    [_EXECUTE_QUERY],
                    scope="/dbs/app",
                ),
                *_custom_role_grant(
                    "change_feed",
                    "77777777-7777-7777-7777-777777777777",
                    [_READ_CHANGE_FEED],
                    scope="/dbs/other",
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertIn("read the container change feed", finding.rationale)
        self.assertNotIn("execute queries", finding.rationale)
        evidence = _evidence(finding)
        self.assertEqual(len(evidence["cosmosdb_read_paths"]), 1)
        self.assertIn(
            "target_address=azurerm_cosmosdb_sql_database.other",
            evidence["cosmosdb_read_paths"][0],
        )
        self.assertIn(
            "read_capabilities=change_feed_read",
            evidence["capability_profile"][0],
        )

    def test_unmask_does_not_modify_reads_from_another_runtime_identity(self) -> None:
        findings = _evaluate(
            [
                _account(),
                _user_assigned_identity(),
                _public(_mixed_identity_web_app()),
                *_custom_role_grant(
                    "read",
                    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                    [_ITEM_READ],
                ),
                *_custom_role_grant(
                    "unmask",
                    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                    [_ITEM_UNMASK],
                    principal_id=_USER_PRINCIPAL_ID,
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        reasoning = finding.severity_reasoning
        assert reasoning is not None
        self.assertEqual(reasoning.data_sensitivity, 2)
        self.assertNotIn("items/unmask", finding.rationale)
        evidence = _evidence(finding)
        self.assertEqual(len(evidence["cosmosdb_read_paths"]), 1)
        self.assertIn(
            f"principal_id={_SYSTEM_PRINCIPAL_ID}",
            evidence["runtime_identity"][0],
        )
        self.assertIn(
            "items_unmask_modifier=false",
            evidence["capability_profile"][0],
        )

    def test_unmask_modifies_severity_only_when_retrieval_exists(self) -> None:
        unmask_only = _evaluate(
            [
                _account(),
                _public(_web_app()),
                _custom_role(data_actions=[_ITEM_UNMASK]),
                _native_assignment(role_definition_id=_CUSTOM_ROLE_ID),
            ]
        )
        read_and_unmask = _evaluate(
            [
                _account(),
                _public(_web_app()),
                _custom_role(data_actions=[_ITEM_READ, _ITEM_UNMASK]),
                _native_assignment(role_definition_id=_CUSTOM_ROLE_ID),
            ]
        )

        self.assertEqual(unmask_only, [])
        self.assertEqual([finding.rule_id for finding in read_and_unmask], [_RULE_ID])
        finding = read_and_unmask[0]
        reasoning = finding.severity_reasoning
        assert reasoning is not None
        self.assertEqual(reasoning.data_sensitivity, 3)
        self.assertIn("items/unmask", finding.rationale)
        self.assertIn("does not independently establish retrieval authority", finding.rationale)
        self.assertIn(
            "items_unmask_modifier=true",
            _evidence(finding)["cosmosdb_read_paths"][0],
        )

    def test_unmask_modifier_combines_with_overlapping_read_assignment(self) -> None:
        findings = _evaluate(
            [
                _account(),
                _public(_web_app()),
                *_custom_role_grant(
                    "read",
                    "44444444-4444-4444-4444-444444444444",
                    [_ITEM_READ],
                ),
                *_custom_role_grant(
                    "unmask",
                    "55555555-5555-5555-5555-555555555555",
                    [_ITEM_UNMASK],
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        reasoning = finding.severity_reasoning
        assert reasoning is not None
        self.assertEqual(reasoning.data_sensitivity, 3)
        self.assertIn(
            "items_unmask_modifier=true",
            _evidence(finding)["capability_profile"][0],
        )

    def test_contributor_wildcards_expand_read_and_unmask_actions(self) -> None:
        findings = _evaluate(
            [
                _account(),
                _public(_web_app()),
                _native_assignment(role_definition_id=_CONTRIBUTOR_ROLE_ID),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        reasoning = finding.severity_reasoning
        assert reasoning is not None
        self.assertEqual(reasoning.data_sensitivity, 3)
        path_evidence = _evidence(finding)["cosmosdb_read_paths"][0]
        self.assertIn("read_capabilities=point_read,query,change_feed_read", path_evidence)
        self.assertIn("items_unmask_modifier=true", path_evidence)

    def test_metadata_private_unknown_and_ordinary_rbac_stay_quiet(self) -> None:
        metadata_only = _evaluate(
            [
                _account(),
                _public(_web_app()),
                _custom_role(data_actions=[_READ_METADATA]),
                _native_assignment(role_definition_id=_CUSTOM_ROLE_ID),
            ]
        )
        private = _evaluate(
            [
                _account(),
                _web_app(),
                _native_assignment(role_definition_id=_READER_ROLE_ID),
            ]
        )
        unknown_app = _web_app()
        unknown_app.values["public_network_access_enabled"] = None
        unknown_app.unknown_values["public_network_access_enabled"] = True
        unknown = _evaluate(
            [
                _account(),
                unknown_app,
                _native_assignment(role_definition_id=_READER_ROLE_ID),
            ]
        )
        ordinary = _evaluate(
            [
                _account(),
                _public(_web_app()),
                _ordinary_role_assignment(),
            ]
        )

        self.assertEqual(metadata_only, [])
        self.assertEqual(private, [])
        self.assertEqual(unknown, [])
        self.assertEqual(ordinary, [])


if __name__ == "__main__":
    unittest.main()

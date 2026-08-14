from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _ACCOUNT_ID,
    _CONTAINER_WILDCARD,
    _CUSTOM_ROLE_ID,
    _ITEM_CREATE,
    _ITEM_DELETE,
    _ITEM_WILDCARD,
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
    _user_assigned_identity,
    _web_app,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_RULE_ID = "azure-public-app-service-cosmosdb-mutation-access"


def _public(resource: TerraformResource) -> TerraformResource:
    resource.values["public_network_access_enabled"] = True
    return resource


def _evaluate(resources: list[TerraformResource]):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class AzurePublicAppServiceCosmosDbMutationRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_public_system_identity_contributor_expands_account_wildcards(self) -> None:
        findings = _evaluate([_account(), _public(_web_app()), _native_assignment()])

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertIn("account-scoped grant", finding.rationale)
        self.assertIn(
            "Cosmos DB for NoSQL account, database, or container is itself public",
            finding.rationale,
        )
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

        evidence = _evidence(finding)
        self.assertIn("public_network_access_enabled=true", evidence["public_endpoint"])
        self.assertTrue(
            any(
                f"principal_id={_SYSTEM_PRINCIPAL_ID}" in value and "role_kind=built_in_data_contributor" in value
                for value in evidence["runtime_identity"]
            )
        )
        self.assertTrue(
            any(
                "target_address=azurerm_cosmosdb_account.orders" in value
                and "mutation_operations=create,update" in value
                and "scope_type=account" in value
                and "resource_scope=exact_cosmosdb_for_nosql_account" in value
                for value in evidence["cosmosdb_mutation_paths"]
            )
        )
        self.assertIn(
            "account_scoped_grants=1; database_scoped_grants=0; "
            "container_scoped_grants=0; broadest_scope=account; blast_radius_factor=3",
            evidence["scope_breadth"],
        )
        self.assertNotIn("custom_role_actions", evidence)

    def test_public_function_custom_database_write_preserves_database_scope(self) -> None:
        findings = _evaluate(
            [
                _account(),
                _database(),
                _user_assigned_identity(),
                _public(_function_app()),
                _custom_role(
                    data_actions=[_ITEM_CREATE],
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
        self.assertEqual(reasoning.privilege_breadth, 1)
        self.assertIn("database-scoped", finding.rationale)
        self.assertIn(
            "do not establish item read access or information disclosure",
            finding.rationale,
        )
        self.assertIn(
            "azurerm_user_assigned_identity.orders_runtime",
            finding.affected_resources,
        )
        evidence = _evidence(finding)
        self.assertTrue(
            any(
                f"principal_id={_USER_PRINCIPAL_ID}" in value and "identity_kind=user_assigned" in value
                for value in evidence["runtime_identity"]
            )
        )
        self.assertTrue(
            any(
                "target_address=azurerm_cosmosdb_sql_database.app" in value
                and "database_address=azurerm_cosmosdb_sql_database.app" in value
                and "container_address=not_applicable" in value
                and "scope_type=database" in value
                for value in evidence["cosmosdb_mutation_paths"]
            )
        )
        self.assertTrue(
            any(
                "role_definition_address=azurerm_cosmosdb_sql_role_definition.workload" in value
                and _ITEM_CREATE.lower() in value.lower()
                for value in evidence["custom_role_actions"]
            )
        )

    def test_public_custom_container_delete_stays_out_of_tampering(self) -> None:
        findings = _evaluate(
            [
                _account(),
                _database(),
                _container(),
                _public(_web_app()),
                _custom_role(
                    data_actions=[_ITEM_DELETE],
                    assignable_scopes=[f"{_ACCOUNT_ID}/dbs/app/colls/events"],
                ),
                _native_assignment(
                    role_definition_id=_CUSTOM_ROLE_ID,
                    scope="/dbs/app/colls/events",
                ),
            ]
        )

        self.assertEqual(findings, [])

    def test_item_wildcard_expands_but_container_wildcard_stays_quiet(self) -> None:
        item_findings = _evaluate(
            [
                _account(),
                _database(),
                _container(),
                _public(_web_app()),
                _custom_role(data_actions=[_ITEM_WILDCARD]),
                _native_assignment(
                    role_definition_id=_CUSTOM_ROLE_ID,
                    scope="/dbs/app/colls/events",
                ),
            ]
        )
        container_findings = _evaluate(
            [
                _account(),
                _database(),
                _container(),
                _public(_web_app()),
                _custom_role(data_actions=[_CONTAINER_WILDCARD]),
                _native_assignment(
                    role_definition_id=_CUSTOM_ROLE_ID,
                    scope="/dbs/app/colls/events",
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in item_findings], [_RULE_ID])
        evidence = _evidence(item_findings[0])
        self.assertTrue(
            any("mutation_operations=create,update" in value for value in evidence["cosmosdb_mutation_paths"])
        )
        self.assertEqual(container_findings, [])

    def test_reader_private_unknown_and_ordinary_rbac_stay_quiet(self) -> None:
        reader = _evaluate(
            [
                _account(),
                _database(),
                _container(),
                _public(_web_app()),
                _native_assignment(
                    role_definition_id=_READER_ROLE_ID,
                    scope="/dbs/app/colls/events",
                ),
            ]
        )
        private = _evaluate([_account(), _web_app(), _native_assignment()])

        unknown_app = _web_app()
        unknown_app.values["public_network_access_enabled"] = None
        unknown_app.unknown_values["public_network_access_enabled"] = True
        unknown = _evaluate([_account(), unknown_app, _native_assignment()])

        ordinary = _evaluate([_account(), _public(_web_app()), _ordinary_role_assignment()])

        self.assertEqual(reader, [])
        self.assertEqual(private, [])
        self.assertEqual(unknown, [])
        self.assertEqual(ordinary, [])


if __name__ == "__main__":
    unittest.main()

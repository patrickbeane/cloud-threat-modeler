from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _ACCOUNT_ID,
    _CUSTOM_ROLE_ID,
    _ITEM_CREATE,
    _ITEM_DELETE,
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
from tests.providers.azure.test_azure_app_service_cosmosdb_item_deletion_paths import (
    _backup_account,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_RULE_ID = "azure-public-app-service-cosmosdb-item-disruption"
_MUTATION_RULE_ID = "azure-public-app-service-cosmosdb-mutation-access"


def _public(resource: TerraformResource) -> TerraformResource:
    resource.values["public_network_access_enabled"] = True
    return resource


def _evaluate(
    resources: list[TerraformResource],
    *rule_ids: str,
):
    inventory = AzureNormalizer().normalize(resources)
    findings = StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or (_RULE_ID,))),
    )
    return inventory, findings


def _evidence(finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


class AzurePublicAppServiceCosmosDbItemDisruptionRuleTests(unittest.TestCase):
    def test_rule_is_registered_as_denial_of_service(self) -> None:
        registered = {rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

        _, findings = _evaluate([_account(), _public(_web_app()), _native_assignment()])
        self.assertEqual(findings[0].category, StrideCategory.DENIAL_OF_SERVICE)

    def test_delete_only_authority_belongs_to_disruption_rule(self) -> None:
        _, findings = _evaluate(
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
            ],
            _MUTATION_RULE_ID,
            _RULE_ID,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            [
                "azurerm_linux_web_app.orders",
                "azurerm_cosmosdb_account.orders",
                "azurerm_cosmosdb_sql_database.app",
                "azurerm_cosmosdb_sql_container.events",
                "azurerm_cosmosdb_sql_role_assignment.workload",
                "azurerm_cosmosdb_sql_role_definition.workload",
            ],
        )
        reasoning = finding.severity_reasoning
        assert reasoning is not None
        self.assertEqual(reasoning.privilege_breadth, 2)
        self.assertEqual(reasoning.blast_radius, 1)

        evidence = _evidence(finding)
        self.assertTrue(
            any(
                f"operation={_ITEM_DELETE}" in value
                and "operation_class=item_deletion" in value
                and "target_granularity=container_item_namespace" in value
                and "target_scope=exact_cosmosdb_for_nosql_container" in value
                and "matched_data_actions=" + _ITEM_DELETE in value
                and "scope_type=container" in value
                for value in evidence["cosmosdb_item_deletion_paths"]
            )
        )
        assessment = " ".join(evidence["assessment_scope"])
        self.assertIn("specific item identities", assessment)
        self.assertIn("irreversible loss", assessment)
        self.assertNotIn("successful deletion", finding.rationale.lower())

    def test_broad_contributor_emits_tampering_and_disruption(self) -> None:
        _, findings = _evaluate(
            [_account(), _public(_web_app()), _native_assignment()],
            _MUTATION_RULE_ID,
            _RULE_ID,
        )

        self.assertEqual(
            {finding.rule_id for finding in findings},
            {_MUTATION_RULE_ID, _RULE_ID},
        )

    def test_native_scope_controls_blast_radius(self) -> None:
        cases = (
            (
                "account",
                [_account(), _public(_web_app()), _native_assignment()],
                3,
                "account_item_namespace",
            ),
            (
                "database",
                [
                    _account(),
                    _database(),
                    _public(_web_app()),
                    _custom_role(
                        data_actions=[_ITEM_DELETE],
                        assignable_scopes=[f"{_ACCOUNT_ID}/dbs/app"],
                    ),
                    _native_assignment(
                        role_definition_id=_CUSTOM_ROLE_ID,
                        scope="/dbs/app",
                    ),
                ],
                2,
                "database_item_namespace",
            ),
            (
                "container",
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
                ],
                1,
                "container_item_namespace",
            ),
        )

        for scope, resources, expected_blast, granularity in cases:
            with self.subTest(scope=scope):
                _, findings = _evaluate(resources)
                self.assertEqual(len(findings), 1)
                reasoning = findings[0].severity_reasoning
                assert reasoning is not None
                self.assertEqual(reasoning.blast_radius, expected_blast)
                evidence = _evidence(findings[0])
                self.assertTrue(
                    any(
                        f"scope_type={scope}" in value and f"target_granularity={granularity}" in value
                        for value in evidence["cosmosdb_item_deletion_paths"]
                    )
                )

    def test_backup_posture_is_operation_specific_plan_local_evidence(
        self,
    ) -> None:
        cases = (
            (
                "continuous",
                _backup_account(
                    backup_type="Continuous",
                    backup_tier="Continuous30Days",
                ),
                (
                    "recovery_state=continuous_backup_configured",
                    "backup_tier=Continuous30Days",
                    "backup_interval_minutes=not_applicable",
                    "backup_retention_hours=not_applicable",
                    "backup_storage_redundancy=not_applicable",
                ),
            ),
            (
                "periodic",
                _backup_account(
                    backup_type="Periodic",
                    interval_minutes=240,
                    retention_hours=168,
                    storage_redundancy="Geo",
                ),
                (
                    "recovery_state=periodic_backup_configured",
                    "backup_tier=not_applicable",
                    "backup_interval_minutes=240",
                    "backup_retention_hours=168",
                    "backup_storage_redundancy=Geo",
                ),
            ),
            (
                "provider_default",
                _backup_account(),
                (
                    "recovery_state=provider_default_periodic_backup",
                    "backup_tier=not_applicable",
                    "backup_interval_minutes=240",
                    "backup_retention_hours=8",
                    "backup_storage_redundancy=Geo",
                ),
            ),
            (
                "unknown",
                _backup_account(unknown_backup=True),
                (
                    "recovery_state=recovery_posture_unknown",
                    "backup_tier=unknown",
                    "backup_interval_minutes=unknown",
                    "backup_retention_hours=unknown",
                    "backup_storage_redundancy=unknown",
                ),
            ),
        )

        for case, account, expected_fragments in cases:
            with self.subTest(case=case):
                _, findings = _evaluate([account, _public(_web_app()), _native_assignment()])
                self.assertEqual(len(findings), 1)
                evidence = _evidence(findings[0])
                self.assertTrue(
                    any(
                        all(fragment in value for fragment in expected_fragments)
                        and "successful_restore_established=false" in value
                        and "irreversible_loss_established=false" in value
                        for value in evidence["recovery_posture"]
                    )
                )
                if case == "unknown":
                    self.assertTrue(evidence["cosmosdb_item_deletion_path_uncertainties"])

    def test_private_workload_retains_path_without_a_finding(self) -> None:
        inventory, findings = _evaluate([_account(), _web_app(), _native_assignment()])

        app = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert app is not None
        self.assertEqual(
            len(azure_facts(app).app_service_cosmosdb_item_deletion_paths),
            1,
        )
        self.assertEqual(findings, [])

    def test_stale_copied_operation_source_and_recovery_are_rejected(
        self,
    ) -> None:
        for stale_kind in ("operation", "source", "recovery"):
            with self.subTest(stale_kind=stale_kind):
                inventory, _ = _evaluate([_account(), _public(_web_app()), _native_assignment()])
                app = inventory.get_by_address("azurerm_linux_web_app.orders")
                assert app is not None
                facts = azure_facts(app)
                if stale_kind == "source":
                    facts.set_app_service_cosmosdb_access_paths([])
                else:
                    path = dict(facts.app_service_cosmosdb_item_deletion_paths[0])
                    if stale_kind == "operation":
                        path["matched_data_actions"] = [
                            _ITEM_DELETE,
                            _ITEM_DELETE,
                        ]
                    else:
                        recovery = dict(path["recovery_evidence"])
                        recovery["backup_retention_hours"] = 999
                        path["recovery_evidence"] = recovery
                    facts.set_app_service_cosmosdb_item_deletion_paths([path])

                findings = StrideRuleEngine().evaluate(
                    inventory,
                    [],
                    rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
                )
                self.assertEqual(findings, [])

    def test_detached_user_assigned_identity_invalidates_copied_path(
        self,
    ) -> None:
        inventory, findings = _evaluate(
            [
                _account(),
                _database(),
                _container(),
                _user_assigned_identity(),
                _public(_function_app()),
                _custom_role(
                    data_actions=[_ITEM_CREATE, _ITEM_DELETE],
                    assignable_scopes=[f"{_ACCOUNT_ID}/dbs/app/colls/events"],
                ),
                _native_assignment(
                    principal_id=_USER_PRINCIPAL_ID,
                    role_definition_id=_CUSTOM_ROLE_ID,
                    scope="/dbs/app/colls/events",
                ),
            ]
        )
        self.assertEqual(len(findings), 1)

        app = inventory.get_by_address("azurerm_linux_function_app.orders_worker")
        assert app is not None
        facts = azure_facts(app)
        facts.set(
            AzureResourceMetadata.RESOLVED_ATTACHED_IDENTITY_ADDRESSES,
            [],
        )
        facts.set(AzureResourceMetadata.ATTACHED_IDENTITY_REFERENCES, [])

        stale_findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
        )
        self.assertEqual(stale_findings, [])


if __name__ == "__main__":
    unittest.main()

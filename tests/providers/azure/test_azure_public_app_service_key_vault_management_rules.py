from __future__ import annotations

import unittest
from typing import Any

from tests.providers.azure.test_azure_app_service_key_vault_management_paths import (
    _CRYPTO_OFFICER_ID,
    _control_assignment,
    _control_role,
    _crypto_officer_assignment,
    _resource,
    _vault_with_recovery,
)
from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _KEY_URI,
    _KEY_VERSIONLESS_URI,
    _key,
    _web_app,
)
from tests.providers.azure.test_azure_public_app_service_storage_mutation_rules import _public
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_DISRUPTION_RULE = "azure-public-app-service-key-vault-key-disruption"
_DELEGATION_RULE = "azure-public-app-service-key-vault-authorization-delegation"


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence(finding: Any) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


class AzurePublicAppServiceKeyVaultManagementRuleTests(unittest.TestCase):
    def test_rules_are_registered(self) -> None:
        registered = {rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_DISRUPTION_RULE, registered)
        self.assertIn(_DELEGATION_RULE, registered)

    def test_public_data_plane_lifecycle_authority_emits_disruption(self) -> None:
        findings = _evaluate(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _public(_web_app()),
                _crypto_officer_assignment(scope="/subscriptions/sub-0001"),
            ],
            _DISRUPTION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DISRUPTION_RULE])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.DENIAL_OF_SERVICE)
        self.assertIn("key update, key deletion, and key deletion and purge", finding.rationale)
        self.assertIn("out-of-plan keys are not modeled", finding.rationale)
        evidence = _evidence(finding)
        self.assertIn("public_network_access_enabled=true", evidence["public_endpoint"])
        self.assertTrue(
            any(
                "operation=delete_plus_purge" in value
                and "authorization_basis=key_vault_data_plane_grant" in value
                and "scope_types=subscription" in value
                for value in evidence["key_vault_management_paths"]
            )
        )
        self.assertTrue(
            any(
                "establishes=deterministic key update, key deletion, and key deletion and purge authority" in value
                for value in evidence["authorization_scope"]
            )
        )
        self.assertIn(
            "subscription_grants=1; resource_group_grants=0; vault_grants=0; exact_key_grants=0; "
            "target_paths=3; modeled_targets=1; modeled_keys=1; broadest_scope=subscription; "
            "out_of_plan_keys_not_modeled=true; blast_radius_basis=parent_scope_grant",
            evidence["scope_breadth"],
        )

    def test_disruption_enriches_exact_downstream_dependents_and_scope_evidence(self) -> None:
        def storage_values(name: str) -> dict[str, object]:
            return {
                "id": (
                    f"/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/{name}"
                ),
                "name": name,
                "customer_managed_key": [{"key_vault_key_id": _KEY_URI}],
            }

        findings = _evaluate(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _public(_web_app()),
                _crypto_officer_assignment(scope="/subscriptions/sub-0001"),
                _resource(AzureResourceType.STORAGE_ACCOUNT, "data", storage_values("data")),
                _resource(AzureResourceType.STORAGE_ACCOUNT, "audit", storage_values("audit")),
            ],
            _DISRUPTION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DISRUPTION_RULE])
        finding = findings[0]
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)
        self.assertIn("azurerm_storage_account.data", finding.affected_resources)
        self.assertIn("azurerm_storage_account.audit", finding.affected_resources)
        evidence = _evidence(finding)
        self.assertIn(
            "unique_dependency_count=2; unique_dependent_resource_count=2; "
            "blast_radius_basis=downstream_encrypted_dependents",
            evidence["downstream_dependencies"],
        )
        self.assertTrue(
            any(
                "dependent_address=azurerm_storage_account.data" in value
                and "configuration_path=['customer_managed_key', 0, 'key_vault_key_id']" in value
                for value in evidence["downstream_dependencies"]
            )
        )
        self.assertIn(
            "subscription_grants=1; resource_group_grants=0; vault_grants=0; exact_key_grants=0; ",
            evidence["scope_breadth"][0],
        )

    def test_update_only_projects_only_matching_versioned_dependencies(self) -> None:
        def storage(name: str, reference: str) -> TerraformResource:
            return _resource(
                AzureResourceType.STORAGE_ACCOUNT,
                name,
                {
                    "id": (
                        f"/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/{name}"
                    ),
                    "name": name,
                    "customer_managed_key": [{"key_vault_key_id": reference}],
                },
            )

        inventory = AzureNormalizer().normalize(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _public(_web_app()),
                _crypto_officer_assignment(),
                storage("versionless", _KEY_VERSIONLESS_URI),
                storage("versioned", _KEY_URI),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None
        workload_facts = azure_facts(workload)
        workload_facts.set_app_service_key_vault_management_paths(
            [path for path in workload_facts.app_service_key_vault_management_paths if path["operation"] == "update"]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DISRUPTION_RULE})),
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DISRUPTION_RULE])
        finding = findings[0]
        self.assertNotIn("azurerm_storage_account.versionless", finding.affected_resources)
        self.assertIn("azurerm_storage_account.versioned", finding.affected_resources)
        self.assertIn(
            "unique_dependency_count=1; unique_dependent_resource_count=1; ",
            _evidence(finding)["downstream_dependencies"][0],
        )

    def test_versionless_dependency_cannot_be_reclassified_as_versioned_for_update(self) -> None:
        storage = _resource(
            AzureResourceType.STORAGE_ACCOUNT,
            "versionless",
            {
                "id": (
                    "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/versionless"
                ),
                "name": "versionless",
                "customer_managed_key": [{"key_vault_key_id": _KEY_VERSIONLESS_URI}],
            },
        )
        inventory = AzureNormalizer().normalize(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _public(_web_app()),
                _crypto_officer_assignment(),
                storage,
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        key = inventory.get_by_address("azurerm_key_vault_key.signing")
        assert workload is not None
        assert key is not None
        workload_facts = azure_facts(workload)
        workload_facts.set_app_service_key_vault_management_paths(
            [path for path in workload_facts.app_service_key_vault_management_paths if path["operation"] == "update"]
        )
        key_facts = azure_facts(key)
        dependency = dict(key_facts.key_vault_encryption_dependencies[0])
        self.assertEqual(dependency["target_kind"], "key")
        dependency["target_kind"] = "key_version"
        key_facts.set_key_vault_encryption_dependency_posture(
            dependencies=[dependency],
            uncertainties=[],
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DISRUPTION_RULE})),
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DISRUPTION_RULE])
        self.assertNotIn("azurerm_storage_account.versionless", findings[0].affected_resources)
        self.assertIn(
            "unique_dependency_count=0; unique_dependent_resource_count=0; ",
            _evidence(findings[0])["downstream_dependencies"][0],
        )

    def test_delete_only_projects_versionless_and_versioned_dependencies(self) -> None:
        def storage(name: str, reference: str) -> TerraformResource:
            return _resource(
                AzureResourceType.STORAGE_ACCOUNT,
                name,
                {
                    "id": (
                        f"/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/{name}"
                    ),
                    "name": name,
                    "customer_managed_key": [{"key_vault_key_id": reference}],
                },
            )

        inventory = AzureNormalizer().normalize(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _public(_web_app()),
                _crypto_officer_assignment(),
                storage("versionless", _KEY_VERSIONLESS_URI),
                storage("versioned", _KEY_URI),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None
        workload_facts = azure_facts(workload)
        workload_facts.set_app_service_key_vault_management_paths(
            [path for path in workload_facts.app_service_key_vault_management_paths if path["operation"] == "delete"]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DISRUPTION_RULE})),
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DISRUPTION_RULE])
        affected = findings[0].affected_resources
        self.assertIn("azurerm_storage_account.versionless", affected)
        self.assertIn("azurerm_storage_account.versioned", affected)
        self.assertIn(
            "unique_dependency_count=2; unique_dependent_resource_count=2; ",
            _evidence(findings[0])["downstream_dependencies"][0],
        )

    def test_stale_permanent_delete_path_is_rejected_against_current_vault(self) -> None:
        unprotected_inventory = AzureNormalizer().normalize(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _public(_web_app()),
                _crypto_officer_assignment(),
            ]
        )
        unprotected_workload = unprotected_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert unprotected_workload is not None
        stale_path = next(
            dict(path)
            for path in azure_facts(unprotected_workload).app_service_key_vault_management_paths
            if path["operation"] == "delete_plus_purge"
        )

        inventory = AzureNormalizer().normalize(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=True),
                _key(key_opts=("encrypt",)),
                _public(_web_app()),
                _crypto_officer_assignment(),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None
        workload_facts = azure_facts(workload)
        paths = [dict(path) for path in workload_facts.app_service_key_vault_management_paths]
        paths.append(stale_path)
        workload_facts.set_app_service_key_vault_management_paths(paths)

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DISRUPTION_RULE})),
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DISRUPTION_RULE])
        evidence = _evidence(findings[0])
        self.assertTrue(any("operation=delete" in value for value in evidence["recovery_posture"]))
        self.assertFalse(any("operation=delete_plus_purge" in value for value in evidence["recovery_posture"]))
        self.assertFalse(
            any("operation=delete_plus_purge" in value for value in evidence["key_vault_management_paths"])
        )

    def test_recovery_evidence_preserves_delete_and_delete_plus_purge(self) -> None:
        findings = _evaluate(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _public(_web_app()),
                _crypto_officer_assignment(),
            ],
            _DISRUPTION_RULE,
        )

        recovery = _evidence(findings[0])["recovery_posture"]
        self.assertTrue(
            any("operation=delete" in value and "recovery_state=recoverable_soft_delete" in value for value in recovery)
        )
        self.assertTrue(
            any(
                "operation=delete_plus_purge" in value
                and "purge_protection_enabled=False" in value
                and "recovery_state=permanent_delete_sequence" in value
                for value in recovery
            )
        )
        self.assertFalse(any("operation=update" in value for value in recovery))

    def test_stale_downstream_dependency_record_does_not_enlarge_finding(self) -> None:
        storage = _resource(
            AzureResourceType.STORAGE_ACCOUNT,
            "data",
            {
                "id": ("/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/data"),
                "name": "data",
                "customer_managed_key": [{"key_vault_key_id": _KEY_URI}],
            },
        )
        inventory = AzureNormalizer().normalize(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _public(_web_app()),
                _crypto_officer_assignment(),
                storage,
            ]
        )
        key = inventory.get_by_address("azurerm_key_vault_key.signing")
        assert key is not None
        key_facts = azure_facts(key)
        dependency = dict(key_facts.key_vault_encryption_dependencies[0])
        dependency["dependent_address"] = "azurerm_storage_account.missing"
        dependency["dependent_resource_type"] = AzureResourceType.STORAGE_ACCOUNT
        key_facts.set_key_vault_encryption_dependency_posture(
            dependencies=[dependency],
            uncertainties=[],
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DISRUPTION_RULE})),
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DISRUPTION_RULE])
        evidence = _evidence(findings[0])
        self.assertIn(
            "unique_dependency_count=0; unique_dependent_resource_count=0; "
            "blast_radius_basis=no_resolved_downstream_dependents",
            evidence["downstream_dependencies"],
        )
        self.assertNotIn("azurerm_storage_account.missing", findings[0].affected_resources)

    def test_dependency_without_singleton_target_identity_is_not_projected(self) -> None:
        storage = _resource(
            AzureResourceType.STORAGE_ACCOUNT,
            "data",
            {
                "id": ("/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/data"),
                "name": "data",
                "customer_managed_key": [{"key_vault_key_id": _KEY_URI}],
            },
        )
        inventory = AzureNormalizer().normalize(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _public(_web_app()),
                _crypto_officer_assignment(),
                storage,
            ]
        )
        key = inventory.get_by_address("azurerm_key_vault_key.signing")
        assert key is not None
        key_facts = azure_facts(key)
        dependency = dict(key_facts.key_vault_encryption_dependencies[0])
        dependency["candidate_key_addresses"] = []
        dependency["target_kind"] = None
        dependency["key_uri"] = None
        dependency["key_resource_id"] = None
        dependency["key_version"] = None
        dependency["key_versionless_uri"] = None
        dependency["key_versionless_resource_id"] = None
        key_facts.set_key_vault_encryption_dependency_posture(
            dependencies=[dependency],
            uncertainties=[],
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DISRUPTION_RULE})),
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DISRUPTION_RULE])
        self.assertNotIn("azurerm_storage_account.data", findings[0].affected_resources)
        self.assertIn(
            "unique_dependency_count=0; unique_dependent_resource_count=0; ",
            _evidence(findings[0])["downstream_dependencies"][0],
        )

    def test_mixed_grant_scopes_are_counted_by_native_scope(self) -> None:
        findings = _evaluate(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _public(_web_app()),
                _crypto_officer_assignment(scope="/subscriptions/sub-0001"),
                _resource(
                    AzureResourceType.ROLE_ASSIGNMENT,
                    "exact_key_access",
                    {
                        "scope": "azurerm_key_vault_key.signing.resource_versionless_id",
                        "role_definition_id": f"/providers/Microsoft.Authorization/roleDefinitions/{_CRYPTO_OFFICER_ID}",
                        "role_definition_name": "Key Vault Crypto Officer",
                        "principal_id": "app-system-principal-id",
                        "principal_type": "ServicePrincipal",
                    },
                ),
            ],
            _DISRUPTION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DISRUPTION_RULE])
        self.assertIn(
            "subscription_grants=1; resource_group_grants=0; vault_grants=0; exact_key_grants=1; ",
            _evidence(findings[0])["scope_breadth"][0],
        )

    def test_recoverable_delete_is_distinguished_from_permanent_delete(self) -> None:
        findings = _evaluate(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=True),
                _key(key_opts=("encrypt",)),
                _public(_web_app()),
                _crypto_officer_assignment(),
            ],
            _DISRUPTION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DISRUPTION_RULE])
        finding = findings[0]
        paths = _evidence(finding)["key_vault_management_paths"]
        self.assertTrue(
            any("operation=delete" in value and "deletion_impact=recoverable_soft_delete" in value for value in paths)
        )
        self.assertFalse(any("operation=delete_plus_purge" in value for value in paths))
        self.assertNotIn("irreversible", finding.rationale.lower())
        self.assertNotIn("permanent", finding.rationale.lower())

    def test_public_control_plane_rbac_authority_emits_delegation(self) -> None:
        findings = _evaluate(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _public(_web_app()),
                _control_role(actions=("Microsoft.Authorization/roleAssignments/write",)),
                _control_assignment(),
            ],
            _DELEGATION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DELEGATION_RULE])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.ELEVATION_OF_PRIVILEGE)
        self.assertIn("RBAC role-assignment management", finding.rationale)
        evidence = _evidence(finding)
        path = evidence["key_vault_management_paths"][0]
        self.assertIn("target_type=vault", path)
        self.assertIn("authorization_basis=azure_control_plane_role_assignment", path)
        self.assertIn("delegation_mechanism=azure_rbac_role_assignment", path)
        self.assertIn("scope_types=vault", path)
        self.assertTrue(
            any(
                "matched_actions=Microsoft.Authorization/roleAssignments/write" in value
                for value in evidence["key_vault_management_paths"]
            )
        )

    def test_legacy_access_policy_mutation_is_delegation_not_disruption(self) -> None:
        findings = _evaluate(
            [
                _vault_with_recovery(rbac_enabled=False, purge_protection=False),
                _public(_web_app()),
                _control_role(actions=("Microsoft.KeyVault/vaults/accessPolicies/write",)),
                _control_assignment(),
            ],
            _DISRUPTION_RULE,
            _DELEGATION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DELEGATION_RULE])
        self.assertIn("legacy access-policy mutation", findings[0].rationale)

    def test_rbac_to_access_policy_transition_is_delegation(self) -> None:
        findings = _evaluate(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _public(_web_app()),
                _control_role(actions=("Microsoft.KeyVault/vaults/write",)),
                _control_assignment(),
            ],
            _DELEGATION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DELEGATION_RULE])
        path = _evidence(findings[0])["key_vault_management_paths"][0]
        self.assertIn("operation=authorization_model_mutation", path)
        self.assertIn("authorization_model_transition=azure_rbac_to_access_policy", path)

    def test_data_plane_key_authority_does_not_emit_delegation(self) -> None:
        findings = _evaluate(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _public(_web_app()),
                _crypto_officer_assignment(),
            ],
            _DELEGATION_RULE,
        )
        self.assertEqual(findings, [])

    def test_control_plane_delegation_does_not_emit_disruption(self) -> None:
        findings = _evaluate(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _public(_web_app()),
                _control_role(actions=("Microsoft.Authorization/roleAssignments/write",)),
                _control_assignment(),
            ],
            _DISRUPTION_RULE,
        )
        self.assertEqual(findings, [])

    def test_malformed_disruption_sequence_does_not_emit(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _public(_web_app()),
                _crypto_officer_assignment(),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None
        facts = azure_facts(workload)
        delete_plus_purge = next(
            path for path in facts.app_service_key_vault_management_paths if path["operation"] == "delete_plus_purge"
        )
        delete_plus_purge["step_operations"] = ["delete"]
        facts.set_app_service_key_vault_management_paths([delete_plus_purge])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DISRUPTION_RULE})),
        )
        self.assertEqual(findings, [])

    def test_private_app_service_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _vault_with_recovery(rbac_enabled=True, purge_protection=False),
                _key(key_opts=("encrypt",)),
                _web_app(),
                _crypto_officer_assignment(),
                _control_role(actions=("Microsoft.Authorization/roleAssignments/write",)),
                _control_assignment(),
            ],
            _DISRUPTION_RULE,
            _DELEGATION_RULE,
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()

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

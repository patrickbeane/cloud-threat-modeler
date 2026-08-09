from __future__ import annotations

import unittest
from typing import Any

from tests.providers.azure.test_azure_app_service_key_vault_secret_management_paths import (
    _system_secret_assignment,
)
from tests.providers.test_public_workload_secret_integrity_boundaries import (
    _azure_secret,
    _azure_secret_admin_role,
    _azure_vault,
    _azure_web_app,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_TAMPERING_RULE = "azure-public-app-service-secret-tampering"
_DISRUPTION_RULE = "azure-public-app-service-secret-disruption"
_WORKLOAD_ADDRESS = "azurerm_linux_web_app.orders"
_SECRET_ADDRESS = "azurerm_key_vault_secret.orders"


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence(finding: Any) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


def _resources(
    *,
    public: bool = True,
    purge_protection: bool | None = False,
) -> list[TerraformResource]:
    return [
        _azure_vault(
            rbac_enabled=True,
            purge_protection_enabled=purge_protection,
        ),
        _azure_secret(),
        _azure_web_app(public=public),
        _azure_secret_admin_role(),
        _system_secret_assignment(
            scope=f"{_SECRET_ADDRESS}.resource_versionless_id",
        ),
    ]


class AzurePublicAppServiceSecretManagementRuleTests(unittest.TestCase):
    def test_rules_are_registered(self) -> None:
        registered = {rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_TAMPERING_RULE, registered)
        self.assertIn(_DISRUPTION_RULE, registered)

    def test_public_secret_authority_emits_separate_tampering_and_disruption_findings(
        self,
    ) -> None:
        findings = _evaluate(
            _resources(),
            _TAMPERING_RULE,
            _DISRUPTION_RULE,
        )

        self.assertEqual(
            {finding.rule_id for finding in findings},
            {_TAMPERING_RULE, _DISRUPTION_RULE},
        )
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        tampering = findings_by_rule[_TAMPERING_RULE]
        disruption = findings_by_rule[_DISRUPTION_RULE]
        self.assertEqual(tampering.category, StrideCategory.TAMPERING)
        self.assertEqual(disruption.category, StrideCategory.DENIAL_OF_SERVICE)
        self.assertIn(_SECRET_ADDRESS, tampering.affected_resources)
        self.assertIn(_SECRET_ADDRESS, disruption.affected_resources)

        tampering_evidence = _evidence(tampering)
        disruption_evidence = _evidence(disruption)
        self.assertTrue(
            any(
                "operation=set" in value and "management_effect=tampering" in value
                for value in tampering_evidence["secret_management_paths"]
            )
        )
        self.assertTrue(all("operation=set" in value for value in tampering_evidence["secret_management_paths"]))
        self.assertTrue(all("operation=set" not in value for value in disruption_evidence["secret_management_paths"]))
        self.assertTrue(any("operation=delete" in value for value in disruption_evidence["secret_management_paths"]))
        self.assertTrue(
            any(
                "operation=delete_plus_purge" in value and "step_operations=delete,purge" in value
                for value in disruption_evidence["secret_management_paths"]
            )
        )
        self.assertIn(
            "recovery_state=recoverable_soft_delete",
            "\n".join(disruption_evidence["recovery_posture"]),
        )
        self.assertIn(
            "recovery_state=permanent_delete_sequence",
            "\n".join(disruption_evidence["recovery_posture"]),
        )
        self.assertIn("secret value mutation", tampering.rationale)
        self.assertIn("secret deletion and purge", disruption.rationale)

    def test_purge_protection_suppresses_only_permanent_secret_deletion(self) -> None:
        findings = _evaluate(
            _resources(purge_protection=True),
            _DISRUPTION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DISRUPTION_RULE])
        evidence = _evidence(findings[0])
        self.assertTrue(any("operation=delete" in value for value in evidence["secret_management_paths"]))
        self.assertFalse(any("operation=delete_plus_purge" in value for value in evidence["secret_management_paths"]))
        self.assertTrue(
            all("recovery_state=recoverable_soft_delete" in value for value in evidence["recovery_posture"])
        )
        self.assertFalse(any("permanent_delete_sequence" in value for value in evidence["recovery_posture"]))

    def test_delete_plus_purge_requires_ordered_unique_steps(self) -> None:
        for step_operations in (("purge", "delete"), ("delete", "purge", "purge")):
            with self.subTest(step_operations=step_operations):
                inventory = AzureNormalizer().normalize(_resources())
                workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
                assert workload is not None
                paths = [
                    path.copy()
                    for path in azure_facts(workload).app_service_key_vault_secret_management_paths
                    if path["operation"] == "delete_plus_purge"
                ]
                self.assertEqual(len(paths), 1)
                paths[0]["step_operations"] = list(step_operations)
                object.__setattr__(workload, "_decoration_state_frozen", False)
                azure_facts(workload).set_app_service_key_vault_secret_management_paths(paths)
                object.__setattr__(workload, "_decoration_state_frozen", True)

                findings = StrideRuleEngine().evaluate(
                    inventory,
                    [],
                    rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DISRUPTION_RULE})),
                )
                self.assertEqual(findings, [])

    def test_private_app_service_stays_quiet(self) -> None:
        findings = _evaluate(_resources(public=False), _TAMPERING_RULE, _DISRUPTION_RULE)
        self.assertEqual(findings, [])

    def test_current_secret_authorization_is_required(self) -> None:
        inventory = AzureNormalizer().normalize(_resources())
        secret = inventory.get_by_address(_SECRET_ADDRESS)
        assert secret is not None
        object.__setattr__(secret, "_decoration_state_frozen", False)
        azure_facts(secret).set_key_vault_secret_authorization_posture(
            grants=[],
            uncertainties=[],
        )
        object.__setattr__(secret, "_decoration_state_frozen", True)

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_TAMPERING_RULE, _DISRUPTION_RULE})),
        )
        self.assertEqual(findings, [])

    def test_stale_secret_path_identity_does_not_create_a_finding(self) -> None:
        inventory = AzureNormalizer().normalize(_resources())
        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = [path.copy() for path in azure_facts(workload).app_service_key_vault_secret_management_paths]
        stale_path = next(path for path in paths if path["operation"] == "set")
        stale_path["secret_name"] = "stale"
        object.__setattr__(workload, "_decoration_state_frozen", False)
        azure_facts(workload).set_app_service_key_vault_secret_management_paths(paths)
        object.__setattr__(workload, "_decoration_state_frozen", True)

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_TAMPERING_RULE})),
        )
        self.assertEqual(findings, [])

    def test_parent_vault_scope_is_visible_without_claiming_out_of_plan_secrets(
        self,
    ) -> None:
        resources = _resources()
        resources[-1] = _system_secret_assignment()
        findings = _evaluate(resources, _TAMPERING_RULE)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        evidence = _evidence(finding)
        self.assertIn(
            "vault_grants=1",
            evidence["scope_breadth"][0],
        )
        self.assertIn(
            "out_of_plan_secrets_not_modeled=true",
            evidence["scope_breadth"][0],
        )
        self.assertIn(
            "exact modeled secret(s)",
            finding.rationale,
        )


if __name__ == "__main__":
    unittest.main()

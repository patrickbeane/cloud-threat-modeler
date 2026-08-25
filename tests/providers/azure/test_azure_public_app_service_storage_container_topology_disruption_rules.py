from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_storage_access_paths import _web_app
from tests.providers.azure.test_azure_app_service_storage_container_topology_destruction_paths import (
    _control_assignment,
    _control_role,
    _storage_account,
    _storage_container,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts

_RULE_ID = "azure-public-app-service-storage-container-topology-disruption"
_BLOB_DISRUPTION_RULE_ID = "azure-public-app-service-storage-blob-disruption"
_MUTATION_RULE_ID = "azure-public-app-service-storage-mutation-access"
_DELETE_CONTAINER = "Microsoft.Storage/storageAccounts/blobServices/containers/delete"
_WORKLOAD_ADDRESS = "azurerm_linux_web_app.orders"
_ACCOUNT_ADDRESS = "azurerm_storage_account.orders"
_CONTAINER_ADDRESS = "azurerm_storage_container.orders"
_ROLE_ADDRESS = "azurerm_role_definition.storage_topology"


def _public_web_app() -> TerraformResource:
    app = _web_app()
    app.values["public_network_access_enabled"] = True
    return app


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    findings = StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or (_RULE_ID,))),
    )
    return inventory, findings


def _reevaluate(inventory, *rule_ids: str):
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or (_RULE_ID,))),
    )


def _resources(
    *,
    public: bool = True,
    container: TerraformResource | None = None,
    account: TerraformResource | None = None,
    role: TerraformResource | None = None,
    assignment: TerraformResource | None = None,
) -> list[TerraformResource]:
    return [
        account or _storage_account(),
        container or _storage_container(),
        _public_web_app() if public else _web_app(),
        role or _control_role(actions=[_DELETE_CONTAINER]),
        assignment or _control_assignment(),
    ]


def _evidence(finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


class AzurePublicAppServiceStorageContainerTopologyDisruptionRuleTests(unittest.TestCase):
    def test_container_deletion_is_topology_dos_only(self) -> None:
        _, findings = _evaluate(
            _resources(),
            _RULE_ID,
            _BLOB_DISRUPTION_RULE_ID,
            _MUTATION_RULE_ID,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        self.assertEqual(findings[0].category, StrideCategory.DENIAL_OF_SERVICE)

    def test_public_finding_preserves_exact_target_and_prerequisite_boundary(self) -> None:
        _, findings = _evaluate(_resources())

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            [
                _WORKLOAD_ADDRESS,
                _ACCOUNT_ADDRESS,
                _CONTAINER_ADDRESS,
                "azurerm_role_assignment.storage_topology",
                _ROLE_ADDRESS,
            ],
        )
        evidence = _evidence(finding)
        self.assertIn(
            "operation=" + _DELETE_CONTAINER,
            evidence["storage_container_topology_destruction_paths"][0],
        )
        self.assertIn(
            "target_scope=exact_storage_container", evidence["storage_container_topology_destruction_paths"][0]
        )
        self.assertIn(
            "protected_content_emptiness_required=false",
            evidence["container_deletion_prerequisite_evidence"][0],
        )
        self.assertIn(
            "matched_actions=" + _DELETE_CONTAINER,
            evidence["container_authorization_evidence"][0],
        )
        self.assertIn(
            "container_soft_delete_state=enabled",
            evidence["container_soft_delete_recovery_evidence"][0],
        )
        self.assertIn(
            "successful_deletion_observed=false",
            evidence["container_soft_delete_recovery_evidence"][0],
        )
        self.assertIn("protected-content emptiness", finding.rationale)
        self.assertNotIn("successful deletion observed=true", finding.rationale)

    def test_protected_content_posture_keeps_authority_and_qualifies_prerequisite(self) -> None:
        _, findings = _evaluate(
            _resources(
                container=_storage_container(
                    has_immutability_policy=True,
                    has_legal_hold=False,
                )
            )
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence(findings[0])
        prerequisite = evidence["container_deletion_prerequisite_evidence"][0]
        self.assertIn("has_immutability_policy=true", prerequisite)
        self.assertIn("protected_content_emptiness_required=true", prerequisite)
        self.assertIn("protected_content_emptiness_state=not_established", prerequisite)
        self.assertIn("constraint_state=protected_content_emptiness_not_established", prerequisite)

    def test_unknown_protection_posture_keeps_authority_but_stays_unknown(self) -> None:
        _, findings = _evaluate(
            _resources(
                container=_storage_container(
                    has_immutability_policy=None,
                    has_legal_hold=None,
                    unknown_constraints=True,
                )
            )
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        prerequisite = _evidence(findings[0])["container_deletion_prerequisite_evidence"][0]
        self.assertIn("protected_content_emptiness_required=unknown", prerequisite)
        self.assertIn("protected_content_emptiness_state=unknown", prerequisite)

    def test_private_workload_keeps_paths_without_public_finding(self) -> None:
        inventory, findings = _evaluate(_resources(public=False))

        self.assertEqual(findings, [])
        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        self.assertTrue(azure_facts(workload).app_service_storage_container_topology_destruction_paths)

    def test_multiple_containers_deduplicate_targets_and_raise_blast_radius(self) -> None:
        _, findings = _evaluate(
            [
                _storage_account(),
                _storage_container(),
                _storage_container(name="archive"),
                _public_web_app(),
                _control_role(actions=[_DELETE_CONTAINER]),
                _control_assignment(scope="azurerm_storage_account.orders.id"),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.affected_resources.count(_ACCOUNT_ADDRESS), 1)
        self.assertEqual(finding.affected_resources.count(_CONTAINER_ADDRESS), 1)
        self.assertEqual(finding.affected_resources.count("azurerm_storage_container.archive"), 1)
        self.assertEqual(len(_evidence(finding)["storage_container_topology_destruction_paths"]), 2)
        self.assertIn("across 2 exact modeled Blob containers", finding.rationale)

    def test_removed_current_role_action_suppresses_cached_finding(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        role = inventory.get_by_address(_ROLE_ADDRESS)
        assert role is not None
        azure_facts(role).set(AzureResourceMetadata.ROLE_DEFINITION_ACTIONS, [])

        self.assertEqual(_reevaluate(inventory), [])

    def test_stale_cached_target_is_rejected(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = azure_facts(workload).app_service_storage_container_topology_destruction_paths
        paths[0]["container_address"] = "azurerm_storage_container.stale"
        azure_facts(workload).set_app_service_storage_container_topology_destruction_paths(paths)

        self.assertEqual(_reevaluate(inventory), [])

    def test_current_condition_change_suppresses_cached_finding(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        assignment = inventory.get_by_address("azurerm_role_assignment.storage_topology")
        assert assignment is not None
        azure_facts(assignment).set(
            AzureResourceMetadata.ROLE_ASSIGNMENT_CONDITION,
            "@Resource[...] StringEquals 'orders'",
        )

        self.assertEqual(_reevaluate(inventory), [])

    def test_recovery_posture_drift_refreshes_current_evidence(self) -> None:
        account = _storage_account(unknown_recovery=True)
        inventory, findings = _evaluate(_resources(account=account))
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        self.assertIn(
            "container_soft_delete_state=unknown",
            _evidence(findings[0])["container_soft_delete_recovery_evidence"][0],
        )

        account_facts = azure_facts(inventory.get_by_address(_ACCOUNT_ADDRESS))
        account_facts.set(AzureResourceMetadata.STORAGE_CONTAINER_DELETE_RETENTION_DAYS, 30)
        account_facts.set(AzureResourceMetadata.STORAGE_POSTURE_UNCERTAINTIES, [])

        current_findings = _reevaluate(inventory)
        self.assertEqual([finding.rule_id for finding in current_findings], [_RULE_ID])
        recovery = _evidence(current_findings[0])["container_soft_delete_recovery_evidence"][0]
        self.assertIn("container_soft_delete_state=enabled", recovery)
        self.assertIn("container_delete_retention_days=30", recovery)
        self.assertNotIn(
            "blob_properties.container_delete_retention_policy.days is unknown after planning",
            _evidence(current_findings[0]).get(
                "storage_container_topology_destruction_path_uncertainties",
                [],
            ),
        )


if __name__ == "__main__":
    unittest.main()

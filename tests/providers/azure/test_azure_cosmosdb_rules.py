from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType

_ACCOUNT_ID = "/subscriptions/example/resourceGroups/data/providers/Microsoft.DocumentDB/databaseAccounts/orders"
_KEY_ID = "azurerm_key_vault_key.cosmos.id"

_COSMOSDB_RULE_IDS = (
    "azure-cosmosdb-customer-managed-key-missing",
    "azure-cosmosdb-continuous-backup-not-configured",
    "azure-cosmosdb-minimum-tls-below-1-2",
)


def _account(
    *,
    values: dict[str, object] | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="azurerm_cosmosdb_account.orders",
        mode="managed",
        resource_type=AzureResourceType.COSMOSDB_ACCOUNT,
        name="orders",
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values={
            "id": _ACCOUNT_ID,
            "name": "orders",
            "resource_group_name": "data",
            "location": "eastus",
            "offer_type": "Standard",
            **(values or {}),
        },
        unknown_values=unknown_values or {},
    )


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AzureCosmosDbRuleTests(unittest.TestCase):
    def test_periodic_backup_without_cmk_and_weak_tls_emits_focused_findings(self) -> None:
        findings = _evaluate(
            [
                _account(
                    values={
                        "backup": [
                            {
                                "type": "Periodic",
                                "interval_in_minutes": 240,
                                "retention_in_hours": 168,
                                "storage_redundancy": "Geo",
                            }
                        ],
                        "minimal_tls_version": "Tls",
                    }
                )
            ],
            *_COSMOSDB_RULE_IDS,
        )

        self.assertEqual([finding.rule_id for finding in findings], list(_COSMOSDB_RULE_IDS))
        self.assertEqual(findings[0].severity.value, "low")
        self.assertEqual(findings[1].severity.value, "medium")
        evidence_by_rule = {finding.rule_id: _evidence_by_key(finding) for finding in findings}

        encryption_evidence = evidence_by_rule["azure-cosmosdb-customer-managed-key-missing"]["encryption_ownership"]
        self.assertEqual(
            encryption_evidence,
            [
                "customer_managed_key_state=not_configured",
                "key_vault_key_id is unset",
                "Cosmos DB encryption at rest remains enabled with Microsoft-managed encryption",
            ],
        )
        self.assertNotIn("unencrypted", " ".join(encryption_evidence).lower())

        self.assertEqual(
            evidence_by_rule["azure-cosmosdb-continuous-backup-not-configured"]["recovery_posture"],
            [
                "backup_configuration_state=configured",
                "backup_block_configured is true",
                "effective_backup_type=Periodic",
                "interval_in_minutes=240",
                "retention_in_hours=168",
                "storage_redundancy=Geo",
            ],
        )
        self.assertEqual(
            evidence_by_rule["azure-cosmosdb-minimum-tls-below-1-2"]["transport_posture"],
            ["minimal_tls_version is Tls"],
        )

    def test_omitted_backup_block_reports_effective_periodic_defaults(self) -> None:
        findings = _evaluate(
            [_account(values={"key_vault_key_id": _KEY_ID})],
            "azure-cosmosdb-continuous-backup-not-configured",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-cosmosdb-continuous-backup-not-configured"],
        )
        self.assertEqual(
            _evidence_by_key(findings[0])["recovery_posture"],
            [
                "backup_configuration_state=not_configured",
                "backup_block_configured is false",
                "effective_backup_type=Periodic",
                "interval_in_minutes=240",
                "retention_in_hours=8",
                "storage_redundancy=Geo",
            ],
        )

    def test_continuous_backup_cmk_and_tls_1_2_stay_quiet(self) -> None:
        findings = _evaluate(
            [
                _account(
                    values={
                        "key_vault_key_id": _KEY_ID,
                        "backup": [{"type": "Continuous", "tier": "Continuous30Days"}],
                        "minimal_tls_version": "Tls12",
                    }
                )
            ],
            *_COSMOSDB_RULE_IDS,
        )

        self.assertEqual(findings, [])

    def test_unknown_encryption_backup_and_tls_do_not_become_explicit_unsafe_claims(self) -> None:
        findings = _evaluate(
            [
                _account(
                    values={
                        "key_vault_key_id": None,
                        "backup": [{"type": None}],
                        "minimal_tls_version": None,
                    },
                    unknown_values={
                        "key_vault_key_id": True,
                        "backup": [{"type": True}],
                        "minimal_tls_version": True,
                    },
                )
            ],
            *_COSMOSDB_RULE_IDS,
        )

        self.assertEqual(findings, [])

    def test_effective_default_tls_1_2_does_not_emit_weak_tls_finding(self) -> None:
        findings = _evaluate(
            [_account(values={"key_vault_key_id": _KEY_ID, "backup": [{"type": "Continuous"}]})],
            "azure-cosmosdb-minimum-tls-below-1-2",
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()

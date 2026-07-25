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
_COSMOSDB_ACCESS_RULE_IDS = (
    "azure-cosmosdb-public-network-unrestricted",
    "azure-cosmosdb-local-authentication-enabled",
    "azure-cosmosdb-missing-private-endpoint",
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


def _private_endpoint(*, with_dns: bool = True) -> TerraformResource:
    values: dict[str, object] = {
        "name": "orders-private-endpoint",
        "private_service_connection": [
            {
                "name": "orders-connection",
                "private_connection_resource_id": _ACCOUNT_ID,
                "subresource_names": ["Sql"],
                "is_manual_connection": False,
            }
        ],
    }
    if with_dns:
        values["private_dns_zone_group"] = [
            {
                "name": "cosmos-dns",
                "private_dns_zone_ids": ["azurerm_private_dns_zone.cosmos.id"],
            }
        ]
    return TerraformResource(
        address="azurerm_private_endpoint.orders",
        mode="managed",
        resource_type=AzureResourceType.PRIVATE_ENDPOINT,
        name="orders",
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values={},
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AzureCosmosDbRuleTests(unittest.TestCase):
    def test_unrestricted_public_account_emits_network_local_auth_and_missing_endpoint_findings(
        self,
    ) -> None:
        findings = _evaluate([_account()], *_COSMOSDB_ACCESS_RULE_IDS)

        self.assertEqual(
            [finding.rule_id for finding in findings],
            list(_COSMOSDB_ACCESS_RULE_IDS),
        )
        evidence_by_rule = {finding.rule_id: _evidence_by_key(finding) for finding in findings}
        network_evidence = evidence_by_rule["azure-cosmosdb-public-network-unrestricted"]["network_posture"]
        self.assertIn("public_network_access_enabled is true", network_evidence)
        self.assertIn("network_restriction_state=unrestricted", network_evidence)
        self.assertIn("ip_range_filter_state=not_configured", network_evidence)
        self.assertIn("virtual_network_filter_enabled is unknown", network_evidence)
        self.assertEqual(
            evidence_by_rule["azure-cosmosdb-local-authentication-enabled"]["authorization_posture"],
            [
                "local_authentication_state=enabled",
                "local_authentication_enabled is true",
            ],
        )

    def test_non_universal_ip_filter_reduces_missing_endpoint_severity_without_claiming_private_only(
        self,
    ) -> None:
        findings = _evaluate(
            [
                _account(
                    values={
                        "ip_range_filter": ["198.51.100.0/24"],
                        "local_authentication_enabled": False,
                    }
                )
            ],
            *_COSMOSDB_ACCESS_RULE_IDS,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-cosmosdb-missing-private-endpoint"],
        )
        self.assertEqual(findings[0].severity.value, "low")
        evidence = _evidence_by_key(findings[0])
        self.assertIn("network_restriction_state=restricted", evidence["network_acl_posture"])
        self.assertIn(
            "network restrictions reduce exposure but do not prove private-only access",
            evidence["network_acl_posture"],
        )
        self.assertIn("do not prove private-only access", findings[0].rationale)

    def test_enabled_vnet_filter_is_mitigating_but_not_private_only(self) -> None:
        findings = _evaluate(
            [
                _account(
                    values={
                        "is_virtual_network_filter_enabled": True,
                        "virtual_network_rule": [{"id": "azurerm_subnet.data.id"}],
                        "local_authentication_enabled": False,
                    }
                )
            ],
            *_COSMOSDB_ACCESS_RULE_IDS,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-cosmosdb-missing-private-endpoint"],
        )
        evidence = _evidence_by_key(findings[0])["network_acl_posture"]
        self.assertIn("network_restriction_state=restricted", evidence)
        self.assertIn("virtual_network_rule subnet_id=azurerm_subnet.data.id", evidence)

    def test_unknown_ip_filter_is_not_overridden_by_known_vnet_restriction(self) -> None:
        findings = _evaluate(
            [
                _account(
                    values={
                        "ip_range_filter": [],
                        "is_virtual_network_filter_enabled": True,
                        "virtual_network_rule": [{"id": "azurerm_subnet.data.id"}],
                        "local_authentication_enabled": False,
                    },
                    unknown_values={"ip_range_filter": True},
                )
            ],
            *_COSMOSDB_ACCESS_RULE_IDS,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-cosmosdb-missing-private-endpoint"],
        )
        evidence = _evidence_by_key(findings[0])["network_acl_posture"]
        self.assertIn("network_restriction_state=unknown", evidence)
        self.assertEqual(findings[0].severity_reasoning.internet_exposure, 0)

    def test_universal_ip_range_is_not_treated_as_a_restriction(self) -> None:
        findings = _evaluate(
            [
                _account(
                    values={
                        "ip_range_filter": ["198.51.100.0/24", "0.0.0.0/0"],
                        "local_authentication_enabled": False,
                    }
                )
            ],
            *_COSMOSDB_ACCESS_RULE_IDS,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "azure-cosmosdb-public-network-unrestricted",
                "azure-cosmosdb-missing-private-endpoint",
            ],
        )
        self.assertIn(
            "network_restriction_state=unrestricted",
            _evidence_by_key(findings[0])["network_posture"],
        )

    def test_cosmos_azure_datacenter_sentinel_is_not_treated_as_restricted(
        self,
    ) -> None:
        findings = _evaluate(
            [
                _account(
                    values={
                        "ip_range_filter": ["0.0.0.0"],
                        "local_authentication_enabled": False,
                    }
                )
            ],
            *_COSMOSDB_ACCESS_RULE_IDS,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "azure-cosmosdb-public-network-unrestricted",
                "azure-cosmosdb-missing-private-endpoint",
            ],
        )
        self.assertIn(
            "network_restriction_state=unrestricted",
            _evidence_by_key(findings[0])["network_posture"],
        )

    def test_private_endpoint_suppresses_missing_coverage_but_public_fallback_remains(
        self,
    ) -> None:
        findings = _evaluate(
            [
                _account(
                    values={
                        "ip_range_filter": ["198.51.100.0/24"],
                        "local_authentication_enabled": False,
                    }
                ),
                _private_endpoint(),
            ],
            *_COSMOSDB_ACCESS_RULE_IDS,
            "azure-private-endpoint-public-fallback",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-private-endpoint-public-fallback"],
        )
        self.assertEqual(findings[0].severity.value, "low")
        self.assertEqual(
            findings[0].affected_resources,
            ["azurerm_cosmosdb_account.orders", "azurerm_private_endpoint.orders"],
        )
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["private_endpoint_subresources"], ["Sql"])
        self.assertIn(
            "network restrictions reduce exposure but do not prove private-only access",
            evidence["network_acl_posture"],
        )

    def test_public_access_disabled_local_auth_disabled_and_private_endpoint_stay_quiet(
        self,
    ) -> None:
        findings = _evaluate(
            [
                _account(
                    values={
                        "public_network_access_enabled": False,
                        "local_authentication_enabled": False,
                    }
                ),
                _private_endpoint(),
            ],
            *_COSMOSDB_ACCESS_RULE_IDS,
            "azure-private-endpoint-public-fallback",
        )

        self.assertEqual(findings, [])

    def test_public_access_disabled_without_private_endpoint_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _account(
                    values={
                        "public_network_access_enabled": False,
                        "local_authentication_enabled": False,
                    }
                )
            ],
            *_COSMOSDB_ACCESS_RULE_IDS,
        )

        self.assertEqual(findings, [])

    def test_unknown_acl_and_local_auth_do_not_become_explicit_unsafe_claims(self) -> None:
        findings = _evaluate(
            [
                _account(
                    values={
                        "ip_range_filter": [],
                        "is_virtual_network_filter_enabled": None,
                        "local_authentication_enabled": None,
                    },
                    unknown_values={
                        "ip_range_filter": True,
                        "is_virtual_network_filter_enabled": True,
                        "local_authentication_enabled": True,
                    },
                )
            ],
            *_COSMOSDB_ACCESS_RULE_IDS,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-cosmosdb-missing-private-endpoint"],
        )
        self.assertNotIn(
            "unrestricted",
            " ".join(value for item in findings[0].evidence for value in item.values),
        )

    def test_cosmos_private_endpoint_participates_in_generic_dns_posture(self) -> None:
        findings = _evaluate(
            [
                _account(values={"public_network_access_enabled": False}),
                _private_endpoint(with_dns=False),
            ],
            "azure-private-endpoint-dns-posture-incomplete",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-private-endpoint-dns-posture-incomplete"],
        )
        self.assertEqual(
            findings[0].affected_resources,
            ["azurerm_cosmosdb_account.orders", "azurerm_private_endpoint.orders"],
        )

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

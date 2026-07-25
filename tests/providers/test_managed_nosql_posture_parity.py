from __future__ import annotations

import unittest
from collections import Counter

from tests.providers.aws.test_aws_dynamodb_rules import _findings as _aws_findings
from tests.providers.aws.test_aws_dynamodb_rules import _safe_table as _aws_safe_table
from tests.providers.aws.test_aws_dynamodb_rules import _table as _aws_table
from tests.providers.azure.test_azure_cosmosdb_rules import _account as _azure_account
from tests.providers.azure.test_azure_cosmosdb_rules import _evaluate as _azure_findings
from tests.providers.azure.test_azure_cosmosdb_rules import (
    _private_endpoint as _azure_private_endpoint,
)
from tests.providers.gcp.test_gcp_firestore_rules import _database as _gcp_database
from tests.providers.gcp.test_gcp_firestore_rules import _findings as _gcp_findings
from tests.providers.gcp.test_gcp_firestore_rules import (
    _hardened_database as _gcp_hardened_database,
)
from tfstride.models import Finding
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_NOSQL_RULE_IDS = frozenset(
    {
        "aws-dynamodb-customer-managed-kms-key-missing",
        "aws-dynamodb-point-in-time-recovery-disabled-or-unknown",
        "aws-dynamodb-deletion-protection-disabled-or-unknown",
    }
)
GCP_NOSQL_RULE_IDS = frozenset(
    {
        "gcp-firestore-customer-managed-encryption-missing",
        "gcp-firestore-point-in-time-recovery-disabled-or-unknown",
        "gcp-firestore-delete-protection-disabled-or-unknown",
    }
)
AZURE_COSMOSDB_RULE_IDS = frozenset(
    {
        "azure-cosmosdb-customer-managed-key-missing",
        "azure-cosmosdb-continuous-backup-not-configured",
        "azure-cosmosdb-minimum-tls-below-1-2",
        "azure-cosmosdb-public-network-unrestricted",
        "azure-cosmosdb-local-authentication-enabled",
        "azure-cosmosdb-missing-private-endpoint",
    }
)
AZURE_PRIVATE_ENDPOINT_RULE_IDS = frozenset(
    {
        "azure-private-endpoint-public-fallback",
    }
)
AZURE_NOSQL_RULE_IDS = AZURE_COSMOSDB_RULE_IDS | AZURE_PRIVATE_ENDPOINT_RULE_IDS
ALL_NOSQL_RULE_IDS = AWS_NOSQL_RULE_IDS | GCP_NOSQL_RULE_IDS | AZURE_NOSQL_RULE_IDS

NOSQL_CONCEPT_RULE_IDS = {
    "encryption_ownership": {
        "aws": frozenset({"aws-dynamodb-customer-managed-kms-key-missing"}),
        "gcp": frozenset({"gcp-firestore-customer-managed-encryption-missing"}),
        "azure": frozenset({"azure-cosmosdb-customer-managed-key-missing"}),
    },
    "recovery_or_pitr": {
        "aws": frozenset({"aws-dynamodb-point-in-time-recovery-disabled-or-unknown"}),
        "gcp": frozenset({"gcp-firestore-point-in-time-recovery-disabled-or-unknown"}),
        "azure": frozenset({"azure-cosmosdb-continuous-backup-not-configured"}),
    },
    "deletion_protection": {
        "aws": frozenset({"aws-dynamodb-deletion-protection-disabled-or-unknown"}),
        "gcp": frozenset({"gcp-firestore-delete-protection-disabled-or-unknown"}),
    },
    "public_network_access": {
        "azure": frozenset({"azure-cosmosdb-public-network-unrestricted"}),
    },
    "local_authentication": {
        "azure": frozenset({"azure-cosmosdb-local-authentication-enabled"}),
    },
    "minimum_tls": {
        "azure": frozenset({"azure-cosmosdb-minimum-tls-below-1-2"}),
    },
    "private_connectivity": {
        "azure": frozenset({"azure-cosmosdb-missing-private-endpoint"}),
    },
}

_AWS_KMS_KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/dynamodb"
_GCP_KMS_KEY_NAME = "projects/tfstride-demo/locations/us/keyRings/data/cryptoKeys/firestore"
_AZURE_KEY_VAULT_KEY_ID = "azurerm_key_vault_key.cosmos.id"


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _rule_ids(findings: list[Finding]) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


def _rule_counts(findings: list[Finding]) -> Counter[str]:
    return Counter(finding.rule_id for finding in findings)


def _evidence_values(finding: Finding) -> list[str]:
    return [value for item in finding.evidence for value in item.values]


def _unsafe_aws_findings(*rule_ids: str) -> list[Finding]:
    return _aws_findings(
        [
            _aws_table(
                server_side_encryption=[{"enabled": False}],
                point_in_time_recovery=[{"enabled": False}],
                deletion_protection_enabled=False,
            )
        ],
        *rule_ids,
    )


def _unsafe_gcp_findings(*rule_ids: str) -> list[Finding]:
    return _gcp_findings(
        [
            _gcp_database(
                point_in_time_recovery_enablement="POINT_IN_TIME_RECOVERY_DISABLED",
                delete_protection_state="DELETE_PROTECTION_DISABLED",
                deletion_policy="DELETE",
            )
        ],
        *rule_ids,
    )


def _unsafe_azure_findings(*rule_ids: str) -> list[Finding]:
    return _azure_findings(
        [
            _azure_account(
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
                    "public_network_access_enabled": True,
                    "ip_range_filter": [],
                    "is_virtual_network_filter_enabled": False,
                    "local_authentication_enabled": True,
                }
            )
        ],
        *rule_ids,
    )


class ManagedNosqlPostureParityTests(unittest.TestCase):
    def test_managed_nosql_rule_families_are_registered(self) -> None:
        self.assertLessEqual(AWS_NOSQL_RULE_IDS, _flatten(AWS_RULE_GROUP_IDS))
        self.assertLessEqual(GCP_NOSQL_RULE_IDS, _flatten(GCP_RULE_GROUP_IDS))
        self.assertLessEqual(AZURE_COSMOSDB_RULE_IDS, _flatten(AZURE_RULE_GROUP_IDS))
        self.assertLessEqual(AZURE_PRIVATE_ENDPOINT_RULE_IDS, _flatten(AZURE_RULE_GROUP_IDS))

    def test_unsafe_provider_local_nosql_concepts_are_pinned(self) -> None:
        findings_by_provider = {
            "aws": _unsafe_aws_findings(*AWS_NOSQL_RULE_IDS),
            "gcp": _unsafe_gcp_findings(*GCP_NOSQL_RULE_IDS),
            "azure": _unsafe_azure_findings(*AZURE_COSMOSDB_RULE_IDS),
        }

        self.assertEqual(
            _rule_counts(findings_by_provider["aws"]),
            Counter({rule_id: 1 for rule_id in AWS_NOSQL_RULE_IDS}),
        )
        self.assertEqual(
            _rule_counts(findings_by_provider["gcp"]),
            Counter({rule_id: 1 for rule_id in GCP_NOSQL_RULE_IDS}),
        )
        self.assertEqual(
            _rule_counts(findings_by_provider["azure"]),
            Counter({rule_id: 1 for rule_id in AZURE_COSMOSDB_RULE_IDS}),
        )

        finding_ids_by_provider = {provider: _rule_ids(findings) for provider, findings in findings_by_provider.items()}
        for concept, provider_expectations in NOSQL_CONCEPT_RULE_IDS.items():
            for provider, expected_rule_ids in provider_expectations.items():
                with self.subTest(concept=concept, provider=provider):
                    self.assertLessEqual(
                        expected_rule_ids,
                        finding_ids_by_provider[provider],
                    )

    def test_recovery_semantics_and_encryption_ownership_remain_provider_local(
        self,
    ) -> None:
        aws_findings = _unsafe_aws_findings(*AWS_NOSQL_RULE_IDS)
        gcp_findings = _unsafe_gcp_findings(*GCP_NOSQL_RULE_IDS)
        azure_findings = _unsafe_azure_findings(*AZURE_COSMOSDB_RULE_IDS)
        findings_by_rule = {finding.rule_id: finding for finding in [*aws_findings, *gcp_findings, *azure_findings]}

        self.assertIn(
            "point_in_time_recovery_state=disabled",
            _evidence_values(findings_by_rule["aws-dynamodb-point-in-time-recovery-disabled-or-unknown"]),
        )
        self.assertIn(
            "point_in_time_recovery_state=disabled",
            _evidence_values(findings_by_rule["gcp-firestore-point-in-time-recovery-disabled-or-unknown"]),
        )
        azure_recovery = findings_by_rule["azure-cosmosdb-continuous-backup-not-configured"]
        self.assertIn("effective_backup_type=Periodic", _evidence_values(azure_recovery))
        self.assertIn("Periodic backup still provides recovery copies", azure_recovery.rationale)

        for rule_id in (
            "aws-dynamodb-customer-managed-kms-key-missing",
            "gcp-firestore-customer-managed-encryption-missing",
            "azure-cosmosdb-customer-managed-key-missing",
        ):
            self.assertNotIn("unencrypted", findings_by_rule[rule_id].rationale.lower())

        self.assertEqual(
            set(NOSQL_CONCEPT_RULE_IDS["deletion_protection"]),
            {"aws", "gcp"},
        )
        self.assertFalse(
            any("delete-protection" in rule_id or "deletion-protection" in rule_id for rule_id in AZURE_NOSQL_RULE_IDS)
        )

    def test_hardened_managed_nosql_posture_is_quiet(self) -> None:
        aws_findings = _aws_findings(
            [_aws_safe_table()],
            *AWS_NOSQL_RULE_IDS,
        )
        gcp_findings = _gcp_findings(
            [_gcp_hardened_database()],
            *GCP_NOSQL_RULE_IDS,
        )
        azure_findings = _azure_findings(
            [
                _azure_account(
                    values={
                        "key_vault_key_id": _AZURE_KEY_VAULT_KEY_ID,
                        "backup": [
                            {
                                "type": "Continuous",
                                "tier": "Continuous30Days",
                            }
                        ],
                        "minimal_tls_version": "Tls12",
                        "public_network_access_enabled": False,
                        "local_authentication_enabled": False,
                    }
                ),
                _azure_private_endpoint(),
            ],
            *AZURE_NOSQL_RULE_IDS,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_unknown_values_do_not_become_explicit_disabled_claims(self) -> None:
        aws_findings = _aws_findings(
            [
                _aws_table(
                    server_side_encryption=[{"enabled": True, "kms_key_arn": _AWS_KMS_KEY_ARN}],
                    point_in_time_recovery=[{"enabled": True}],
                    deletion_protection_enabled=True,
                    unknown_values={
                        "server_side_encryption": True,
                        "point_in_time_recovery": True,
                        "deletion_protection_enabled": True,
                    },
                )
            ],
            *AWS_NOSQL_RULE_IDS,
        )
        gcp_findings = _gcp_findings(
            [
                _gcp_database(
                    cmek_config=[{"kms_key_name": _GCP_KMS_KEY_NAME}],
                    point_in_time_recovery_enablement="POINT_IN_TIME_RECOVERY_ENABLED",
                    delete_protection_state="DELETE_PROTECTION_ENABLED",
                    unknown_values={
                        "cmek_config": True,
                        "point_in_time_recovery_enablement": True,
                        "delete_protection_state": True,
                    },
                )
            ],
            *GCP_NOSQL_RULE_IDS,
        )
        azure_findings = _azure_findings(
            [
                _azure_account(
                    values={
                        "key_vault_key_id": None,
                        "backup": [{"type": None}],
                        "minimal_tls_version": None,
                        "public_network_access_enabled": None,
                        "ip_range_filter": [],
                        "is_virtual_network_filter_enabled": None,
                        "local_authentication_enabled": None,
                    },
                    unknown_values={
                        "key_vault_key_id": True,
                        "backup": [{"type": True}],
                        "minimal_tls_version": True,
                        "public_network_access_enabled": True,
                        "ip_range_filter": True,
                        "is_virtual_network_filter_enabled": True,
                        "local_authentication_enabled": True,
                    },
                ),
                _azure_private_endpoint(),
            ],
            *AZURE_NOSQL_RULE_IDS,
        )

        self.assertEqual(_rule_ids(aws_findings), AWS_NOSQL_RULE_IDS)
        self.assertEqual(
            _rule_ids(gcp_findings),
            frozenset(
                {
                    "gcp-firestore-point-in-time-recovery-disabled-or-unknown",
                    "gcp-firestore-delete-protection-disabled-or-unknown",
                }
            ),
        )
        self.assertEqual(
            _rule_ids(azure_findings),
            AZURE_PRIVATE_ENDPOINT_RULE_IDS,
        )

        for finding in [*aws_findings, *gcp_findings, *azure_findings]:
            self.assertNotIn("explicitly disables", finding.rationale.lower())
        for finding in [*aws_findings, *gcp_findings]:
            self.assertEqual(finding.severity.value, "low")
            self.assertTrue(
                any("unknown" in value for value in _evidence_values(finding)),
                finding.rule_id,
            )

        azure_evidence = _evidence_values(azure_findings[0])
        self.assertIn("public_network_access_enabled is unknown", azure_evidence)
        self.assertNotIn("public_network_access_enabled is true", azure_evidence)

    def test_private_endpoint_does_not_hide_public_fallback(self) -> None:
        findings = _azure_findings(
            [
                _azure_account(
                    values={
                        "key_vault_key_id": _AZURE_KEY_VAULT_KEY_ID,
                        "backup": [{"type": "Continuous"}],
                        "minimal_tls_version": "Tls12",
                        "public_network_access_enabled": True,
                        "ip_range_filter": ["198.51.100.0/24"],
                        "local_authentication_enabled": False,
                    }
                ),
                _azure_private_endpoint(),
            ],
            *AZURE_NOSQL_RULE_IDS,
        )

        self.assertEqual(
            _rule_ids(findings),
            AZURE_PRIVATE_ENDPOINT_RULE_IDS,
        )
        self.assertIn(
            "network restrictions reduce exposure but do not prove private-only access",
            _evidence_values(findings[0]),
        )

    def test_managed_nosql_findings_do_not_leak_across_provider_inventories(self) -> None:
        findings_by_provider = {
            "aws": _unsafe_aws_findings(*ALL_NOSQL_RULE_IDS),
            "gcp": _unsafe_gcp_findings(*ALL_NOSQL_RULE_IDS),
            "azure": _unsafe_azure_findings(*ALL_NOSQL_RULE_IDS),
        }

        expected_rule_ids = {
            "aws": AWS_NOSQL_RULE_IDS,
            "gcp": GCP_NOSQL_RULE_IDS,
            "azure": AZURE_COSMOSDB_RULE_IDS,
        }
        for provider, findings in findings_by_provider.items():
            with self.subTest(provider=provider):
                self.assertEqual(_rule_ids(findings), expected_rule_ids[provider])
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))


if __name__ == "__main__":
    unittest.main()

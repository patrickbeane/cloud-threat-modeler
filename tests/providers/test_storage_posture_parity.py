from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_storage_rules import (
    _bucket as _aws_bucket,
)
from tests.providers.aws.test_aws_storage_rules import (
    _encryption as _aws_encryption,
)
from tests.providers.aws.test_aws_storage_rules import (
    _findings as _aws_findings,
)
from tests.providers.aws.test_aws_storage_rules import (
    _lifecycle as _aws_lifecycle,
)
from tests.providers.aws.test_aws_storage_rules import (
    _object_lock as _aws_object_lock,
)
from tests.providers.aws.test_aws_storage_rules import (
    _versioning as _aws_versioning,
)
from tests.providers.azure.test_azure_storage_rules import (
    _account as _azure_storage_account,
)
from tests.providers.azure.test_azure_storage_rules import (
    _container as _azure_storage_container,
)
from tests.providers.azure.test_azure_storage_rules import (
    _evaluate as _azure_findings,
)
from tests.providers.azure.test_azure_storage_rules import (
    _storage_safe_posture as _azure_storage_safe_posture,
)
from tests.providers.gcp.rule_support.data import (
    _storage_bucket as _gcp_storage_bucket,
)
from tests.providers.gcp.rule_support.data import (
    _storage_bucket_iam_member as _gcp_storage_bucket_iam_member,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import Finding, TerraformResource
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_STORAGE_VERSIONING_RULE_ID = "aws-s3-versioning-disabled"
GCP_STORAGE_VERSIONING_RULE_ID = "gcp-gcs-versioning-disabled"
AZURE_STORAGE_VERSIONING_RULE_ID = "azure-storage-account-blob-versioning-disabled"

AWS_STORAGE_RULE_IDS = frozenset(
    {
        "aws-s3-public-access",
        "aws-s3-customer-managed-encryption-missing",
        AWS_STORAGE_VERSIONING_RULE_ID,
        "aws-s3-object-lock-retention-missing",
        "aws-s3-lifecycle-noncurrent-retention-insufficient",
    }
)
GCP_STORAGE_RULE_IDS = frozenset(
    {
        "gcp-gcs-public-access",
        "gcp-gcs-uniform-bucket-level-access-disabled",
        "gcp-gcs-public-access-prevention-not-enforced",
        GCP_STORAGE_VERSIONING_RULE_ID,
        "gcp-gcs-customer-managed-encryption-missing",
        "gcp-gcs-retention-policy-insufficient",
    }
)
AZURE_STORAGE_RULE_IDS = frozenset(
    {
        "azure-storage-container-public-access",
        "azure-storage-account-nested-public-access-enabled",
        "azure-storage-account-shared-key-enabled",
        "azure-storage-account-minimum-tls-below-1-2",
        "azure-storage-account-public-network-unrestricted",
        "azure-storage-account-customer-managed-key-missing",
        "azure-storage-account-infrastructure-encryption-not-enabled",
        AZURE_STORAGE_VERSIONING_RULE_ID,
        "azure-storage-account-blob-soft-delete-insufficient",
        "azure-storage-account-container-soft-delete-insufficient",
        "azure-storage-account-point-in-time-restore-missing",
        "azure-storage-account-missing-private-endpoint",
    }
)


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _gcp_findings(
    resources: list[TerraformResource],
    rule_ids: frozenset[str],
    *,
    data_sensitivity: str | None = None,
) -> list[Finding]:
    inventory = GcpNormalizer().normalize(resources)
    if data_sensitivity is not None:
        for bucket in inventory.by_type("google_storage_bucket"):
            bucket.data_sensitivity = data_sensitivity
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )


def _finding_ids(findings: list[Finding]) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


def _severity_vector(finding: Finding) -> tuple[int, int, int, int, int, int]:
    reasoning = finding.severity_reasoning
    assert reasoning is not None
    return (
        reasoning.internet_exposure,
        reasoning.privilege_breadth,
        reasoning.data_sensitivity,
        reasoning.lateral_movement,
        reasoning.blast_radius,
        reasoning.final_score,
    )


def _finding_contract(
    finding: Finding,
) -> tuple[str, str, tuple[int, int, int, int, int, int], list[str], str | None, list[tuple[str, list[str]]]]:
    return (
        finding.rule_id,
        finding.severity.value,
        _severity_vector(finding),
        finding.affected_resources,
        finding.trust_boundary_id,
        [(item.key, item.values) for item in finding.evidence],
    )


class StoragePostureParityTests(unittest.TestCase):
    def test_provider_storage_rule_families_are_registered(self) -> None:
        self.assertEqual(
            AWS_STORAGE_RULE_IDS,
            frozenset(rule_id for rule_id in _flatten(AWS_RULE_GROUP_IDS) if rule_id.startswith("aws-s3-")),
        )
        self.assertEqual(
            GCP_STORAGE_RULE_IDS,
            frozenset(rule_id for rule_id in _flatten(GCP_RULE_GROUP_IDS) if rule_id.startswith("gcp-gcs-")),
        )
        self.assertEqual(
            AZURE_STORAGE_RULE_IDS,
            frozenset(rule_id for rule_id in _flatten(AZURE_RULE_GROUP_IDS) if rule_id.startswith("azure-storage-")),
        )

    def test_enabled_versioning_stays_quiet_across_providers(self) -> None:
        aws_findings = _aws_findings(
            [_aws_bucket(), _aws_versioning("Enabled")],
            {AWS_STORAGE_VERSIONING_RULE_ID},
        )
        gcp_findings = _gcp_findings(
            [_gcp_storage_bucket(versioning_enabled=True)],
            frozenset({GCP_STORAGE_VERSIONING_RULE_ID}),
        )
        _, _, azure_findings = _azure_findings(
            [_azure_storage_account(blob_versioning=True)],
            AZURE_STORAGE_VERSIONING_RULE_ID,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_explicitly_disabled_versioning_findings_are_pinned_by_provider(self) -> None:
        aws_findings = _aws_findings(
            [_aws_bucket(), _aws_versioning("Suspended")],
            {AWS_STORAGE_VERSIONING_RULE_ID},
        )
        gcp_findings = _gcp_findings(
            [_gcp_storage_bucket(versioning_enabled=False)],
            frozenset({GCP_STORAGE_VERSIONING_RULE_ID}),
        )
        _, _, azure_findings = _azure_findings(
            [_azure_storage_account(blob_versioning=False)],
            AZURE_STORAGE_VERSIONING_RULE_ID,
        )

        self.assertEqual(
            [_finding_contract(findings[0]) for findings in (aws_findings, gcp_findings, azure_findings)],
            [
                (
                    AWS_STORAGE_VERSIONING_RULE_ID,
                    "medium",
                    (0, 0, 2, 0, 1, 3),
                    ["aws_s3_bucket.logs"],
                    None,
                    [
                        (
                            "target_resource",
                            ["address=aws_s3_bucket.logs", "type=aws_s3_bucket"],
                        ),
                        (
                            "versioning_posture",
                            [
                                "s3_versioning_state=disabled",
                                "versioning_configuration.status=Suspended",
                                "source=aws_s3_bucket_versioning.logs",
                            ],
                        ),
                    ],
                ),
                (
                    GCP_STORAGE_VERSIONING_RULE_ID,
                    "medium",
                    (0, 0, 2, 0, 1, 3),
                    ["google_storage_bucket.logs"],
                    None,
                    [
                        (
                            "data_protection_posture",
                            ["versioning.enabled is false", "data_sensitivity is sensitive"],
                        )
                    ],
                ),
                (
                    AZURE_STORAGE_VERSIONING_RULE_ID,
                    "medium",
                    (0, 0, 2, 0, 1, 3),
                    ["azurerm_storage_account.logs"],
                    None,
                    [
                        (
                            "target_resource",
                            ["address=azurerm_storage_account.logs", "type=azurerm_storage_account"],
                        ),
                        (
                            "versioning_posture",
                            ["blob_properties.versioning_enabled is disabled"],
                        ),
                    ],
                ),
            ],
        )

    def test_unresolved_versioning_findings_are_pinned_by_provider(self) -> None:
        azure_account = _azure_storage_account(blob_versioning=True)
        azure_account.unknown_values["blob_properties"] = [{"versioning_enabled": True}]

        aws_findings = _aws_findings(
            [_aws_bucket(), _aws_versioning(None, unknown=True)],
            {AWS_STORAGE_VERSIONING_RULE_ID},
        )
        gcp_findings = _gcp_findings(
            [
                _gcp_storage_bucket(
                    versioning_enabled=True,
                    unknown_values={"versioning": [{"enabled": True}]},
                )
            ],
            frozenset({GCP_STORAGE_VERSIONING_RULE_ID}),
        )
        _, _, azure_findings = _azure_findings(
            [azure_account],
            AZURE_STORAGE_VERSIONING_RULE_ID,
        )

        self.assertEqual(
            [_finding_contract(findings[0]) for findings in (aws_findings, gcp_findings, azure_findings)],
            [
                (
                    AWS_STORAGE_VERSIONING_RULE_ID,
                    "low",
                    (0, 0, 1, 0, 0, 1),
                    ["aws_s3_bucket.logs"],
                    None,
                    [
                        (
                            "target_resource",
                            ["address=aws_s3_bucket.logs", "type=aws_s3_bucket"],
                        ),
                        (
                            "versioning_posture",
                            [
                                "s3_versioning_state=unknown",
                                "versioning_configuration.status is unknown",
                                "source=aws_s3_bucket_versioning.logs",
                            ],
                        ),
                        (
                            "posture_uncertainty",
                            [
                                "aws_s3_bucket_versioning.logs: "
                                "versioning_configuration.status is unknown after planning"
                            ],
                        ),
                    ],
                ),
                (
                    GCP_STORAGE_VERSIONING_RULE_ID,
                    "medium",
                    (0, 0, 2, 0, 1, 3),
                    ["google_storage_bucket.logs"],
                    None,
                    [
                        (
                            "data_protection_posture",
                            ["versioning.enabled is unset", "data_sensitivity is sensitive"],
                        )
                    ],
                ),
                (
                    AZURE_STORAGE_VERSIONING_RULE_ID,
                    "low",
                    (0, 0, 1, 0, 0, 1),
                    ["azurerm_storage_account.logs"],
                    None,
                    [
                        (
                            "target_resource",
                            ["address=azurerm_storage_account.logs", "type=azurerm_storage_account"],
                        ),
                        (
                            "versioning_posture",
                            ["blob_properties.versioning_enabled is unknown"],
                        ),
                        (
                            "posture_uncertainty",
                            ["blob_properties.versioning_enabled is unknown after planning"],
                        ),
                    ],
                ),
            ],
        )

    def test_missing_versioning_configuration_keeps_provider_specific_meaning(self) -> None:
        gcp_bucket = _gcp_storage_bucket()
        del gcp_bucket.values["versioning"]

        aws_findings = _aws_findings(
            [_aws_bucket()],
            {AWS_STORAGE_VERSIONING_RULE_ID},
        )
        gcp_findings = _gcp_findings(
            [gcp_bucket],
            frozenset({GCP_STORAGE_VERSIONING_RULE_ID}),
        )
        _, _, azure_findings = _azure_findings(
            [_azure_storage_account()],
            AZURE_STORAGE_VERSIONING_RULE_ID,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(
            [_finding_contract(findings[0]) for findings in (gcp_findings, azure_findings)],
            [
                (
                    GCP_STORAGE_VERSIONING_RULE_ID,
                    "medium",
                    (0, 0, 2, 0, 1, 3),
                    ["google_storage_bucket.logs"],
                    None,
                    [
                        (
                            "data_protection_posture",
                            ["versioning.enabled is false", "data_sensitivity is sensitive"],
                        )
                    ],
                ),
                (
                    AZURE_STORAGE_VERSIONING_RULE_ID,
                    "low",
                    (0, 0, 1, 0, 0, 1),
                    ["azurerm_storage_account.logs"],
                    None,
                    [
                        (
                            "target_resource",
                            ["address=azurerm_storage_account.logs", "type=azurerm_storage_account"],
                        ),
                        (
                            "versioning_posture",
                            ["blob_properties.versioning_enabled is unknown"],
                        ),
                    ],
                ),
            ],
        )

    def test_gcp_versioning_rule_remains_scoped_to_sensitive_buckets(self) -> None:
        findings = _gcp_findings(
            [_gcp_storage_bucket(versioning_enabled=False)],
            frozenset({GCP_STORAGE_VERSIONING_RULE_ID}),
            data_sensitivity="standard",
        )

        self.assertEqual(findings, [])

    def test_unsafe_storage_posture_exercises_each_provider_family(self) -> None:
        aws_findings = _aws_findings(
            [
                _aws_bucket(acl="public-read"),
                _aws_encryption(algorithm="AES256"),
                _aws_versioning("Suspended"),
                _aws_object_lock(include_default_retention=False),
                _aws_lifecycle(noncurrent_days=1),
            ],
            set(AWS_STORAGE_RULE_IDS),
        )
        gcp_findings = _gcp_findings(
            [
                _gcp_storage_bucket(
                    public_access_prevention="inherited",
                    uniform_bucket_level_access=False,
                    versioning_enabled=False,
                    default_kms_key_name=None,
                ),
                _gcp_storage_bucket_iam_member(),
            ],
            GCP_STORAGE_RULE_IDS,
        )
        _, _, azure_findings = _azure_findings(
            [
                _azure_storage_account(
                    allow_public=True,
                    shared_key=True,
                    min_tls="TLS1_1",
                    public_network=True,
                    infrastructure_encryption=False,
                    blob_versioning=False,
                ),
                _azure_storage_container("blob"),
            ],
            *AZURE_STORAGE_RULE_IDS,
        )

        self.assertEqual(_finding_ids(aws_findings), AWS_STORAGE_RULE_IDS)
        self.assertEqual(_finding_ids(gcp_findings), GCP_STORAGE_RULE_IDS)
        self.assertEqual(_finding_ids(azure_findings), AZURE_STORAGE_RULE_IDS)

    def test_hardened_storage_posture_stays_quiet_across_providers(self) -> None:
        aws_findings = _aws_findings(
            [
                _aws_bucket(),
                _aws_encryption(
                    algorithm="aws:kms",
                    kms_master_key_id="arn:aws:kms:us-east-1:111122223333:key/storage",
                ),
                _aws_versioning("Enabled"),
                _aws_object_lock(days=30, mode="GOVERNANCE"),
                _aws_lifecycle(noncurrent_days=30),
            ],
            set(AWS_STORAGE_RULE_IDS),
        )
        gcp_findings = _gcp_findings(
            [
                _gcp_storage_bucket(
                    public_access_prevention="enforced",
                    uniform_bucket_level_access=True,
                    versioning_enabled=True,
                    retention_policy={"retention_period": 2_592_000, "is_locked": True},
                )
            ],
            GCP_STORAGE_RULE_IDS,
        )
        _, _, azure_findings = _azure_findings(
            [
                _azure_storage_account(
                    allow_public=False,
                    shared_key=False,
                    min_tls="TLS1_2",
                    public_network=False,
                    default_action="Deny",
                    **_azure_storage_safe_posture(),
                ),
                _azure_storage_container("private"),
            ],
            *AZURE_STORAGE_RULE_IDS,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])


if __name__ == "__main__":
    unittest.main()

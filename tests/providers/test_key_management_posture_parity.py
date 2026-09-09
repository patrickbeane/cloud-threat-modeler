from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_kms_rules import _KMS_DELETION_WINDOW_RULE as _AWS_KMS_DELETION_WINDOW_RULE
from tests.providers.aws.test_aws_kms_rules import _KMS_ROTATION_RULE as _AWS_KMS_ROTATION_RULE
from tests.providers.aws.test_aws_kms_rules import _kms_key as _aws_kms_key
from tests.providers.azure.test_azure_key_vault_rules import _evaluate as _azure_findings
from tests.providers.azure.test_azure_key_vault_rules import _key as _azure_key
from tests.providers.azure.test_azure_key_vault_rules import _rotation_policy as _azure_rotation_policy
from tests.providers.azure.test_azure_key_vault_rules import _vault as _azure_vault
from tests.providers.gcp.test_gcp_kms_rules import _KMS_DESTROY_RULE_ID as _GCP_KMS_DESTROY_RULE
from tests.providers.gcp.test_gcp_kms_rules import _KMS_ROTATION_RULE_ID as _GCP_KMS_ROTATION_RULE
from tests.providers.gcp.test_gcp_kms_rules import _kms_key as _gcp_kms_key
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import Finding, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_AZURE_KEY_ROTATION_RULE = "azure-key-vault-key-rotation-policy-incomplete"
AWS_KEY_MANAGEMENT_RULE_IDS = frozenset({_AWS_KMS_ROTATION_RULE, _AWS_KMS_DELETION_WINDOW_RULE})
GCP_KEY_MANAGEMENT_RULE_IDS = frozenset({_GCP_KMS_ROTATION_RULE, _GCP_KMS_DESTROY_RULE})
AZURE_KEY_MANAGEMENT_RULE_IDS = frozenset({_AZURE_KEY_ROTATION_RULE})
ALL_KEY_MANAGEMENT_RULE_IDS = AWS_KEY_MANAGEMENT_RULE_IDS | GCP_KEY_MANAGEMENT_RULE_IDS | AZURE_KEY_MANAGEMENT_RULE_IDS


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _finding_ids(findings: list[Finding]) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


def _evaluate_aws(resources: list[TerraformResource], rule_ids: frozenset[str]) -> list[Finding]:
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )


def _evaluate_gcp(
    resources: list[TerraformResource],
    rule_ids: frozenset[str],
    *,
    data_sensitivity: str | None = None,
) -> list[Finding]:
    inventory = GcpNormalizer().normalize(resources)
    if data_sensitivity is not None:
        for key in inventory.by_type("google_kms_crypto_key"):
            key.data_sensitivity = data_sensitivity
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )


def _evaluate_azure(resources: list[TerraformResource], rule_ids: frozenset[str]) -> list[Finding]:
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )


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


def _evidence_by_key(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


class KeyManagementPostureParityTests(unittest.TestCase):
    def test_provider_key_management_rule_families_are_registered(self) -> None:
        self.assertLessEqual(AWS_KEY_MANAGEMENT_RULE_IDS, _flatten(AWS_RULE_GROUP_IDS))
        self.assertLessEqual(GCP_KEY_MANAGEMENT_RULE_IDS, _flatten(GCP_RULE_GROUP_IDS))
        self.assertLessEqual(AZURE_KEY_MANAGEMENT_RULE_IDS, _flatten(AZURE_RULE_GROUP_IDS))

    def test_missing_or_disabled_rotation_findings_pin_exact_provider_contracts(self) -> None:
        aws_disabled = _evaluate_aws(
            [_aws_kms_key(enable_key_rotation=False)],
            frozenset({_AWS_KMS_ROTATION_RULE}),
        )
        aws_missing = _evaluate_aws(
            [_aws_kms_key()],
            frozenset({_AWS_KMS_ROTATION_RULE}),
        )
        gcp_missing = _evaluate_gcp(
            [_gcp_kms_key()],
            frozenset({_GCP_KMS_ROTATION_RULE}),
        )
        _, _, azure_missing = _azure_findings(
            [_azure_vault(public_network=False), _azure_key()],
            _AZURE_KEY_ROTATION_RULE,
        )

        self.assertEqual(len(aws_disabled), 1)
        self.assertEqual(len(aws_missing), 1)
        self.assertEqual(len(gcp_missing), 1)
        self.assertEqual(len(azure_missing), 1)
        self.assertEqual(_finding_contract(aws_missing[0]), _finding_contract(aws_disabled[0]))
        self.assertEqual(
            [
                _finding_contract(aws_disabled[0]),
                _finding_contract(gcp_missing[0]),
                _finding_contract(azure_missing[0]),
            ],
            [
                (
                    _AWS_KMS_ROTATION_RULE,
                    "medium",
                    (0, 0, 2, 0, 1, 3),
                    ["aws_kms_key.customer"],
                    None,
                    [
                        (
                            "target_resource",
                            [
                                "address=aws_kms_key.customer",
                                "type=aws_kms_key",
                                "identifier=customer",
                                "arn=arn:aws:kms:us-east-1:111122223333:key/customer",
                            ],
                        ),
                        (
                            "key_posture",
                            [
                                "key_usage=ENCRYPT_DECRYPT",
                                "key_spec=unset",
                                "customer_master_key_spec=unset",
                                "origin=AWS_KMS",
                                "custom_key_store_id=unset",
                                "xks_key_id=unset",
                                "multi_region_state=disabled",
                            ],
                        ),
                        (
                            "rotation_posture",
                            [
                                "enable_key_rotation_state=disabled",
                                "rotation_period_in_days=unset",
                                "default_rotation_period_days=365",
                                "tfstride_rotation_baseline_max_days=365",
                                "rotation_posture_state=disabled",
                                "enable_key_rotation is false",
                                "automatic rotation is evaluated only for symmetric ENCRYPT_DECRYPT keys "
                                "with AWS_KMS origin outside custom key stores",
                            ],
                        ),
                    ],
                ),
                (
                    _GCP_KMS_ROTATION_RULE,
                    "medium",
                    (0, 0, 2, 0, 1, 3),
                    ["google_kms_crypto_key.customer"],
                    None,
                    [
                        (
                            "target_resource",
                            [
                                "address=google_kms_crypto_key.customer",
                                "type=google_kms_crypto_key",
                                "identifier=projects/tfstride-demo/locations/global/keyRings/"
                                "tfstride-app/cryptoKeys/tfstride-customer-key",
                            ],
                        ),
                        (
                            "rotation_issues",
                            ["rotation_period is missing"],
                        ),
                        (
                            "rotation_posture",
                            [
                                "purpose=ENCRYPT_DECRYPT",
                                "rotation_period=unset",
                                "rotation_period_state=missing",
                                "maximum_rotation_period_days=90",
                                "maximum_rotation_period_seconds=7776000",
                            ],
                        ),
                    ],
                ),
                (
                    _AZURE_KEY_ROTATION_RULE,
                    "medium",
                    (0, 0, 2, 0, 1, 3),
                    [
                        "azurerm_key_vault_key.signing",
                        "azurerm_key_vault.application",
                    ],
                    None,
                    [
                        (
                            "target_resource",
                            [
                                "address=azurerm_key_vault_key.signing",
                                "type=azurerm_key_vault_key",
                                "identifier=signing",
                                "key_vault_reference=azurerm_key_vault.application.id",
                                "resolved_key_vault_address=azurerm_key_vault.application",
                            ],
                        ),
                        (
                            "rotation_issues",
                            ["key has no rotation_policy"],
                        ),
                        (
                            "key_posture",
                            [
                                "key_type=RSA",
                                "key_size=2048",
                                "curve=unset",
                                "key_ops=encrypt, decrypt, sign, verify",
                                "minimum_rsa_key_size_bits=2048",
                                "expiration_date=unset",
                                "not_before_date=unset",
                                "maximum_key_expiry_days=730",
                                "maximum_rotation_interval_days=365",
                            ],
                        ),
                        (
                            "rotation_policy",
                            [
                                "rotation_policy_present=false",
                                "expire_after=unset",
                                "notify_before_expiry=unset",
                                "automatic.time_after_creation=unset",
                                "automatic.time_before_expiry=unset",
                            ],
                        ),
                    ],
                ),
            ],
        )

    def test_excessive_rotation_and_expiry_intervals_pin_thresholds_and_issue_order(self) -> None:
        aws_findings = _evaluate_aws(
            [
                _aws_kms_key(
                    enable_key_rotation=True,
                    rotation_period_in_days=366,
                )
            ],
            frozenset({_AWS_KMS_ROTATION_RULE}),
        )
        gcp_findings = _evaluate_gcp(
            [_gcp_kms_key(rotation_period="7776001s")],
            frozenset({_GCP_KMS_ROTATION_RULE}),
        )
        _, _, azure_findings = _azure_findings(
            [
                _azure_vault(public_network=False),
                _azure_key(
                    rotation_policy=_azure_rotation_policy(
                        expire_after="P731D",
                        time_after_creation="P366D",
                    ),
                    not_before_date="2026-01-01T00:00:00Z",
                    expiration_date="2028-01-02T00:00:00Z",
                ),
            ],
            _AZURE_KEY_ROTATION_RULE,
        )

        findings = [aws_findings[0], gcp_findings[0], azure_findings[0]]
        self.assertEqual(
            [(finding.severity.value, _severity_vector(finding)) for finding in findings],
            [("medium", (0, 0, 2, 0, 1, 3))] * 3,
        )
        self.assertEqual(
            _evidence_by_key(aws_findings[0])["rotation_posture"],
            [
                "enable_key_rotation_state=enabled",
                "rotation_period_in_days=366",
                "default_rotation_period_days=365",
                "tfstride_rotation_baseline_max_days=365",
                "rotation_posture_state=too_long",
                "enable_key_rotation is true",
                "effective_rotation_period_days=366",
                "automatic rotation is evaluated only for symmetric ENCRYPT_DECRYPT keys "
                "with AWS_KMS origin outside custom key stores",
            ],
        )
        self.assertEqual(
            _evidence_by_key(gcp_findings[0]),
            {
                "target_resource": [
                    "address=google_kms_crypto_key.customer",
                    "type=google_kms_crypto_key",
                    "identifier=projects/tfstride-demo/locations/global/keyRings/"
                    "tfstride-app/cryptoKeys/tfstride-customer-key",
                ],
                "rotation_issues": [
                    "rotation_period is 7776001 seconds; maximum is 7776000 seconds",
                ],
                "rotation_posture": [
                    "purpose=ENCRYPT_DECRYPT",
                    "rotation_period=7776001s",
                    "rotation_period_state=too_long",
                    "maximum_rotation_period_days=90",
                    "maximum_rotation_period_seconds=7776000",
                    "rotation_period_seconds=7776001",
                ],
            },
        )
        self.assertEqual(
            [item.key for item in azure_findings[0].evidence],
            [
                "target_resource",
                "rotation_issues",
                "key_posture",
                "rotation_policy",
            ],
        )
        azure_evidence = _evidence_by_key(azure_findings[0])
        self.assertEqual(
            azure_evidence["rotation_issues"],
            [
                "rotation_policy.expire_after is P731D (731 days); maximum is 730 days",
                "rotation_policy.automatic.time_after_creation is P366D (366 days); maximum is 365 days",
                "configured key lifetime is 731 days; maximum is 730 days",
            ],
        )
        self.assertEqual(
            azure_evidence["rotation_policy"],
            [
                "rotation_policy_present=true",
                "expire_after=P731D",
                "notify_before_expiry=P30D",
                "automatic.time_after_creation=P366D",
                "automatic.time_before_expiry=unset",
                "expire_after_days=731",
                "automatic_time_after_creation_days=366",
            ],
        )
        self.assertEqual(
            azure_findings[0].affected_resources,
            [
                "azurerm_key_vault_key.signing",
                "azurerm_key_vault.application",
            ],
        )

    def test_aws_unresolved_rotation_is_low_while_gcp_and_azure_stay_quiet(self) -> None:
        aws_findings = _evaluate_aws(
            [_aws_kms_key(unknown_values={"enable_key_rotation": True})],
            frozenset({_AWS_KMS_ROTATION_RULE}),
        )
        gcp_findings = _evaluate_gcp(
            [_gcp_kms_key(unknown_values={"rotation_period": True})],
            frozenset({_GCP_KMS_ROTATION_RULE}),
        )
        _, _, azure_findings = _azure_findings(
            [
                _azure_vault(public_network=False),
                _azure_key(
                    rotation_policy=[{"automatic": [{}]}],
                    unknown_values={
                        "rotation_policy": [
                            {
                                "expire_after": True,
                                "automatic": [{"time_after_creation": True}],
                            }
                        ]
                    },
                ),
            ],
            _AZURE_KEY_ROTATION_RULE,
        )

        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])
        self.assertEqual(len(aws_findings), 1)
        self.assertEqual(aws_findings[0].severity.value, "low")
        self.assertEqual(_severity_vector(aws_findings[0]), (0, 0, 1, 0, 0, 1))
        self.assertEqual(
            [(item.key, item.values) for item in aws_findings[0].evidence],
            [
                (
                    "target_resource",
                    [
                        "address=aws_kms_key.customer",
                        "type=aws_kms_key",
                        "identifier=customer",
                        "arn=arn:aws:kms:us-east-1:111122223333:key/customer",
                    ],
                ),
                (
                    "key_posture",
                    [
                        "key_usage=ENCRYPT_DECRYPT",
                        "key_spec=unset",
                        "customer_master_key_spec=unset",
                        "origin=AWS_KMS",
                        "custom_key_store_id=unset",
                        "xks_key_id=unset",
                        "multi_region_state=disabled",
                    ],
                ),
                (
                    "rotation_posture",
                    [
                        "enable_key_rotation_state=unknown",
                        "rotation_period_in_days=unset",
                        "default_rotation_period_days=365",
                        "tfstride_rotation_baseline_max_days=365",
                        "rotation_posture_state=unknown",
                        "enable_key_rotation is unknown",
                        "automatic rotation is evaluated only for symmetric ENCRYPT_DECRYPT keys "
                        "with AWS_KMS origin outside custom key stores",
                    ],
                ),
                (
                    "posture_uncertainty",
                    ["enable_key_rotation is unknown after planning"],
                ),
            ],
        )

    def test_azure_missing_rotation_controls_remain_ordered_medium_findings(self) -> None:
        cases = (
            (
                "automatic",
                [{"expire_after": "P365D", "notify_before_expiry": "P30D"}],
                ["rotation_policy.automatic is not configured"],
            ),
            (
                "expiry",
                [
                    {
                        "notify_before_expiry": "P30D",
                        "automatic": [{"time_after_creation": "P180D"}],
                    }
                ],
                ["rotation_policy.expire_after is not configured"],
            ),
        )

        for case, rotation_policy, expected_issues in cases:
            with self.subTest(case=case):
                _, _, findings = _azure_findings(
                    [
                        _azure_vault(public_network=False),
                        _azure_key(rotation_policy=rotation_policy),
                    ],
                    _AZURE_KEY_ROTATION_RULE,
                )

                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].severity.value, "medium")
                self.assertEqual(_severity_vector(findings[0]), (0, 0, 2, 0, 1, 3))
                self.assertEqual(
                    findings[0].affected_resources,
                    [
                        "azurerm_key_vault_key.signing",
                        "azurerm_key_vault.application",
                    ],
                )
                self.assertEqual(
                    [item.key for item in findings[0].evidence],
                    [
                        "target_resource",
                        "rotation_issues",
                        "key_posture",
                        "rotation_policy",
                    ],
                )
                self.assertEqual(
                    _evidence_by_key(findings[0])["rotation_issues"],
                    expected_issues,
                )

    def test_rotation_applicability_and_sensitive_key_gates_remain_provider_local(self) -> None:
        aws_findings = _evaluate_aws(
            [
                _aws_kms_key(
                    name="signing",
                    key_usage="SIGN_VERIFY",
                    key_spec="ECC_NIST_P256",
                ),
                _aws_kms_key(
                    name="rsa",
                    key_usage="ENCRYPT_DECRYPT",
                    key_spec="RSA_2048",
                ),
                _aws_kms_key(
                    name="imported",
                    origin="EXTERNAL",
                    enable_key_rotation=False,
                ),
                _aws_kms_key(
                    name="custom_store",
                    custom_key_store_id="cks-1234",
                    enable_key_rotation=False,
                ),
                _aws_kms_key(
                    name="xks",
                    origin="EXTERNAL_KEY_STORE",
                    xks_key_id="xks-key",
                    enable_key_rotation=False,
                ),
                _aws_kms_key(
                    name="unknown_origin",
                    enable_key_rotation=False,
                    unknown_values={"origin": True},
                ),
            ],
            frozenset({_AWS_KMS_ROTATION_RULE}),
        )
        gcp_asymmetric = _evaluate_gcp(
            [_gcp_kms_key(purpose="ASYMMETRIC_SIGN")],
            frozenset({_GCP_KMS_ROTATION_RULE}),
        )
        gcp_standard = _evaluate_gcp(
            [_gcp_kms_key()],
            frozenset({_GCP_KMS_ROTATION_RULE}),
            data_sensitivity="standard",
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_asymmetric, [])
        self.assertEqual(gcp_standard, [])

    def test_missing_or_weak_key_lifecycle_findings_are_pinned_by_provider(self) -> None:
        aws_findings = _evaluate_aws(
            [_aws_kms_key(enable_key_rotation=False, deletion_window_in_days=7)],
            AWS_KEY_MANAGEMENT_RULE_IDS,
        )
        gcp_findings = _evaluate_gcp(
            [_gcp_kms_key(destroy_scheduled_duration="86400s")],
            GCP_KEY_MANAGEMENT_RULE_IDS,
        )
        _, _, azure_findings = _azure_findings(
            [_azure_key()],
            _AZURE_KEY_ROTATION_RULE,
        )

        self.assertEqual(_finding_ids(aws_findings), AWS_KEY_MANAGEMENT_RULE_IDS)
        self.assertEqual(_finding_ids(gcp_findings), GCP_KEY_MANAGEMENT_RULE_IDS)
        self.assertEqual(_finding_ids(azure_findings), AZURE_KEY_MANAGEMENT_RULE_IDS)
        aws_findings_by_rule = {finding.rule_id: finding for finding in aws_findings}
        self.assertIn("rotation", aws_findings_by_rule[_AWS_KMS_ROTATION_RULE].rationale.lower())
        self.assertIn("deletion", aws_findings_by_rule[_AWS_KMS_DELETION_WINDOW_RULE].rationale.lower())
        gcp_findings_by_rule = {finding.rule_id: finding for finding in gcp_findings}
        self.assertIn("rotation", gcp_findings_by_rule[_GCP_KMS_ROTATION_RULE].rationale.lower())
        self.assertIn("destruction", gcp_findings_by_rule[_GCP_KMS_DESTROY_RULE].rationale.lower())
        self.assertIn("rotation", azure_findings[0].rationale.lower())

    def test_configured_key_rotation_thresholds_and_aws_default_stay_quiet(self) -> None:
        aws_findings = _evaluate_aws(
            [
                _aws_kms_key(
                    name="default_period",
                    key_spec="SYMMETRIC_DEFAULT",
                    enable_key_rotation=True,
                ),
                _aws_kms_key(
                    name="bounded_period",
                    key_spec="SYMMETRIC_DEFAULT",
                    enable_key_rotation=True,
                    rotation_period_in_days=365,
                ),
            ],
            frozenset({_AWS_KMS_ROTATION_RULE}),
        )
        gcp_findings = _evaluate_gcp(
            [_gcp_kms_key(rotation_period="7776000s")],
            frozenset({_GCP_KMS_ROTATION_RULE}),
        )
        _, _, azure_findings = _azure_findings(
            [
                _azure_vault(public_network=False),
                _azure_key(
                    rotation_policy=_azure_rotation_policy(
                        expire_after="P730D",
                        time_after_creation="P365D",
                    ),
                    not_before_date="2026-01-01T00:00:00Z",
                    expiration_date="2028-01-01T00:00:00Z",
                ),
            ],
            _AZURE_KEY_ROTATION_RULE,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_asymmetric_or_unknown_key_shapes_are_not_overclaimed(self) -> None:
        aws_findings = _evaluate_aws(
            [
                _aws_kms_key(name="signing", key_usage="SIGN_VERIFY", key_spec="ECC_NIST_P256"),
                _aws_kms_key(
                    name="unknown",
                    deletion_window_in_days=7,
                    unknown_values={
                        "key_spec": True,
                        "enable_key_rotation": True,
                        "deletion_window_in_days": True,
                    },
                ),
            ],
            AWS_KEY_MANAGEMENT_RULE_IDS,
        )
        gcp_findings = _evaluate_gcp(
            [
                _gcp_kms_key(name="signing", purpose="ASYMMETRIC_SIGN"),
                _gcp_kms_key(
                    name="pending",
                    destroy_scheduled_duration="86400s",
                    unknown_values={
                        "rotation_period": True,
                        "destroy_scheduled_duration": True,
                    },
                ),
            ],
            GCP_KEY_MANAGEMENT_RULE_IDS,
        )
        _, _, azure_findings = _azure_findings(
            [
                _azure_key(
                    rotation_policy=[{"automatic": [{}]}],
                    unknown_values={
                        "rotation_policy": [
                            {
                                "expire_after": True,
                                "automatic": [{"time_after_creation": True}],
                            }
                        ]
                    },
                )
            ],
            _AZURE_KEY_ROTATION_RULE,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_key_management_posture_rules_remain_provider_local(self) -> None:
        findings_by_provider = {
            "aws": _evaluate_aws(
                [_aws_kms_key(enable_key_rotation=False, deletion_window_in_days=7)],
                ALL_KEY_MANAGEMENT_RULE_IDS,
            ),
            "gcp": _evaluate_gcp(
                [_gcp_kms_key(destroy_scheduled_duration="86400s")],
                ALL_KEY_MANAGEMENT_RULE_IDS,
            ),
            "azure": _evaluate_azure(
                [_azure_key()],
                ALL_KEY_MANAGEMENT_RULE_IDS,
            ),
        }

        for provider, findings in findings_by_provider.items():
            with self.subTest(provider=provider):
                self.assertTrue(findings)
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))


if __name__ == "__main__":
    unittest.main()

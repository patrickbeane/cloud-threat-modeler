from __future__ import annotations

import unittest
from typing import Any

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_CMEK_RULE = "gcp-firestore-customer-managed-encryption-missing"
_PITR_RULE = "gcp-firestore-point-in-time-recovery-disabled-or-unknown"
_DELETE_PROTECTION_RULE = "gcp-firestore-delete-protection-disabled-or-unknown"
_FIRESTORE_RULE_IDS = (_CMEK_RULE, _PITR_RULE, _DELETE_PROTECTION_RULE)
_KMS_KEY_NAME = "projects/tfstride-demo/locations/us/keyRings/data/cryptoKeys/firestore"
_MISSING = object()


def _database(
    *,
    name: str = "orders",
    cmek_config: object = _MISSING,
    point_in_time_recovery_enablement: object = _MISSING,
    delete_protection_state: object = _MISSING,
    deletion_policy: object = _MISSING,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": f"projects/tfstride-demo/databases/{name}",
        "name": name,
        "project": "tfstride-demo",
        "location_id": "nam5",
        "type": "FIRESTORE_NATIVE",
    }
    if cmek_config is not _MISSING:
        values["cmek_config"] = cmek_config
    if point_in_time_recovery_enablement is not _MISSING:
        values["point_in_time_recovery_enablement"] = point_in_time_recovery_enablement
    if delete_protection_state is not _MISSING:
        values["delete_protection_state"] = delete_protection_state
    if deletion_policy is not _MISSING:
        values["deletion_policy"] = deletion_policy
    return _terraform_resource(
        f"google_firestore_database.{name}",
        "google_firestore_database",
        values,
        unknown_values=unknown_values,
    )


def _hardened_database(*, name: str = "orders") -> TerraformResource:
    return _database(
        name=name,
        cmek_config=[{"kms_key_name": _KMS_KEY_NAME}],
        point_in_time_recovery_enablement="POINT_IN_TIME_RECOVERY_ENABLED",
        delete_protection_state="DELETE_PROTECTION_ENABLED",
        deletion_policy="ABANDON",
    )


def _findings(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or _FIRESTORE_RULE_IDS)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpFirestoreRuleTests(unittest.TestCase):
    def test_firestore_rules_are_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}
        self.assertTrue(set(_FIRESTORE_RULE_IDS).issubset(registered))

    def test_google_managed_encryption_and_disabled_recovery_controls_are_detected(
        self,
    ) -> None:
        findings = _findings(
            [
                _database(
                    point_in_time_recovery_enablement="POINT_IN_TIME_RECOVERY_DISABLED",
                    delete_protection_state="DELETE_PROTECTION_DISABLED",
                    deletion_policy="DELETE",
                )
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], list(_FIRESTORE_RULE_IDS))
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual(findings_by_rule[_CMEK_RULE].severity.value, "low")
        self.assertEqual(findings_by_rule[_PITR_RULE].severity.value, "medium")
        self.assertEqual(findings_by_rule[_DELETE_PROTECTION_RULE].severity.value, "medium")

        cmek_finding = findings_by_rule[_CMEK_RULE]
        self.assertIn("Google-managed Firestore encryption", cmek_finding.rationale)
        self.assertNotIn("unencrypted", cmek_finding.rationale.lower())
        self.assertEqual(
            _evidence_by_key(cmek_finding)["encryption_ownership"],
            [
                "cmek_state=not_configured",
                "kms_key_name=unset",
                "storage_encrypted=true",
                "encryption_provider=Google-managed Firestore encryption",
                "finding_scope=customer-managed key ownership and control posture",
            ],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule[_PITR_RULE])["recovery_posture"],
            [
                "point_in_time_recovery_state=disabled",
                "point_in_time_recovery_enablement=POINT_IN_TIME_RECOVERY_DISABLED",
            ],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule[_DELETE_PROTECTION_RULE])["delete_protection"],
            [
                "service_delete_protection_state=disabled",
                "delete_protection_value=DELETE_PROTECTION_DISABLED",
                "terraform_deletion_policy=DELETE",
                "terraform_deletion_policy_state=configured",
                ("Terraform deletion policy is separate from the Firestore service delete-protection control"),
            ],
        )

    def test_hardened_database_is_quiet(self) -> None:
        self.assertEqual(_findings([_hardened_database()]), [])

    def test_omitted_controls_emit_without_claiming_explicit_disablement(self) -> None:
        findings = _findings([_database()])

        self.assertEqual([finding.rule_id for finding in findings], list(_FIRESTORE_RULE_IDS))
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        self.assertIn("Google-managed Firestore encryption", findings_by_rule[_CMEK_RULE].rationale)
        self.assertIn("does not configure", findings_by_rule[_PITR_RULE].rationale)
        self.assertIn("does not configure", findings_by_rule[_DELETE_PROTECTION_RULE].rationale)
        self.assertNotIn("explicitly disables", findings_by_rule[_PITR_RULE].rationale)
        self.assertNotIn("explicitly disables", findings_by_rule[_DELETE_PROTECTION_RULE].rationale)

    def test_unknown_recovery_controls_emit_lower_severity_without_disabled_claims(self) -> None:
        findings = _findings(
            [
                _database(
                    cmek_config=[{"kms_key_name": _KMS_KEY_NAME}],
                    unknown_values={
                        "point_in_time_recovery_enablement": True,
                        "delete_protection_state": True,
                    },
                )
            ]
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [_PITR_RULE, _DELETE_PROTECTION_RULE],
        )
        for finding in findings:
            self.assertEqual(finding.severity.value, "low")
            self.assertNotIn("disabled", finding.rationale.lower())

        findings_by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual(
            _evidence_by_key(findings_by_rule[_PITR_RULE])["posture_uncertainty"],
            ["point_in_time_recovery_enablement is unknown after planning"],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule[_DELETE_PROTECTION_RULE])["posture_uncertainty"],
            ["delete_protection_state is unknown after planning"],
        )

    def test_unknown_cmek_does_not_become_google_managed_encryption_claim(self) -> None:
        findings = _findings(
            [
                _database(
                    point_in_time_recovery_enablement="POINT_IN_TIME_RECOVERY_ENABLED",
                    delete_protection_state="DELETE_PROTECTION_ENABLED",
                    unknown_values={"cmek_config": True},
                )
            ],
            _CMEK_RULE,
        )

        self.assertEqual(findings, [])

    def test_terraform_abandon_policy_does_not_replace_service_delete_protection(self) -> None:
        findings = _findings(
            [
                _database(
                    cmek_config=[{"kms_key_name": _KMS_KEY_NAME}],
                    point_in_time_recovery_enablement="POINT_IN_TIME_RECOVERY_ENABLED",
                    delete_protection_state="DELETE_PROTECTION_DISABLED",
                    deletion_policy="ABANDON",
                )
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DELETE_PROTECTION_RULE])
        evidence = _evidence_by_key(findings[0])["delete_protection"]
        self.assertIn("terraform_deletion_policy=ABANDON", evidence)
        self.assertIn("service delete protection", findings[0].rationale)

    def test_firestore_rules_do_not_infer_security_rules_or_public_access(self) -> None:
        findings = _findings([_database()])

        text = " ".join(
            [finding.rule_id + " " + finding.rationale for finding in findings]
            + [value for finding in findings for item in finding.evidence for value in item.values]
        ).lower()
        self.assertNotIn("security rules", text)
        self.assertNotIn("public access", text)


if __name__ == "__main__":
    unittest.main()

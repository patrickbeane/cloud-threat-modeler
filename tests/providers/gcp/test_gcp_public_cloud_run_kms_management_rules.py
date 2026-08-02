from __future__ import annotations

import unittest

from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _key,
    _key_member,
    _project_member,
    _ring_member,
    _version,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _as_resource,
    _evidence,
    _public_cloud_run,
    _public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_DISRUPTION_RULE = "gcp-public-cloud-run-kms-key-disruption"
_DELEGATION_RULE = "gcp-public-cloud-run-kms-authorization-delegation"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    return StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


class GcpPublicCloudRunKmsManagementRuleTests(unittest.TestCase):
    def test_rules_are_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_DISRUPTION_RULE, registered)
        self.assertIn(_DELEGATION_RULE, registered)

    def test_public_project_management_emits_distinct_findings_and_counts_grants_once(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_key("data", "ENCRYPT_DECRYPT")),
                _as_resource(_key("secondary", "ENCRYPT_DECRYPT")),
                _as_resource(_version("data", "GOOGLE_SYMMETRIC_ENCRYPTION")),
                _as_resource(_project_member("runtime_admin", "roles/cloudkms.admin")),
            ],
            _DISRUPTION_RULE,
            _DELEGATION_RULE,
        )

        self.assertEqual(
            {finding.rule_id for finding in findings},
            {_DISRUPTION_RULE, _DELEGATION_RULE},
        )
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        disruption = findings_by_rule[_DISRUPTION_RULE]
        delegation = findings_by_rule[_DELEGATION_RULE]
        self.assertEqual(disruption.category, StrideCategory.DENIAL_OF_SERVICE)
        self.assertEqual(delegation.category, StrideCategory.ELEVATION_OF_PRIVILEGE)
        self.assertEqual(disruption.trust_boundary_id, f"internet-to-service:internet->{_WORKLOAD_ADDRESS}")
        self.assertEqual(delegation.trust_boundary_id, f"internet-to-service:internet->{_WORKLOAD_ADDRESS}")
        assert disruption.severity_reasoning is not None
        assert delegation.severity_reasoning is not None
        self.assertEqual(disruption.severity_reasoning.blast_radius, 2)
        self.assertEqual(delegation.severity_reasoning.blast_radius, 2)
        self.assertIn("Cloud KMS disruption authority", disruption.rationale)
        self.assertIn("authorization-delegation authority", delegation.rationale)

        disruption_evidence = _evidence(disruption)
        delegation_evidence = _evidence(delegation)
        self.assertEqual(
            disruption_evidence["scope_breadth"],
            [
                "project_grants=1; key_ring_grants=0; exact_key_grants=0; "
                "target_paths=2; modeled_targets=1; modeled_keys=1; modeled_versions=1; "
                "blast_radius_basis=project_applicable_grant"
            ],
        )
        self.assertEqual(
            delegation_evidence["scope_breadth"],
            [
                "project_grants=1; key_ring_grants=0; exact_key_grants=0; "
                "target_paths=3; modeled_targets=3; modeled_keys=2; modeled_versions=0; "
                "blast_radius_basis=project_applicable_grant"
            ],
        )
        self.assertTrue(
            all("management_effect=disruption" in value for value in disruption_evidence["kms_management_paths"])
        )
        self.assertTrue(
            all("management_effect=delegation" in value for value in delegation_evidence["kms_management_paths"])
        )
        self.assertIn("iam_scope_is_key_version=false", disruption_evidence["authorization_scope"][1])

    def test_public_key_ring_and_exact_key_scopes_have_distinct_breadth(self) -> None:
        ring_findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_key("data", "ENCRYPT_DECRYPT")),
                _as_resource(_key("secondary", "ENCRYPT_DECRYPT")),
                _as_resource(_ring_member("runtime_ring_admin", "roles/cloudkms.admin")),
            ],
            _DELEGATION_RULE,
        )
        exact_findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_key("data", "ENCRYPT_DECRYPT")),
                _as_resource(_key_member("runtime_key_admin", "data", "roles/cloudkms.admin")),
            ],
            _DELEGATION_RULE,
        )

        self.assertEqual(len(ring_findings), 1)
        self.assertEqual(len(exact_findings), 1)
        assert ring_findings[0].severity_reasoning is not None
        assert exact_findings[0].severity_reasoning is not None
        self.assertEqual(ring_findings[0].severity_reasoning.blast_radius, 2)
        self.assertEqual(exact_findings[0].severity_reasoning.blast_radius, 1)
        self.assertIn(
            "key_ring_grants=1; exact_key_grants=0;",
            _evidence(ring_findings[0])["scope_breadth"][0],
        )
        self.assertIn(
            "key_ring_grants=0; exact_key_grants=1;",
            _evidence(exact_findings[0])["scope_breadth"][0],
        )

    def test_private_cloud_run_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(public_ingress=False),
                _public_invoker(),
                _as_resource(_key("data", "ENCRYPT_DECRYPT")),
                _as_resource(_project_member("runtime_admin", "roles/cloudkms.admin")),
            ],
            _DISRUPTION_RULE,
            _DELEGATION_RULE,
        )
        self.assertEqual(findings, [])

    def test_conditioned_management_grant_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_key("data", "ENCRYPT_DECRYPT")),
                _as_resource(
                    _project_member(
                        "runtime_admin",
                        "roles/cloudkms.admin",
                        condition={
                            "title": "business-hours",
                            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
                        },
                    )
                ),
            ],
            _DISRUPTION_RULE,
            _DELEGATION_RULE,
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()

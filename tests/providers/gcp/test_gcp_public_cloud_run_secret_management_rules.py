from __future__ import annotations

import unittest

from tests.providers.gcp.test_gcp_cloud_run_secret_management_paths import (
    _cloud_run,
    _project_member,
    _secret,
    _secret_member,
    _version,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _evidence,
    _public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_TAMPERING_RULE = "gcp-public-cloud-run-secret-tampering"
_DISRUPTION_RULE = "gcp-public-cloud-run-secret-disruption"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_SECRET_ADDRESS = "google_secret_manager_secret.orders"
_VERSION_ADDRESS = "google_secret_manager_secret_version.orders"
_SECRET_IAM_ADDRESS = "google_secret_manager_secret_iam_member.runtime"
_PUBLIC_INVOKER_ADDRESS = "google_cloud_run_v2_service_iam_member.public_invoker"
_PROJECT = "tfstride-demo"


def _public_cloud_run() -> TerraformResource:
    workload = _cloud_run()
    workload.values["ingress"] = "INGRESS_TRAFFIC_ALL"
    return workload


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


class GcpPublicCloudRunSecretManagementRuleTests(unittest.TestCase):
    def test_rules_are_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_TAMPERING_RULE, registered)
        self.assertIn(_DISRUPTION_RULE, registered)

    def test_public_admin_emits_tampering_and_disruption_with_operation_exact_evidence(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _secret(),
                _version(),
                _project_member(),
            ],
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
        self.assertEqual(
            tampering.trust_boundary_id,
            f"internet-to-service:internet->{_WORKLOAD_ADDRESS}",
        )
        self.assertEqual(
            disruption.trust_boundary_id,
            f"internet-to-service:internet->{_WORKLOAD_ADDRESS}",
        )
        self.assertIn(_SECRET_ADDRESS, tampering.affected_resources)
        self.assertIn(_VERSION_ADDRESS, disruption.affected_resources)
        self.assertIn("secret-version addition", tampering.rationale)
        self.assertIn("secret-version destruction", disruption.rationale)

        tampering_evidence = _evidence(tampering)
        disruption_evidence = _evidence(disruption)
        self.assertTrue(
            any(
                "operation=secretmanager.versions.add" in value and "management_effect=tampering" in value
                for value in tampering_evidence["secret_management_paths"]
            )
        )
        self.assertTrue(
            any(
                "operation=secretmanager.versions.destroy" in value and "target_type=secret_version" in value
                for value in disruption_evidence["secret_management_paths"]
            )
        )
        self.assertIn(
            "scope_type=project",
            disruption_evidence["secret_management_paths"][0],
        )
        self.assertIn("version_destroy_ttl=604800s", disruption_evidence["recovery_evidence"][0])
        self.assertIn("recovery_state=version_destroy_delay", disruption_evidence["recovery_evidence"][0])
        self.assertNotIn("recovery_evidence", tampering_evidence)

    def test_secret_version_adder_emits_only_tampering(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _secret(),
                _project_member(role="roles/secretmanager.secretVersionAdder"),
            ],
            _TAMPERING_RULE,
            _DISRUPTION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_TAMPERING_RULE])
        self.assertIn(
            "secretmanager.versions.add",
            _evidence(findings[0])["authorization_scope"][0],
        )

    def test_version_manager_emits_disruption_for_disable_and_destroy(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _secret(),
                _version(),
                _project_member(role="roles/secretmanager.secretVersionManager"),
            ],
            _DISRUPTION_RULE,
        )

        self.assertEqual(len(findings), 1)
        evidence = _evidence(findings[0])
        operations = {value.split(";", 1)[0] for value in evidence["secret_management_paths"]}
        self.assertEqual(
            operations,
            {
                "operation=secretmanager.versions.disable",
                "operation=secretmanager.versions.destroy",
            },
        )
        self.assertEqual(len(evidence["recovery_evidence"]), 1)

    def test_secret_delete_does_not_claim_version_destroy_recovery(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _secret(),
                _project_member(),
            ],
            _DISRUPTION_RULE,
        )

        self.assertEqual(len(findings), 1)
        evidence = _evidence(findings[0])
        self.assertTrue(
            all("operation=secretmanager.secrets.delete" in value for value in evidence["secret_management_paths"])
        )
        self.assertNotIn("recovery_evidence", evidence)

    def test_exact_secret_scope_is_preserved(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _secret(),
                _secret_member(
                    role="roles/secretmanager.secretVersionAdder",
                    secret_reference="projects/tfstride-demo/secrets/orders",
                ),
            ],
            _TAMPERING_RULE,
        )

        self.assertEqual(len(findings), 1)
        evidence = _evidence(findings[0])
        self.assertIn("scope_type=secret", evidence["secret_management_paths"][0])
        self.assertEqual(
            evidence["scope_breadth"],
            [
                "project_grants=0; secret_grants=1; modeled_secrets=1; modeled_versions=0; "
                "target_paths=1; modeled_targets=1; blast_radius_basis=secret_scoped_grants"
            ],
        )

    def test_private_or_conditioned_invocation_stays_quiet(self) -> None:
        private = _cloud_run()
        conditioned_invoker = _public_invoker(
            condition={"title": "only-internal", "expression": "request.auth != null"}
        )
        findings = _evaluate(
            [
                private,
                conditioned_invoker,
                _secret(),
                _project_member(),
            ],
            _TAMPERING_RULE,
            _DISRUPTION_RULE,
        )
        self.assertEqual(findings, [])

    def test_unknown_or_conditional_lifecycle_authority_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _secret(),
                _secret_member(
                    role="roles/secretmanager.secretVersionAdder",
                    condition={"title": "orders-only", "expression": "resource.name.endsWith('orders')"},
                ),
            ],
            _TAMPERING_RULE,
            _DISRUPTION_RULE,
        )
        self.assertEqual(findings, [])

    def test_removed_current_grant_suppresses_copied_management_path(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _public_cloud_run(),
                _public_invoker(),
                _secret(),
                _project_member(role="roles/secretmanager.secretVersionAdder"),
            ]
        )
        secret = inventory.get_by_address(_SECRET_ADDRESS)
        assert secret is not None
        object.__setattr__(secret, "_decoration_state_frozen", False)
        gcp_facts(secret).set_secret_manager_iam_posture(grants=[], uncertainties=[])
        object.__setattr__(secret, "_decoration_state_frozen", True)
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_TAMPERING_RULE})),
        )
        self.assertEqual(findings, [])

    def test_extra_copied_matched_permission_suppresses_finding(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _public_cloud_run(),
                _public_invoker(),
                _secret(),
                _project_member(role="roles/secretmanager.secretVersionAdder"),
            ]
        )
        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = [path.copy() for path in gcp_facts(workload).cloud_run_secret_management_paths]
        path = next(path for path in paths if path["operation"] == "secretmanager.versions.add")
        path["matched_permissions"] = [
            "secretmanager.versions.add",
            "secretmanager.secrets.delete",
        ]
        object.__setattr__(workload, "_decoration_state_frozen", False)
        gcp_facts(workload).set_cloud_run_secret_management_paths(paths)
        object.__setattr__(workload, "_decoration_state_frozen", True)

        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_TAMPERING_RULE})),
        )
        self.assertEqual(findings, [])

    def test_incorrect_copied_target_resource_type_suppresses_finding(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _public_cloud_run(),
                _public_invoker(),
                _secret(),
                _project_member(role="roles/secretmanager.secretVersionAdder"),
            ]
        )
        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = [path.copy() for path in gcp_facts(workload).cloud_run_secret_management_paths]
        path = next(path for path in paths if path["operation"] == "secretmanager.versions.add")
        path["target_resource_type"] = "google_secret_manager_secret_version"
        object.__setattr__(workload, "_decoration_state_frozen", False)
        gcp_facts(workload).set_cloud_run_secret_management_paths(paths)
        object.__setattr__(workload, "_decoration_state_frozen", True)

        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_TAMPERING_RULE})),
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()

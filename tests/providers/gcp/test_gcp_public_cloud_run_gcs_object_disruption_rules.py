from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_gcs_object_deletion_paths import (
    _BUCKET_ADDRESS,
    _PROJECT,
    _bucket,
    _bucket_member,
    _custom_role,
    _project_member,
)
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_mutation_rules import (
    _PUBLIC_INVOKER_ADDRESS,
    _cloud_run,
    _public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_RULE_ID = "gcp-public-cloud-run-gcs-object-disruption"
_MUTATION_RULE_ID = "gcp-public-cloud-run-gcs-mutation-access"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    findings = StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or {_RULE_ID})),
    )
    return inventory, findings


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


def _cloud_run_with_service_account(email: str) -> TerraformResource:
    return _terraform_resource(
        _WORKLOAD_ADDRESS,
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        {
            "name": "orders",
            "project": _PROJECT,
            "location": "us-central1",
            "ingress": "INGRESS_TRAFFIC_ALL",
            "template": [{"service_account": email}],
        },
    )


class GcpPublicCloudRunGcsObjectDisruptionRuleTests(unittest.TestCase):
    def test_public_delete_authority_emits_dos_and_not_gcs_mutation(self) -> None:
        _, findings = _evaluate(
            [
                _cloud_run(),
                _public_invoker(),
                _bucket(),
                _custom_role(role_id="deleteOnly", permissions=["storage.objects.delete"]),
                _bucket_member(role="projects/tfstride-demo/roles/deleteOnly"),
            ],
            _RULE_ID,
            _MUTATION_RULE_ID,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.DENIAL_OF_SERVICE)
        self.assertEqual(
            finding.affected_resources,
            [
                _WORKLOAD_ADDRESS,
                _PUBLIC_INVOKER_ADDRESS,
                _BUCKET_ADDRESS,
                "google_storage_bucket_iam_member.orders_delete",
            ],
        )
        evidence = _evidence(finding)
        self.assertEqual(len(evidence["gcs_object_deletion_paths"]), 2)
        self.assertTrue(
            all("operation=storage.objects.delete" in value for value in evidence["gcs_object_deletion_paths"])
        )
        self.assertTrue(
            any(
                "target_granularity=bucket_object_namespace" in value for value in evidence["gcs_object_deletion_paths"]
            )
        )
        self.assertTrue(
            any(
                "target_granularity=bucket_generation_namespace" in value
                for value in evidence["gcs_object_deletion_paths"]
            )
        )
        self.assertTrue(
            any(
                "recovery_state=soft_deleted_recoverable_during_retention" in value
                for value in evidence["recovery_posture"]
            )
        )
        self.assertTrue(any("scope_type=bucket" in value for value in evidence["authorization_scope"]))
        self.assertTrue(
            any(
                "recovery_state=live_generation_retained_as_noncurrent" in value
                for value in evidence["recovery_posture"]
            )
        )

    def test_project_delete_authority_preserves_project_scope(self) -> None:
        _, findings = _evaluate(
            [_cloud_run(), _public_invoker(), _bucket(), _project_member()],
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence(findings[0])
        self.assertTrue(any("scope_type=project" in value for value in evidence["authorization_scope"]))
        self.assertTrue(any(f"scope={_PROJECT}" in value for value in evidence["authorization_scope"]))

    def test_fully_qualified_project_evidence_revalidates_to_same_project(self) -> None:
        _, findings = _evaluate(
            [
                _cloud_run(),
                _public_invoker(),
                _bucket(project=f"projects/{_PROJECT}"),
                _project_member(project=f"projects/{_PROJECT}"),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence(findings[0])
        self.assertTrue(any("scope_type=project" in value for value in evidence["authorization_scope"]))
        self.assertTrue(any(f"scope={_PROJECT}" in value for value in evidence["authorization_scope"]))

    def test_recovery_state_is_bound_to_deletion_operation_class(self) -> None:
        cases = (
            (
                {"versioning_enabled": True, "soft_delete_seconds": 604_800},
                {
                    "logical_object_deletion": "live_generation_retained_as_noncurrent",
                    "generation_deletion": "soft_deleted_recoverable_during_retention",
                },
            ),
            (
                {"versioning_enabled": True, "soft_delete_seconds": 0},
                {
                    "logical_object_deletion": "live_generation_retained_as_noncurrent",
                    "generation_deletion": "generation_not_protected_by_versioning",
                },
            ),
            (
                {"versioning_enabled": False, "soft_delete_seconds": 604_800},
                {
                    "logical_object_deletion": "soft_deleted_recoverable_during_retention",
                    "generation_deletion": "soft_deleted_recoverable_during_retention",
                },
            ),
            (
                {"versioning_enabled": None, "soft_delete_seconds": 604_800},
                {
                    "logical_object_deletion": "recovery_posture_unknown",
                    "generation_deletion": "soft_deleted_recoverable_during_retention",
                },
            ),
            (
                {"versioning_enabled": None, "soft_delete_seconds": 0},
                {
                    "logical_object_deletion": "recovery_posture_unknown",
                    "generation_deletion": "generation_not_protected_by_versioning",
                },
            ),
        )

        for bucket_options, expected_states in cases:
            with self.subTest(bucket_options=bucket_options):
                _, findings = _evaluate(
                    [
                        _cloud_run(),
                        _public_invoker(),
                        _bucket(**bucket_options),
                        _bucket_member(),
                    ]
                )
                self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
                recovery = _evidence(findings[0])["recovery_posture"]
                for operation_class, state in expected_states.items():
                    matching = [value for value in recovery if f"operation_class={operation_class}" in value]
                    self.assertEqual(len(matching), 1)
                    self.assertIn(f"recovery_state={state}", matching[0])

    def test_unknown_recovery_posture_does_not_suppress_deterministic_delete(self) -> None:
        _, findings = _evaluate(
            [
                _cloud_run(),
                _public_invoker(),
                _bucket(unknown_soft_delete=True),
                _bucket_member(),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence(findings[0])
        self.assertTrue(
            any("recovery_state=recovery_posture_unknown" in value for value in evidence["recovery_posture"])
        )
        self.assertTrue(any("soft_delete_state=unknown" in value for value in evidence["recovery_posture"]))
        self.assertIn("recovery posture is partly unknown", findings[0].rationale.lower())

    def test_versioning_and_retention_evidence_remain_operation_specific(self) -> None:
        _, findings = _evaluate(
            [
                _cloud_run(),
                _public_invoker(),
                _bucket(retention_period="2592000", retention_locked=True),
                _bucket_member(),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence(findings[0])
        self.assertTrue(any("retention_compatibility=unknown" in value for value in evidence["recovery_posture"]))
        self.assertTrue(any("retention_period_seconds=2592000" in value for value in evidence["recovery_posture"]))
        self.assertTrue(
            any(
                "retention_effect=may_block_deletion_until_target_age_is_known" in value
                for value in evidence["recovery_posture"]
            )
        )

    def test_private_cloud_run_stays_quiet(self) -> None:
        _, findings = _evaluate([_cloud_run(public_ingress=False), _public_invoker(), _bucket(), _bucket_member()])

        self.assertEqual(findings, [])

    def test_rule_rejects_unknown_or_unsupported_iam_scope_evidence(self) -> None:
        project_inventory, project_findings = _evaluate([_cloud_run(), _public_invoker(), _bucket(), _project_member()])
        self.assertEqual([finding.rule_id for finding in project_findings], [_RULE_ID])
        project_source = project_inventory.get_by_address("google_project_iam_member.orders_delete")
        assert project_source is not None
        gcp_facts(project_source).set(GcpResourceMetadata.IAM_SCOPE_REFERENCE_STATE, "unknown")
        self.assertEqual(
            StrideRuleEngine().evaluate(
                project_inventory,
                detect_trust_boundaries(project_inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
            ),
            [],
        )

        bucket_inventory, bucket_findings = _evaluate([_cloud_run(), _public_invoker(), _bucket(), _bucket_member()])
        self.assertEqual([finding.rule_id for finding in bucket_findings], [_RULE_ID])
        bucket_source = bucket_inventory.get_by_address("google_storage_bucket_iam_member.orders_delete")
        assert bucket_source is not None
        gcp_facts(bucket_source).set(
            GcpResourceMetadata.BUCKET_NAME,
            "module.dynamic/buckets/tfstride-orders-data",
        )
        self.assertEqual(
            StrideRuleEngine().evaluate(
                bucket_inventory,
                detect_trust_boundaries(bucket_inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
            ),
            [],
        )

    def test_custom_role_definition_lineage_is_revalidated(self) -> None:
        inventory, findings = _evaluate(
            [
                _cloud_run(),
                _public_invoker(),
                _bucket(),
                _custom_role(role_id="roleA"),
                _custom_role(role_id="roleB"),
                _bucket_member(role="projects/tfstride-demo/roles/roleA"),
            ]
        )
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        facts = gcp_facts(workload)
        paths = facts.cloud_run_gcs_object_deletion_paths
        custom_paths = [path for path in paths if path["role_kind"] == "custom"]
        self.assertEqual(len(custom_paths), 2)
        for path in custom_paths:
            path["iam_source_addresses"] = [
                path["iam_source_addresses"][0],
                "google_project_iam_custom_role.roleB",
            ]
        facts.set_cloud_run_gcs_object_deletion_paths(paths)

        self.assertEqual(
            StrideRuleEngine().evaluate(
                inventory,
                detect_trust_boundaries(inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
            ),
            [],
        )

    def test_stale_operation_target_and_iam_evidence_is_rejected(self) -> None:
        inventory, findings = _evaluate([_cloud_run(), _public_invoker(), _bucket(), _bucket_member()])
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        facts = gcp_facts(workload)
        paths = facts.cloud_run_gcs_object_deletion_paths

        for path in paths:
            path["matched_permissions"] = ["storage.objects.delete", "storage.objects.get"]
        facts.set_cloud_run_gcs_object_deletion_paths(paths)
        self.assertEqual(
            StrideRuleEngine().evaluate(
                inventory,
                detect_trust_boundaries(inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
            ),
            [],
        )

        for path in paths:
            path["matched_permissions"] = ["storage.objects.delete"]
            path["target_scope"] = "projects/_/buckets/other/objects/*"
        facts.set_cloud_run_gcs_object_deletion_paths(paths)
        self.assertEqual(
            StrideRuleEngine().evaluate(
                inventory,
                detect_trust_boundaries(inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
            ),
            [],
        )

        for path in paths:
            path["target_scope"] = "projects/_/buckets/tfstride-orders-data/objects/*"
            path["role"] = "roles/storage.objectViewer"
        facts.set_cloud_run_gcs_object_deletion_paths(paths)
        self.assertEqual(
            StrideRuleEngine().evaluate(
                inventory,
                detect_trust_boundaries(inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
            ),
            [],
        )

    def test_wrong_runtime_service_account_stays_quiet(self) -> None:
        _, findings = _evaluate(
            [
                _cloud_run_with_service_account("other@tfstride-demo.iam.gserviceaccount.com"),
                _public_invoker(),
                _bucket(),
                _bucket_member(),
            ]
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()

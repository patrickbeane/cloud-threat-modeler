from __future__ import annotations

import unittest

from tests.providers.gcp.test_gcp_cloud_run_gcs_object_deletion_paths import (
    _BUCKET_ADDRESS,
    _PROJECT,
    _bucket,
    _bucket_member,
    _custom_role,
)
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_object_disruption_rules import (
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

_RULE_ID = "gcp-public-cloud-run-gcs-bucket-topology-disruption"
_MUTATION_RULE_ID = "gcp-public-cloud-run-gcs-mutation-access"
_OBJECT_DISRUPTION_RULE_ID = "gcp-public-cloud-run-gcs-object-disruption"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_ROLE_NAME = f"projects/{_PROJECT}/roles/bucketTopology"
_DELETE_BUCKET = "storage.buckets.delete"


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


class GcpPublicCloudRunGcsBucketTopologyDisruptionRuleTests(unittest.TestCase):
    def test_bucket_deletion_is_topology_dos_only(self) -> None:
        _, findings = _evaluate(
            [
                _cloud_run(),
                _public_invoker(),
                _bucket(),
                _custom_role(
                    role_id="bucketTopology",
                    permissions=[_DELETE_BUCKET],
                    stage="GA",
                    deleted=False,
                ),
                _bucket_member(role=_ROLE_NAME),
            ],
            _RULE_ID,
            _MUTATION_RULE_ID,
            _OBJECT_DISRUPTION_RULE_ID,
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
                "google_project_iam_custom_role.bucketTopology",
                "google_storage_bucket_iam_member.orders_delete",
            ],
        )
        evidence = _evidence(finding)
        self.assertEqual(len(evidence["gcs_bucket_topology_destruction_paths"]), 1)
        self.assertIn("operation=storage.buckets.delete", evidence["gcs_bucket_topology_destruction_paths"][0])
        self.assertIn("target_scope=exact_gcs_bucket", evidence["gcs_bucket_topology_destruction_paths"][0])
        self.assertIn("scope_type=bucket", evidence["gcs_bucket_topology_destruction_paths"][0])
        self.assertIn("bucket_emptiness_state=not_established", evidence["bucket_deletion_recovery_evidence"][0])
        self.assertIn("successful_deletion_observed=false", evidence["bucket_deletion_recovery_evidence"][0])
        self.assertIn("does not establish bucket emptiness", finding.rationale)

    def test_bucket_scoped_storage_editor_is_revalidated(self) -> None:
        _, findings = _evaluate(
            [_cloud_run(), _public_invoker(), _bucket(), _bucket_member(role="roles/storage.editor")],
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence(findings[0])
        self.assertIn("role_kind=storage_editor", evidence["gcs_bucket_topology_destruction_paths"][0])

    def test_private_workload_keeps_paths_without_public_finding(self) -> None:
        inventory, findings = _evaluate(
            [
                _cloud_run(public_ingress=False),
                _public_invoker(),
                _bucket(),
                _custom_role(
                    role_id="bucketTopology",
                    permissions=[_DELETE_BUCKET],
                    stage="GA",
                    deleted=False,
                ),
                _bucket_member(role=_ROLE_NAME),
            ]
        )

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        self.assertTrue(gcp_facts(workload).cloud_run_gcs_bucket_topology_destruction_paths)
        self.assertEqual(findings, [])

    def test_unknown_recovery_posture_does_not_suppress_authority(self) -> None:
        _, findings = _evaluate(
            [
                _cloud_run(),
                _public_invoker(),
                _bucket(unknown_soft_delete=True),
                _custom_role(
                    role_id="bucketTopology",
                    permissions=[_DELETE_BUCKET],
                    stage="GA",
                    deleted=False,
                ),
                _bucket_member(role=_ROLE_NAME),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence(findings[0])
        self.assertIn("soft_delete_state=unknown", evidence["bucket_deletion_recovery_evidence"][0])
        self.assertIn("bucket_recovery_state=unknown", evidence["bucket_deletion_recovery_evidence"][0])

    def test_stale_current_custom_role_suppresses_topology_finding(self) -> None:
        resources = [
            _cloud_run(),
            _public_invoker(),
            _bucket(),
            _custom_role(
                role_id="bucketTopology",
                permissions=[_DELETE_BUCKET],
                stage="GA",
                deleted=False,
            ),
            _bucket_member(role=_ROLE_NAME),
        ]
        inventory, findings = _evaluate(resources)
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        role = inventory.get_by_address("google_project_iam_custom_role.bucketTopology")
        assert role is not None
        gcp_facts(role).set(GcpResourceMetadata.CUSTOM_ROLE_STAGE, "DISABLED")

        stale_findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
        )
        self.assertEqual(stale_findings, [])

    def test_removed_current_bucket_allow_suppresses_topology_finding(self) -> None:
        resources = [
            _cloud_run(),
            _public_invoker(),
            _bucket(),
            _custom_role(
                role_id="bucketTopology",
                permissions=[_DELETE_BUCKET],
                stage="GA",
                deleted=False,
            ),
            _bucket_member(role=_ROLE_NAME),
        ]
        inventory, findings = _evaluate(resources)
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        source = inventory.get_by_address("google_storage_bucket_iam_member.orders_delete")
        assert source is not None
        gcp_facts(source).set(GcpResourceMetadata.IAM_BINDINGS, [])
        gcp_facts(source).set(GcpResourceMetadata.IAM_ROLE, None)
        gcp_facts(source).set(GcpResourceMetadata.IAM_MEMBER, None)

        stale_findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
        )
        self.assertEqual(stale_findings, [])

    def test_recovery_posture_drift_refreshes_current_finding_evidence(self) -> None:
        resources = [
            _cloud_run(),
            _public_invoker(),
            _bucket(unknown_soft_delete=True),
            _custom_role(
                role_id="bucketTopology",
                permissions=[_DELETE_BUCKET],
                stage="GA",
                deleted=False,
            ),
            _bucket_member(role=_ROLE_NAME),
        ]
        inventory, findings = _evaluate(resources)
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        self.assertIn(
            "soft_delete_state=unknown",
            _evidence(findings[0])["bucket_deletion_recovery_evidence"][0],
        )

        bucket = inventory.get_by_address(_BUCKET_ADDRESS)
        assert bucket is not None
        bucket_facts = gcp_facts(bucket)
        bucket_facts.set(GcpResourceMetadata.GCS_SOFT_DELETE_STATE, "enabled")
        bucket_facts.set(
            GcpResourceMetadata.GCS_SOFT_DELETE_RETENTION_DURATION_SECONDS,
            604_800,
        )
        bucket_facts.set(GcpResourceMetadata.GCS_SOFT_DELETE_POLICY_UNCERTAINTIES, [])

        current_findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
        )
        self.assertEqual([finding.rule_id for finding in current_findings], [_RULE_ID])
        recovery_evidence = _evidence(current_findings[0])["bucket_deletion_recovery_evidence"][0]
        self.assertIn("soft_delete_state=enabled", recovery_evidence)
        self.assertIn("soft_delete_retention_duration_seconds=604800", recovery_evidence)
        self.assertIn("bucket_recovery_state=soft_delete_recovery_configured", recovery_evidence)
        self.assertNotIn(
            "soft_delete_policy.retention_duration_seconds is unknown after planning",
            _evidence(current_findings[0])["bucket_topology_destruction_path_uncertainties"],
        )

    def test_custom_role_permission_drift_refreshes_current_finding_evidence(self) -> None:
        resources = [
            _cloud_run(),
            _public_invoker(),
            _bucket(),
            _custom_role(
                role_id="bucketTopology",
                permissions=[_DELETE_BUCKET],
                stage="GA",
                deleted=False,
            ),
            _bucket_member(role=_ROLE_NAME),
        ]
        inventory, findings = _evaluate(resources)
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        role = inventory.get_by_address("google_project_iam_custom_role.bucketTopology")
        assert role is not None
        gcp_facts(role).set(
            GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS,
            [_DELETE_BUCKET, "storage.buckets.get"],
        )

        current_findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
        )
        self.assertEqual([finding.rule_id for finding in current_findings], [_RULE_ID])
        self.assertIn(
            "custom_role_permissions=storage.buckets.delete,storage.buckets.get",
            _evidence(current_findings[0])["gcs_bucket_topology_destruction_paths"][0],
        )

    def test_stale_copied_target_is_rejected(self) -> None:
        resources = [
            _cloud_run(),
            _public_invoker(),
            _bucket(),
            _custom_role(
                role_id="bucketTopology",
                permissions=[_DELETE_BUCKET],
                stage="GA",
                deleted=False,
            ),
            _bucket_member(role=_ROLE_NAME),
        ]
        inventory, findings = _evaluate(resources)
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = gcp_facts(workload).cloud_run_gcs_bucket_topology_destruction_paths
        paths[0]["bucket_address"] = "google_storage_bucket.stale"
        gcp_facts(workload).set_cloud_run_gcs_bucket_topology_destruction_paths(paths)

        stale_findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
        )
        self.assertEqual(stale_findings, [])


if __name__ == "__main__":
    unittest.main()

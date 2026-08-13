from __future__ import annotations

import unittest

from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _DATABASE_ADDRESS,
    _DATABASE_RESOURCE_NAME,
    _IAM_ADDRESS,
    _PROJECT,
    _WORKLOAD_ADDRESS,
    _custom_role,
    _database,
    _project_iam_member,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _PUBLIC_INVOKER_ADDRESS,
    _public_cloud_run,
    _public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_RULE_ID = "gcp-public-cloud-run-firestore-entity-disruption"
_MUTATION_RULE_ID = "gcp-public-cloud-run-firestore-mutation-access"


def _as_resource(value: object) -> TerraformResource:
    assert isinstance(value, TerraformResource)
    return value


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


class GcpPublicCloudRunFirestoreEntityDisruptionRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

    def test_entity_delete_is_dos_and_not_tampering(self) -> None:
        _, findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(
                    _custom_role(
                        role_id="firestoreDeleteOnly",
                        permissions=["datastore.entities.delete"],
                    )
                ),
                _as_resource(
                    _project_iam_member(
                        role="projects/tfstride-demo/roles/firestoreDeleteOnly",
                    )
                ),
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
                _DATABASE_ADDRESS,
                "google_project_iam_custom_role.cloud_run_firestore",
                _IAM_ADDRESS,
            ],
        )
        evidence = _evidence(finding)
        self.assertEqual(len(evidence["firestore_entity_deletion_paths"]), 1)
        self.assertIn(
            "operation=datastore.entities.delete",
            evidence["firestore_entity_deletion_paths"][0],
        )
        self.assertIn(
            "operation_class=entity_deletion",
            evidence["firestore_entity_deletion_paths"][0],
        )
        self.assertIn(
            "target_granularity=database_entity_namespace",
            evidence["firestore_entity_deletion_paths"][0],
        )
        self.assertIn(
            "scope_type=project",
            evidence["authorization_scope"][0],
        )
        self.assertIn(
            "pitr_state=not_configured",
            evidence["recovery_posture"][0],
        )
        self.assertEqual(
            evidence["scope_breadth"],
            [
                "project_applicable_grants=1; exact_database_grants=0; "
                "modeled_databases=1; blast_radius_basis=project_applicable_grant"
            ],
        )

    def test_fully_qualified_project_identity_revalidates_to_same_database(self) -> None:
        database = _as_resource(_database())
        database.values["project"] = f"projects/{_PROJECT}"
        iam_member = _as_resource(_project_iam_member())
        iam_member.values["project"] = f"projects/{_PROJECT}"

        _, findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                database,
                iam_member,
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence(findings[0])
        self.assertIn("scope_type=project", evidence["authorization_scope"][0])

    def test_bulk_delete_is_operation_exact_and_broader_privilege(self) -> None:
        _, findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(
                    _project_iam_member(
                        role="roles/datastore.bulkAdmin",
                        name="orders_bulk_delete",
                    )
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.privilege_breadth, 2)
        evidence = _evidence(finding)
        self.assertEqual(len(evidence["firestore_entity_deletion_paths"]), 1)
        path_evidence = evidence["firestore_entity_deletion_paths"][0]
        self.assertIn("operation=datastore.databases.bulkDelete", path_evidence)
        self.assertIn("operation_class=bulk_entity_deletion", path_evidence)
        self.assertIn(
            "target_granularity=database_bulk_entity_namespace",
            path_evidence,
        )
        self.assertIn(
            "matched_permissions=datastore.databases.bulkDelete",
            path_evidence,
        )

    def test_one_owner_grant_is_counted_once_across_deletion_operations(self) -> None:
        _, findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(_project_iam_member(role="roles/datastore.owner")),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence(findings[0])
        self.assertEqual(len(evidence["firestore_entity_deletion_paths"]), 2)
        self.assertEqual(
            evidence["scope_breadth"],
            [
                "project_applicable_grants=1; exact_database_grants=0; "
                "modeled_databases=1; blast_radius_basis=project_applicable_grant"
            ],
        )

    def test_one_project_grant_is_counted_once_across_database_fanout(self) -> None:
        _, findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(
                    _database(
                        address="google_firestore_database.archive",
                        name="archive",
                    )
                ),
                _as_resource(_project_iam_member(role="roles/datastore.owner")),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence(findings[0])
        self.assertEqual(len(evidence["firestore_entity_deletion_paths"]), 4)
        self.assertEqual(
            evidence["scope_breadth"],
            [
                "project_applicable_grants=1; exact_database_grants=0; "
                "modeled_databases=2; blast_radius_basis=project_applicable_grant"
            ],
        )

    def test_exact_database_scope_preserves_narrow_recovery_and_blast_radius(self) -> None:
        condition = {
            "title": "orders-only",
            "expression": f'resource.name == "{_DATABASE_RESOURCE_NAME}"',
        }
        role = f"projects/{_PROJECT}/roles/cloudRunFirestoreDelete"
        _, findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(
                    _custom_role(
                        role_id="cloudRunFirestoreDelete",
                        permissions=["datastore.entities.delete"],
                    )
                ),
                _as_resource(
                    _project_iam_member(
                        role=role,
                        condition=condition,
                    )
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.blast_radius, 1)
        evidence = _evidence(finding)
        self.assertIn("scope_type=database", evidence["authorization_scope"][0])
        self.assertIn("condition_evaluation=exact_database_scope_match", evidence["firestore_entity_deletion_paths"][0])

    def test_unknown_pitr_preserves_deterministic_delete_and_recovery_uncertainty(self) -> None:
        database = _as_resource(_database())
        database.unknown_values["point_in_time_recovery_enablement"] = True

        _, findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                database,
                _as_resource(_project_iam_member()),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence(findings[0])
        recovery = evidence["recovery_posture"][0]
        self.assertIn("pitr_state=unknown", recovery)
        self.assertIn("recovery_state=recovery_posture_unknown", recovery)
        self.assertIn("recovery posture is partly unknown", findings[0].rationale.lower())

    def test_private_and_runtime_conditioned_workloads_stay_quiet(self) -> None:
        runtime_condition = {
            "title": "temporary",
            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
        }
        self.assertEqual(
            _evaluate(
                [
                    _public_cloud_run(public_ingress=False),
                    _public_invoker(),
                    _as_resource(_database()),
                    _as_resource(_project_iam_member()),
                ]
            )[1],
            [],
        )
        self.assertEqual(
            _evaluate(
                [
                    _public_cloud_run(),
                    _public_invoker(),
                    _as_resource(_database()),
                    _as_resource(_project_iam_member(condition=runtime_condition)),
                ]
            )[1],
            [],
        )

    def test_stale_deletion_operation_and_current_grant_evidence_is_rejected(self) -> None:
        resources = [
            _public_cloud_run(),
            _public_invoker(),
            _as_resource(_database()),
            _as_resource(_project_iam_member()),
        ]
        inventory, findings = _evaluate(resources)
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        database = inventory.get_by_address(_DATABASE_ADDRESS)
        assert workload is not None
        assert database is not None

        workload_facts = gcp_facts(workload)
        paths = workload_facts.cloud_run_firestore_entity_deletion_paths
        for path in paths:
            path["matched_permissions"] = [
                "datastore.entities.delete",
                "datastore.entities.get",
            ]
        workload_facts.set_cloud_run_firestore_entity_deletion_paths(paths)
        self.assertEqual(
            StrideRuleEngine().evaluate(
                inventory,
                detect_trust_boundaries(inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
            ),
            [],
        )

        workload_facts.set_cloud_run_firestore_entity_deletion_paths(
            [
                {
                    **path,
                    "matched_permissions": ["datastore.entities.delete"],
                }
                for path in paths
            ]
        )
        gcp_facts(database).set(GcpResourceMetadata.FIRESTORE_IAM_GRANTS, [])
        self.assertEqual(
            StrideRuleEngine().evaluate(
                inventory,
                detect_trust_boundaries(inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()

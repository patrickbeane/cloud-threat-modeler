from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _DATABASE_ADDRESS,
    _PROJECT,
    _project_iam_member,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_database_topology_destruction_paths import (
    _custom_topology_role,
    _database_resource,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _PUBLIC_INVOKER_ADDRESS,
    _public_cloud_run,
    _public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import ResourceInventory, StrideCategory, TerraformResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_RULE_ID = "gcp-public-cloud-run-firestore-database-topology-disruption"
_MUTATION_RULE_ID = "gcp-public-cloud-run-firestore-mutation-access"
_ENTITY_DISRUPTION_RULE_ID = "gcp-public-cloud-run-firestore-entity-disruption"
_READ_RULE_ID = "gcp-public-cloud-run-firestore-read-access"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_ROLE_NAME = f"projects/{_PROJECT}/roles/firestoreTopology"
_DELETE_DATABASE = "datastore.databases.delete"


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


def _evaluate_inventory(inventory, *rule_ids: str):
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or {_RULE_ID})),
    )


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


def _current_inventory(
    inventory: ResourceInventory,
    resources,
) -> ResourceInventory:
    return ResourceInventory(
        provider=inventory.provider,
        resources=resources,
        unsupported_resources=list(inventory.unsupported_resources),
        plan_time_unknown_resources=inventory.plan_time_unknown_resources,
    )


def _nonpublic_authoritative_invoker_binding() -> TerraformResource:
    return _terraform_resource(
        "google_cloud_run_v2_service_iam_binding.private_invoker",
        GcpResourceType.CLOUD_RUN_V2_SERVICE_IAM_BINDING,
        {
            "name": "orders",
            "location": "us-central1",
            "role": "roles/run.invoker",
            "members": ["serviceAccount:private@example.iam.gserviceaccount.com"],
        },
    )


def _resources(
    *,
    public_ingress: bool = True,
    role_permissions: list[str] | None = None,
    unknown_pitr: bool = False,
) -> list[TerraformResource]:
    workload = _public_cloud_run(public_ingress=public_ingress)
    return [
        workload,
        _public_invoker(),
        _database_resource(unknown_pitr=unknown_pitr),
        _as_resource(_custom_topology_role(permissions=role_permissions or [_DELETE_DATABASE])),
        _as_resource(_project_iam_member(role=_ROLE_NAME)),
    ]


class GcpPublicCloudRunFirestoreDatabaseTopologyDisruptionRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

    def test_database_delete_is_topology_dos_only(self) -> None:
        _, findings = _evaluate(
            _resources(),
            _RULE_ID,
            _MUTATION_RULE_ID,
            _ENTITY_DISRUPTION_RULE_ID,
            _READ_RULE_ID,
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
                "google_project_iam_member.orders_firestore",
            ],
        )
        evidence = _evidence(finding)
        self.assertEqual(len(evidence["firestore_database_topology_destruction_paths"]), 1)
        path_evidence = evidence["firestore_database_topology_destruction_paths"][0]
        self.assertIn("operation=datastore.databases.delete", path_evidence)
        self.assertIn("target_granularity=database_topology", path_evidence)
        self.assertIn("scope_type=project", path_evidence)
        recovery = evidence["firestore_database_recovery_evidence"][0]
        self.assertIn("successful_deletion_observed=false", recovery)
        self.assertIn("database_content_prerequisites_evaluated=false", recovery)
        self.assertIn("out_of_plan_topology_evaluated=false", recovery)
        self.assertIn("does not establish database content prerequisites", finding.rationale)

    def test_mixed_entity_mutation_and_database_delete_stay_separate(self) -> None:
        _, findings = _evaluate(
            _resources(role_permissions=["datastore.entities.create", _DELETE_DATABASE]),
            _RULE_ID,
            _MUTATION_RULE_ID,
            _ENTITY_DISRUPTION_RULE_ID,
            _READ_RULE_ID,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [_MUTATION_RULE_ID, _RULE_ID],
        )
        mutation_finding = findings[0]
        mutation_evidence = _evidence(mutation_finding)["firestore_mutation_paths"]
        self.assertTrue(mutation_evidence)
        self.assertTrue(all(_DELETE_DATABASE not in record for record in mutation_evidence))
        self.assertTrue(all("database_administration_classes=none" in record for record in mutation_evidence))
        assert mutation_finding.severity_reasoning is not None
        self.assertEqual(mutation_finding.severity_reasoning.privilege_breadth, 1)
        self.assertEqual(mutation_finding.severity_reasoning.final_score, 8)
        self.assertNotIn("destructive_administration", mutation_finding.rationale)
        topology_evidence = _evidence(findings[1])["firestore_database_topology_destruction_paths"]
        self.assertTrue(any(_DELETE_DATABASE in record for record in topology_evidence))

    def test_private_workload_keeps_paths_without_public_finding(self) -> None:
        inventory, findings = _evaluate(_resources(public_ingress=False))

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        self.assertTrue(gcp_facts(workload).cloud_run_firestore_database_topology_destruction_paths)
        self.assertEqual(findings, [])

    def test_current_public_invoker_source_is_required(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        current_inventory = _current_inventory(
            inventory,
            tuple(resource for resource in inventory.resources if resource.address != _PUBLIC_INVOKER_ADDRESS),
        )

        workload = current_inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        self.assertTrue(gcp_facts(workload).cloud_run_firestore_database_topology_destruction_paths)
        self.assertEqual(_evaluate_inventory(current_inventory), [])

    def test_current_public_invoker_member_is_revalidated(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        source = inventory.get_by_address(_PUBLIC_INVOKER_ADDRESS)
        assert source is not None
        gcp_facts(source).set(
            GcpResourceMetadata.IAM_BINDINGS,
            [
                {
                    "role": "roles/run.invoker",
                    "members": ["serviceAccount:private@example.iam.gserviceaccount.com"],
                }
            ],
        )

        self.assertEqual(_evaluate_inventory(inventory), [])

    def test_current_public_invoker_condition_is_revalidated(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        source = inventory.get_by_address(_PUBLIC_INVOKER_ADDRESS)
        assert source is not None
        gcp_facts(source).set(
            GcpResourceMetadata.IAM_BINDINGS,
            [
                {
                    "role": "roles/run.invoker",
                    "members": ["allUsers"],
                    "condition": {
                        "title": "runtime-window",
                        "expression": ('request.time < timestamp("2030-01-01T00:00:00Z")'),
                    },
                    "condition_state": "configured",
                }
            ],
        )

        self.assertEqual(_evaluate_inventory(inventory), [])

    def test_current_public_invoker_target_is_revalidated(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        source = inventory.get_by_address(_PUBLIC_INVOKER_ADDRESS)
        assert source is not None
        gcp_facts(source).set(
            GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE,
            "other-service",
        )

        self.assertEqual(_evaluate_inventory(inventory), [])

    def test_current_public_invoker_manager_overlap_fails_closed(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        conflicting_inventory = GcpNormalizer().normalize([_nonpublic_authoritative_invoker_binding()])
        current_inventory = _current_inventory(
            inventory,
            (*inventory.resources, *conflicting_inventory.resources),
        )

        self.assertEqual(_evaluate_inventory(current_inventory), [])

    def test_disabled_invoker_iam_check_remains_a_direct_public_posture(self) -> None:
        resources = _resources()
        workload = resources[0]
        workload.values["invoker_iam_disabled"] = True
        resources = [resource for resource in resources if resource.address != _PUBLIC_INVOKER_ADDRESS]

        _, findings = _evaluate(resources)

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        self.assertNotIn(_PUBLIC_INVOKER_ADDRESS, findings[0].affected_resources)
        self.assertNotIn(
            "public_invoker_bindings",
            _evidence(findings[0]),
        )
        self.assertIn(
            "disables the Cloud Run Invoker IAM check",
            _evidence(findings[0])["public_exposure_reasons"][0],
        )

    def test_removed_current_allow_suppresses_topology_finding(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        source = inventory.get_by_address("google_project_iam_member.orders_firestore")
        assert source is not None
        gcp_facts(source).set(GcpResourceMetadata.IAM_BINDINGS, [])
        gcp_facts(source).set(GcpResourceMetadata.IAM_ROLE, None)
        gcp_facts(source).set(GcpResourceMetadata.IAM_MEMBER, None)

        self.assertEqual(_evaluate_inventory(inventory), [])

    def test_stale_copied_target_is_rejected(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = gcp_facts(workload).cloud_run_firestore_database_topology_destruction_paths
        paths[0]["firestore_database_address"] = "google_firestore_database.stale"
        gcp_facts(workload).set_cloud_run_firestore_database_topology_destruction_paths(paths)

        self.assertEqual(_evaluate_inventory(inventory), [])

    def test_recovery_posture_drift_refreshes_finding_without_losing_authority(self) -> None:
        inventory, findings = _evaluate(_resources(unknown_pitr=True))
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        initial_recovery = _evidence(findings[0])["firestore_database_recovery_evidence"][0]
        self.assertIn("pitr_state=unknown", initial_recovery)

        database = inventory.get_by_address(_DATABASE_ADDRESS)
        assert database is not None
        database_facts = gcp_facts(database)
        database_facts.set(GcpResourceMetadata.FIRESTORE_PITR_STATE, "enabled")
        database_facts.set(GcpResourceMetadata.FIRESTORE_PITR_ENABLEMENT, "POINT_IN_TIME_RECOVERY_ENABLED")
        database_facts.set(GcpResourceMetadata.FIRESTORE_POSTURE_UNCERTAINTIES, [])

        current_findings = _evaluate_inventory(inventory)
        self.assertEqual([finding.rule_id for finding in current_findings], [_RULE_ID])
        current_evidence = _evidence(current_findings[0])
        recovery = current_evidence["firestore_database_recovery_evidence"][0]
        self.assertIn("pitr_state=enabled", recovery)
        self.assertIn("historical_version_retention_state=pitr_up_to_seven_days", recovery)
        self.assertNotIn(
            "point_in_time_recovery_enablement is unknown",
            current_evidence["firestore_database_topology_destruction_path_uncertainties"],
        )

    def test_custom_role_permission_drift_refreshes_finding_evidence(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        role = inventory.get_by_address("google_project_iam_custom_role.cloud_run_firestore")
        assert role is not None
        gcp_facts(role).set(
            GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS,
            [_DELETE_DATABASE, "datastore.databases.get"],
        )

        current_findings = _evaluate_inventory(inventory)
        self.assertEqual([finding.rule_id for finding in current_findings], [_RULE_ID])
        path_evidence = _evidence(current_findings[0])["firestore_database_topology_destruction_paths"][0]
        self.assertIn(
            "custom_role_permissions=datastore.databases.delete,datastore.databases.get",
            path_evidence,
        )

    def test_duplicate_cached_paths_do_not_duplicate_targets_or_evidence(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = gcp_facts(workload).cloud_run_firestore_database_topology_destruction_paths
        gcp_facts(workload).set_cloud_run_firestore_database_topology_destruction_paths(paths + [dict(paths[0])])

        current_findings = _evaluate_inventory(inventory)
        self.assertEqual([finding.rule_id for finding in current_findings], [_RULE_ID])
        evidence = _evidence(current_findings[0])
        self.assertEqual(len(evidence["firestore_database_topology_destruction_paths"]), 1)
        self.assertEqual(current_findings[0].affected_resources.count(_DATABASE_ADDRESS), 1)


if __name__ == "__main__":
    unittest.main()

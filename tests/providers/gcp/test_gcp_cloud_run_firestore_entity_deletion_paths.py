from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _DATABASE_ADDRESS,
    _DATABASE_RESOURCE_NAME,
    _PROJECT,
    _cloud_run,
    _custom_role,
    _database,
    _project_iam_member,
    _workload_facts,
)
from tfstride.providers.gcp.resource_types import GcpResourceType


class GcpCloudRunFirestoreEntityDeletionPathTests(unittest.TestCase):
    def test_owner_preserves_entity_and_bulk_deletion_paths(self) -> None:
        facts = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _project_iam_member(role="roles/datastore.owner"),
            ]
        )

        paths = facts.cloud_run_firestore_entity_deletion_paths
        self.assertEqual(
            {path["operation"] for path in paths},
            {
                "datastore.entities.delete",
                "datastore.databases.bulkDelete",
            },
        )
        self.assertEqual(
            {path["operation_class"] for path in paths},
            {"entity_deletion", "bulk_entity_deletion"},
        )
        self.assertEqual(
            {path["target_granularity"] for path in paths},
            {"database_entity_namespace", "database_bulk_entity_namespace"},
        )
        for path in paths:
            self.assertEqual(path["scope_type"], "project")
            self.assertEqual(path["scope"], _PROJECT)
            self.assertEqual(path["iam_source_addresses"], ["google_project_iam_member.orders_firestore"])
            self.assertEqual(path["recovery_evidence"]["pitr_state"], "not_configured")
            self.assertEqual(
                path["recovery_evidence"]["historical_version_retention_state"],
                "native_approximately_one_hour",
            )
        self.assertEqual(facts.cloud_run_firestore_entity_deletion_path_uncertainties, [])

    def test_wildcard_permissions_remain_operation_specific(self) -> None:
        role = "projects/tfstride-demo/roles/cloudRunFirestore"
        cases = (
            ("datastore.entities.*", {"datastore.entities.delete"}),
            ("datastore.databases.*", {"datastore.databases.bulkDelete"}),
            (
                "datastore.*",
                {
                    "datastore.entities.delete",
                    "datastore.databases.bulkDelete",
                },
            ),
        )
        for permission, expected_operations in cases:
            with self.subTest(permission=permission):
                facts = _workload_facts(
                    [
                        _cloud_run(),
                        _database(),
                        _custom_role(permissions=[permission]),
                        _project_iam_member(role=role),
                    ]
                )

                self.assertEqual(
                    {path["operation"] for path in facts.cloud_run_firestore_entity_deletion_paths},
                    expected_operations,
                )

    def test_bulk_admin_models_only_database_bulk_delete(self) -> None:
        facts = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _project_iam_member(role="roles/datastore.bulkAdmin"),
            ]
        )

        paths = facts.cloud_run_firestore_entity_deletion_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["operation"], "datastore.databases.bulkDelete")
        self.assertEqual(paths[0]["matched_permissions"], ["datastore.databases.bulkDelete"])

    def test_project_delete_authority_fans_to_exact_databases(self) -> None:
        facts = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _database(address="google_firestore_database.archive", name="archive"),
                _project_iam_member(role="roles/datastore.user"),
            ]
        )

        self.assertEqual(
            [
                (path["firestore_database_address"], path["scope_type"], path["resource_scope"])
                for path in facts.cloud_run_firestore_entity_deletion_paths
            ],
            [
                ("google_firestore_database.archive", "project", "firestore_project"),
                (_DATABASE_ADDRESS, "project", "firestore_project"),
            ],
        )

    def test_project_and_database_proofs_remain_distinct(self) -> None:
        role = f"projects/{_PROJECT}/roles/cloudRunFirestore"
        condition = {
            "title": "orders-only",
            "expression": f'resource.name == "{_DATABASE_RESOURCE_NAME}"',
        }
        facts = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _custom_role(),
                _project_iam_member(role="roles/datastore.user", name="project_proof"),
                _project_iam_member(role=role, name="database_proof", condition=condition),
            ]
        )

        paths = facts.cloud_run_firestore_entity_deletion_paths
        self.assertEqual(len(paths), 2)
        self.assertEqual({path["operation"] for path in paths}, {"datastore.entities.delete"})
        self.assertEqual({path["scope_type"] for path in paths}, {"project", "database"})
        self.assertEqual(
            {path["firestore_database_address"] for path in paths},
            {_DATABASE_ADDRESS},
        )

    def test_exact_database_condition_and_custom_role_lineage_are_preserved(self) -> None:
        role = f"projects/{_PROJECT}/roles/cloudRunFirestore"
        condition = {
            "title": "orders-only",
            "expression": f'resource.name == "{_DATABASE_RESOURCE_NAME}"',
        }
        facts = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _custom_role(),
                _project_iam_member(role=role, condition=condition),
            ]
        )

        paths = facts.cloud_run_firestore_entity_deletion_paths
        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(path["operation"], "datastore.entities.delete")
        self.assertEqual(path["scope_type"], "database")
        self.assertEqual(path["scope"], _DATABASE_RESOURCE_NAME)
        self.assertEqual(path["resource_scope"], "exact_firestore_database")
        self.assertEqual(path["condition"], condition)
        self.assertEqual(path["condition_evaluation"], "exact_database_scope_match")
        self.assertEqual(path["role_definition_address"], "google_project_iam_custom_role.cloud_run_firestore")
        self.assertEqual(
            path["iam_source_addresses"],
            [
                "google_project_iam_member.orders_firestore",
                "google_project_iam_custom_role.cloud_run_firestore",
            ],
        )
        self.assertEqual(path["custom_role_stage"], "GA")
        self.assertFalse(path["custom_role_deleted"])
        self.assertEqual(
            path["custom_role_permissions"],
            [
                "datastore.databases.update",
                "datastore.entities.create",
                "datastore.entities.delete",
                "resourcemanager.projects.get",
            ],
        )

    def test_pitr_states_are_recovery_evidence_not_authorization_gates(self) -> None:
        cases = (
            (
                "POINT_IN_TIME_RECOVERY_ENABLED",
                False,
                "enabled",
                True,
                "pitr_up_to_seven_days",
            ),
            (
                "POINT_IN_TIME_RECOVERY_DISABLED",
                False,
                "disabled",
                False,
                "native_approximately_one_hour",
            ),
            (None, False, "not_configured", False, "native_approximately_one_hour"),
            (None, True, "unknown", None, "unknown"),
        )
        for enablement, unknown, expected_state, expected_enabled, expected_retention in cases:
            with self.subTest(expected_state=expected_state):
                facts = _workload_facts(
                    [
                        _cloud_run(),
                        _database_with_pitr(enablement, unknown=unknown),
                        _project_iam_member(role="roles/datastore.user"),
                    ]
                )

                self.assertEqual(len(facts.cloud_run_firestore_entity_deletion_paths), 1)
                recovery = facts.cloud_run_firestore_entity_deletion_paths[0]["recovery_evidence"]
                self.assertEqual(recovery["pitr_state"], expected_state)
                self.assertEqual(recovery["pitr_enabled"], expected_enabled)
                self.assertEqual(
                    recovery["historical_version_retention_state"],
                    expected_retention,
                )
                if expected_state == "unknown":
                    self.assertTrue(recovery["uncertainties"])
                else:
                    self.assertEqual(recovery["uncertainties"], [])

    def test_inactive_custom_roles_do_not_project_deletion_paths(self) -> None:
        cases = (
            (
                _custom_role_with_lifecycle(stage="DISABLED", deleted=False),
                "disabled",
            ),
            (
                _custom_role_with_lifecycle(stage="GA", deleted=True),
                "deleted",
            ),
            (
                _custom_role_with_lifecycle(stage="GA", unknown_deleted=True),
                "unresolved deletion lifecycle",
            ),
        )
        role = "projects/tfstride-demo/roles/cloudRunFirestore"
        for role_resource, expected_fragment in cases:
            with self.subTest(expected_fragment=expected_fragment):
                facts = _workload_facts(
                    [
                        _cloud_run(),
                        _database(),
                        role_resource,
                        _project_iam_member(role=role),
                    ]
                )

                self.assertEqual(facts.cloud_run_firestore_entity_deletion_paths, [])
                self.assertTrue(
                    any(
                        expected_fragment in uncertainty
                        for uncertainty in facts.cloud_run_firestore_entity_deletion_path_uncertainties
                    )
                )

    def test_read_only_or_unrelated_runtime_authority_does_not_create_deletion_paths(self) -> None:
        read_only = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _project_iam_member(role="roles/datastore.viewer"),
            ]
        )
        unrelated_identity = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _project_iam_member(member="serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"),
            ]
        )

        self.assertEqual(read_only.cloud_run_firestore_entity_deletion_paths, [])
        self.assertEqual(unrelated_identity.cloud_run_firestore_entity_deletion_paths, [])
        self.assertEqual(unrelated_identity.cloud_run_firestore_entity_deletion_path_uncertainties, [])

    def test_entity_deletion_paths_remain_for_private_workloads(self) -> None:
        facts = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _project_iam_member(role="roles/datastore.user"),
            ]
        )

        self.assertEqual(len(facts.cloud_run_firestore_entity_deletion_paths), 1)
        self.assertEqual(
            facts.cloud_run_firestore_entity_deletion_paths[0]["management_effect"],
            "disruption",
        )


def _custom_role_with_lifecycle(
    *,
    stage: str | None = None,
    deleted: bool | None = None,
    unknown_deleted: bool = False,
) -> object:
    values: dict[str, object] = {
        "project": _PROJECT,
        "role_id": "cloudRunFirestore",
        "name": f"projects/{_PROJECT}/roles/cloudRunFirestore",
        "permissions": ["datastore.entities.delete"],
    }
    unknown_values: dict[str, object] = {}
    if stage is not None:
        values["stage"] = stage
    if deleted is not None:
        values["deleted"] = deleted
    if unknown_deleted:
        unknown_values["deleted"] = True
    return _terraform_resource(
        "google_project_iam_custom_role.cloud_run_firestore",
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        values,
        unknown_values=unknown_values,
    )


def _database_with_pitr(
    enablement: str | None,
    *,
    unknown: bool,
) -> object:
    values: dict[str, object] = {
        "id": f"projects/{_PROJECT}/databases/orders",
        "name": "orders",
        "project": _PROJECT,
        "location_id": "nam5",
        "type": "FIRESTORE_NATIVE",
    }
    unknown_values: dict[str, object] = {}
    if unknown:
        unknown_values["point_in_time_recovery_enablement"] = True
    elif enablement is not None:
        values["point_in_time_recovery_enablement"] = enablement
    return _terraform_resource(
        _DATABASE_ADDRESS,
        GcpResourceType.FIRESTORE_DATABASE,
        values,
        unknown_values=unknown_values,
    )


if __name__ == "__main__":
    unittest.main()

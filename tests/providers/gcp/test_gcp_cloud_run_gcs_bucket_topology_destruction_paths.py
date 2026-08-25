from __future__ import annotations

import json
import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_gcs_object_deletion_paths import (
    _BUCKET_ADDRESS,
    _BUCKET_NAME,
    _OTHER_PROJECT,
    _PROJECT,
    _SERVICE_ACCOUNT_EMAIL,
    _SERVICE_ACCOUNT_MEMBER,
    _WORKLOAD_ADDRESS,
    _bucket,
    _bucket_binding,
    _bucket_member,
    _bucket_policy,
    _cloud_run,
    _custom_role,
    _project_member,
)
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_decoration.cloud_run_gcs_bucket_topology_destruction_paths import (
    current_cloud_run_gcs_bucket_topology_destruction_paths,
)
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import (
    GcpDecorationContext,
    GcpResourceIndexBuilder,
)
from tfstride.providers.gcp.resource_types import GcpResourceType

_DELETE_BUCKET = "storage.buckets.delete"
_DELETE_OBJECT = "storage.objects.delete"


def _tf(value: object) -> TerraformResource:
    assert isinstance(value, TerraformResource)
    return value


def _normalize(*resources: object):
    inventory = GcpNormalizer().normalize([_tf(resource) for resource in resources])
    workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
    bucket = inventory.get_by_address(_BUCKET_ADDRESS)
    assert workload is not None
    assert bucket is not None
    return inventory, workload, bucket, gcp_facts(workload)


def _project_binding(
    *,
    role: str,
    members: list[str] | None = None,
    name: str = "topology",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _terraform_resource(
        f"google_project_iam_binding.{name}",
        GcpResourceType.PROJECT_IAM_BINDING,
        {
            "project": _PROJECT,
            "role": role,
            "members": members or [_SERVICE_ACCOUNT_MEMBER],
        },
        unknown_values=unknown_values,
    )


def _unknown_bucket_binding(
    *,
    role: str | None,
    unknown_target: bool = False,
    unknown_role: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "bucket": f"{_BUCKET_ADDRESS}.name",
        "members": ["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
    }
    if role is not None:
        values["role"] = role
    unknown_values: dict[str, object] = {}
    if unknown_target:
        unknown_values["bucket"] = True
    if unknown_role:
        unknown_values["role"] = True
    return _terraform_resource(
        "google_storage_bucket_iam_binding.unresolved",
        GcpResourceType.STORAGE_BUCKET_IAM_BINDING,
        values,
        unknown_values=unknown_values,
    )


class GcpCloudRunGcsBucketTopologyDestructionPathTests(unittest.TestCase):
    def test_exact_bucket_custom_role_preserves_authority_and_recovery_boundary(
        self,
    ) -> None:
        inventory, workload, _bucket_resource, facts = _normalize(
            _cloud_run(),
            _bucket(retention_period="2592000", retention_locked=True),
            _custom_role(
                role_id="bucketTopology",
                permissions=[_DELETE_BUCKET, "storage.buckets.get"],
                stage="GA",
                deleted=False,
            ),
            _bucket_member(
                role=f"projects/{_PROJECT}/roles/bucketTopology",
            ),
        )

        self.assertFalse(workload.public_exposure)
        self.assertEqual(len(facts.cloud_run_gcs_bucket_topology_destruction_paths), 1)
        path = facts.cloud_run_gcs_bucket_topology_destruction_paths[0]
        self.assertEqual(path["workload_address"], _WORKLOAD_ADDRESS)
        self.assertEqual(path["service_account_email"], _SERVICE_ACCOUNT_EMAIL)
        self.assertEqual(path["service_account_member"], _SERVICE_ACCOUNT_MEMBER)
        self.assertEqual(path["bucket_address"], _BUCKET_ADDRESS)
        self.assertEqual(path["bucket_name"], _BUCKET_NAME)
        self.assertEqual(path["bucket_project"], _PROJECT)
        self.assertEqual(path["bucket_reference"], f"projects/_/buckets/{_BUCKET_NAME}")
        self.assertEqual(path["operation"], _DELETE_BUCKET)
        self.assertEqual(path["matched_permissions"], [_DELETE_BUCKET])
        self.assertEqual(path["target_granularity"], "bucket_topology")
        self.assertEqual(path["target_scope"], "exact_gcs_bucket")
        self.assertEqual(path["scope_type"], "bucket")
        self.assertEqual(path["grant_basis"], "gcs_bucket_iam")
        self.assertEqual(path["authorization_state"], "granted")
        self.assertTrue(path["policy_complete"])
        self.assertEqual(path["iam_manager_ambiguity_state"], "not_detected")
        self.assertEqual(path["condition_state"], "not_configured")
        self.assertEqual(
            path["lifecycle_compatibility_state"],
            "bucket_emptiness_not_established",
        )
        role_evidence = path["role_evidence"]
        self.assertEqual(role_evidence["role_kind"], "custom")
        self.assertEqual(
            role_evidence["role_definition_address"],
            "google_project_iam_custom_role.bucketTopology",
        )
        self.assertEqual(
            role_evidence["custom_role_permissions"],
            [_DELETE_BUCKET, "storage.buckets.get"],
        )
        self.assertEqual(
            role_evidence["custom_role_grant_scope_compatibility_state"],
            "compatible",
        )
        self.assertEqual(
            path["iam_source_addresses"],
            [
                "google_storage_bucket_iam_member.orders_delete",
                "google_project_iam_custom_role.bucketTopology",
            ],
        )
        recovery = path["recovery_evidence"]
        self.assertTrue(recovery["bucket_emptiness_required"])
        self.assertEqual(recovery["bucket_emptiness_state"], "not_established")
        self.assertEqual(recovery["soft_delete_state"], "enabled")
        self.assertEqual(
            recovery["soft_delete_retention_duration_seconds"],
            604_800,
        )
        self.assertEqual(recovery["retention_period_seconds"], 2_592_000)
        self.assertTrue(recovery["retention_policy_locked"])
        self.assertFalse(recovery["out_of_plan_object_inventory_evaluated"])
        self.assertFalse(recovery["successful_deletion_observed"])
        self.assertFalse(recovery["restoration_observed"])
        self.assertTrue(recovery["uncertainties"])
        serialized = json.dumps(path, sort_keys=True)
        self.assertNotIn('successful_deletion_observed": true', serialized)
        self.assertIsNotNone(inventory.get_by_address(path["iam_resource_address"]))

    def test_predefined_roles_respect_project_and_bucket_scope(self) -> None:
        project_roles = {
            "roles/owner": "owner",
            "roles/editor": "editor",
            "roles/storage.admin": "storage_admin",
            "roles/storage.editor": "storage_editor",
        }
        for role, role_kind in project_roles.items():
            with self.subTest(scope="project", role=role):
                _inventory, _workload, _bucket_resource, facts = _normalize(
                    _cloud_run(),
                    _bucket(),
                    _project_member(role=role),
                )
                self.assertEqual(len(facts.cloud_run_gcs_bucket_topology_destruction_paths), 1)
                path = facts.cloud_run_gcs_bucket_topology_destruction_paths[0]
                self.assertEqual(path["scope_type"], "project")
                self.assertEqual(path["scope"], _PROJECT)
                self.assertEqual(path["role_evidence"]["role_kind"], role_kind)

        bucket_roles = {
            "roles/storage.admin": "storage_admin",
            "roles/storage.editor": "storage_editor",
        }
        for role, role_kind in bucket_roles.items():
            with self.subTest(scope="bucket", role=role):
                _inventory, _workload, _bucket_resource, facts = _normalize(
                    _cloud_run(),
                    _bucket(),
                    _bucket_member(role=role),
                )
                self.assertEqual(len(facts.cloud_run_gcs_bucket_topology_destruction_paths), 1)
                path = facts.cloud_run_gcs_bucket_topology_destruction_paths[0]
                self.assertEqual(path["scope_type"], "bucket")
                self.assertEqual(path["scope"], f"projects/_/buckets/{_BUCKET_NAME}")
                self.assertEqual(path["role_evidence"]["role_kind"], role_kind)

        for role in ("roles/owner", "roles/editor"):
            with self.subTest(scope="bucket", role=role):
                _inventory, _workload, _bucket_resource, facts = _normalize(
                    _cloud_run(),
                    _bucket(),
                    _bucket_member(role=role),
                )
                self.assertEqual(facts.cloud_run_gcs_bucket_topology_destruction_paths, [])
                self.assertTrue(facts.cloud_run_gcs_bucket_topology_destruction_path_uncertainties)

    def test_project_grant_fans_only_to_exact_same_project_buckets(self) -> None:
        archive_address = "google_storage_bucket.archive"
        foreign_address = "google_storage_bucket.foreign"
        inventory = GcpNormalizer().normalize(
            [
                _tf(_cloud_run()),
                _tf(_bucket()),
                _tf(_bucket(address=archive_address, name="tfstride-archive-data")),
                _tf(
                    _bucket(
                        address=foreign_address,
                        name="tfstride-foreign-data",
                        project=_OTHER_PROJECT,
                    )
                ),
                _tf(_project_member(role="roles/storage.admin")),
            ]
        )
        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = gcp_facts(workload).cloud_run_gcs_bucket_topology_destruction_paths
        self.assertEqual(len(paths), 2)
        self.assertEqual(
            {path["bucket_address"] for path in paths},
            {_BUCKET_ADDRESS, archive_address},
        )
        self.assertFalse(any(path["bucket_address"] == foreign_address for path in paths))

    def test_object_delete_authority_does_not_become_bucket_topology_authority(
        self,
    ) -> None:
        _inventory, _workload, _bucket_resource, object_only = _normalize(
            _cloud_run(),
            _bucket(),
            _bucket_member(role="roles/storage.objectAdmin"),
        )
        self.assertEqual(object_only.cloud_run_gcs_bucket_topology_destruction_paths, [])
        self.assertEqual(len(object_only.cloud_run_gcs_object_deletion_paths), 2)

        _inventory, _workload, _bucket_resource, mixed = _normalize(
            _cloud_run(),
            _bucket(),
            _custom_role(
                role_id="mixedStorage",
                permissions=[_DELETE_BUCKET, _DELETE_OBJECT],
                stage="GA",
                deleted=False,
            ),
            _bucket_member(role=f"projects/{_PROJECT}/roles/mixedStorage"),
        )
        self.assertEqual(len(mixed.cloud_run_gcs_bucket_topology_destruction_paths), 1)
        self.assertEqual(len(mixed.cloud_run_gcs_object_deletion_paths), 2)
        self.assertEqual(
            mixed.cloud_run_gcs_bucket_topology_destruction_paths[0]["matched_permissions"],
            [_DELETE_BUCKET],
        )
        self.assertTrue(
            all(path["matched_permissions"] == [_DELETE_OBJECT] for path in mixed.cloud_run_gcs_object_deletion_paths)
        )

    def test_conditions_identity_and_custom_role_lifecycle_fail_closed(self) -> None:
        condition = {
            "title": "runtime-window",
            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
        }
        cases = {
            "condition": (
                _cloud_run(),
                _custom_role(
                    role_id="bucketTopology",
                    permissions=[_DELETE_BUCKET],
                    stage="GA",
                    deleted=False,
                ),
                _bucket_member(
                    role=f"projects/{_PROJECT}/roles/bucketTopology",
                    condition=condition,
                ),
            ),
            "unknown identity": (
                _cloud_run(service_account=None),
                _custom_role(
                    role_id="bucketTopology",
                    permissions=[_DELETE_BUCKET],
                    stage="GA",
                    deleted=False,
                ),
                _bucket_member(role=f"projects/{_PROJECT}/roles/bucketTopology"),
            ),
            "unknown stage": (
                _cloud_run(),
                _custom_role(
                    role_id="bucketTopology",
                    permissions=[_DELETE_BUCKET],
                    unknown_stage=True,
                ),
                _bucket_member(role=f"projects/{_PROJECT}/roles/bucketTopology"),
            ),
            "unknown deleted": (
                _cloud_run(),
                _custom_role(
                    role_id="bucketTopology",
                    permissions=[_DELETE_BUCKET],
                    stage="GA",
                    unknown_deleted=True,
                ),
                _bucket_member(role=f"projects/{_PROJECT}/roles/bucketTopology"),
            ),
            "unknown permissions": (
                _cloud_run(),
                _custom_role(
                    role_id="bucketTopology",
                    permissions=[_DELETE_BUCKET],
                    stage="GA",
                    deleted=False,
                    unknown_permissions=True,
                ),
                _bucket_member(role=f"projects/{_PROJECT}/roles/bucketTopology"),
            ),
            "wildcard permission": (
                _cloud_run(),
                _custom_role(
                    role_id="bucketTopology",
                    permissions=["storage.buckets.*"],
                    stage="GA",
                    deleted=False,
                ),
                _bucket_member(role=f"projects/{_PROJECT}/roles/bucketTopology"),
            ),
        }
        for case, resources in cases.items():
            with self.subTest(case=case):
                _inventory, _workload, _bucket_resource, facts = _normalize(
                    resources[0],
                    _bucket(),
                    resources[1],
                    resources[2],
                )
                self.assertEqual(facts.cloud_run_gcs_bucket_topology_destruction_paths, [])
                self.assertTrue(facts.cloud_run_gcs_bucket_topology_destruction_path_uncertainties)

        for case, role in {
            "disabled": _custom_role(
                role_id="bucketTopology",
                permissions=[_DELETE_BUCKET],
                stage="DISABLED",
                deleted=False,
            ),
            "deleted": _custom_role(
                role_id="bucketTopology",
                permissions=[_DELETE_BUCKET],
                stage="GA",
                deleted=True,
            ),
        }.items():
            with self.subTest(case=case):
                _inventory, _workload, _bucket_resource, facts = _normalize(
                    _cloud_run(),
                    _bucket(),
                    role,
                    _bucket_member(role=f"projects/{_PROJECT}/roles/bucketTopology"),
                )
                self.assertEqual(facts.cloud_run_gcs_bucket_topology_destruction_paths, [])

    def test_custom_role_must_be_grantable_in_bucket_project(self) -> None:
        _inventory, _workload, _bucket_resource, facts = _normalize(
            _cloud_run(),
            _bucket(project=_OTHER_PROJECT),
            _custom_role(
                role_id="bucketTopology",
                permissions=[_DELETE_BUCKET],
                stage="GA",
                deleted=False,
            ),
            _bucket_member(role=f"projects/{_PROJECT}/roles/bucketTopology"),
        )
        self.assertEqual(facts.cloud_run_gcs_bucket_topology_destruction_paths, [])
        self.assertTrue(
            any(
                "not grantable" in uncertainty
                for uncertainty in facts.cloud_run_gcs_bucket_topology_destruction_path_uncertainties
            )
        )

    def test_manager_overlap_reconciles_custom_role_aliases(self) -> None:
        role_name = f"projects/{_PROJECT}/roles/bucketTopology"
        _inventory, _workload, _bucket_resource, ambiguous = _normalize(
            _cloud_run(),
            _bucket(),
            _custom_role(
                role_id="bucketTopology",
                permissions=[_DELETE_BUCKET],
                stage="GA",
                deleted=False,
            ),
            _bucket_member(role="google_project_iam_custom_role.bucketTopology.name"),
            _bucket_binding(
                role=role_name,
                members=["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
            ),
        )
        self.assertEqual(ambiguous.cloud_run_gcs_bucket_topology_destruction_paths, [])
        self.assertTrue(
            any(
                "ambiguous" in uncertainty
                for uncertainty in ambiguous.cloud_run_gcs_bucket_topology_destruction_path_uncertainties
            )
        )

        _inventory, _workload, _bucket_resource, compatible = _normalize(
            _cloud_run(),
            _bucket(),
            _custom_role(
                role_id="bucketTopology",
                permissions=[_DELETE_BUCKET],
                stage="GA",
                deleted=False,
            ),
            _bucket_member(role="google_project_iam_custom_role.bucketTopology.name"),
            _bucket_binding(
                role="roles/storage.objectViewer",
                members=["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
            ),
        )
        self.assertEqual(len(compatible.cloud_run_gcs_bucket_topology_destruction_paths), 1)

    def test_unresolved_authoritative_managers_suppress_potential_overlap(self) -> None:
        role = "roles/storage.admin"
        for case, manager in {
            "unknown role": _unknown_bucket_binding(
                role=None,
                unknown_role=True,
            ),
            "unknown target": _unknown_bucket_binding(
                role=role,
                unknown_target=True,
            ),
        }.items():
            with self.subTest(case=case):
                _inventory, _workload, _bucket_resource, facts = _normalize(
                    _cloud_run(),
                    _bucket(),
                    _bucket_member(role=role),
                    manager,
                )
                self.assertEqual(facts.cloud_run_gcs_bucket_topology_destruction_paths, [])
                self.assertTrue(
                    any(
                        "unresolved" in uncertainty
                        for uncertainty in facts.cloud_run_gcs_bucket_topology_destruction_path_uncertainties
                    )
                )

    def test_bucket_target_reference_contract_is_exact(self) -> None:
        for target in (_BUCKET_NAME, f"projects/_/buckets/{_BUCKET_NAME}", f"{_BUCKET_ADDRESS}.name"):
            with self.subTest(target=target):
                _inventory, _workload, _bucket_resource, facts = _normalize(
                    _cloud_run(),
                    _bucket(),
                    _bucket_member(bucket=target, role="roles/storage.admin"),
                )
                self.assertEqual(len(facts.cloud_run_gcs_bucket_topology_destruction_paths), 1)

        _inventory, _workload, _bucket_resource, unsupported = _normalize(
            _cloud_run(),
            _bucket(),
            _bucket_member(
                bucket=f"{_BUCKET_ADDRESS}.id",
                role="roles/storage.admin",
            ),
        )
        self.assertEqual(unsupported.cloud_run_gcs_bucket_topology_destruction_paths, [])
        self.assertTrue(unsupported.cloud_run_gcs_bucket_topology_destruction_path_uncertainties)

        _inventory, _workload, _bucket_resource, unrelated = _normalize(
            _cloud_run(),
            _bucket(),
            _bucket_member(
                bucket="tfstride-other-data",
                role="roles/storage.admin",
            ),
        )
        self.assertEqual(unrelated.cloud_run_gcs_bucket_topology_destruction_paths, [])
        self.assertEqual(
            unrelated.cloud_run_gcs_bucket_topology_destruction_path_uncertainties,
            [],
        )

        unknown_name = _tf(_bucket())
        unknown_name.values.pop("name")
        unknown_name.unknown_values["name"] = True
        _inventory, _workload, normalized_bucket, unresolved = _normalize(
            _cloud_run(),
            unknown_name,
            _bucket_member(role="roles/storage.admin"),
        )
        self.assertIsNone(gcp_facts(normalized_bucket).bucket_name)
        self.assertEqual(unresolved.cloud_run_gcs_bucket_topology_destruction_paths, [])
        self.assertTrue(
            any(
                "unresolved exact native identity" in uncertainty
                for uncertainty in unresolved.cloud_run_gcs_bucket_topology_destruction_path_uncertainties
            )
        )

    def test_soft_delete_states_qualify_recovery_without_proving_emptiness(self) -> None:
        cases = (
            ("enabled", _bucket(soft_delete_seconds=604_800), "enabled", 604_800),
            ("disabled", _bucket(soft_delete_seconds=0), "disabled", 0),
            (
                "unknown",
                _bucket(soft_delete_seconds=None, unknown_soft_delete=True),
                "unknown",
                None,
            ),
            (
                "not observed",
                _bucket(include_soft_delete=False),
                "not_observed",
                None,
            ),
        )
        for case, bucket, expected_state, expected_duration in cases:
            with self.subTest(case=case):
                _inventory, _workload, _bucket_resource, facts = _normalize(
                    _cloud_run(),
                    bucket,
                    _bucket_member(role="roles/storage.admin"),
                )
                path = facts.cloud_run_gcs_bucket_topology_destruction_paths[0]
                recovery = path["recovery_evidence"]
                self.assertEqual(recovery["soft_delete_state"], expected_state)
                self.assertEqual(
                    recovery["soft_delete_retention_duration_seconds"],
                    expected_duration,
                )
                self.assertEqual(recovery["bucket_emptiness_state"], "not_established")
                self.assertFalse(recovery["successful_deletion_observed"])
                self.assertFalse(recovery["restoration_observed"])
                self.assertTrue(path["posture_uncertainties"])

    def test_current_path_evaluator_recomputes_effective_iam(self) -> None:
        inventory, workload, bucket, facts = _normalize(
            _cloud_run(),
            _bucket(),
            _bucket_member(role="roles/storage.admin"),
        )
        resources = list(inventory.resources)
        context = GcpDecorationContext(GcpResourceIndexBuilder().build(resources))
        current = current_cloud_run_gcs_bucket_topology_destruction_paths(
            workload,
            bucket,
            resources,
            context,
        )
        self.assertEqual(current, facts.cloud_run_gcs_bucket_topology_destruction_paths)

        current_resources = [
            resource for resource in resources if resource.address != "google_storage_bucket_iam_member.orders_delete"
        ]
        current_context = GcpDecorationContext(GcpResourceIndexBuilder().build(current_resources))
        self.assertEqual(
            current_cloud_run_gcs_bucket_topology_destruction_paths(
                workload,
                bucket,
                current_resources,
                current_context,
            ),
            [],
        )

        _active_inventory, active_workload, active_bucket, active_facts = _normalize(
            _cloud_run(),
            _bucket(),
            _custom_role(
                role_id="bucketTopology",
                permissions=[_DELETE_BUCKET],
                stage="GA",
                deleted=False,
            ),
            _bucket_member(role=f"projects/{_PROJECT}/roles/bucketTopology"),
        )
        self.assertEqual(
            len(active_facts.cloud_run_gcs_bucket_topology_destruction_paths),
            1,
        )

        disabled_inventory, _disabled_workload, _disabled_bucket, _disabled_facts = _normalize(
            _cloud_run(),
            _bucket(),
            _custom_role(
                role_id="bucketTopology",
                permissions=[_DELETE_BUCKET],
                stage="DISABLED",
                deleted=False,
            ),
            _bucket_member(role=f"projects/{_PROJECT}/roles/bucketTopology"),
        )
        disabled_resources = list(disabled_inventory.resources)
        disabled_context = GcpDecorationContext(GcpResourceIndexBuilder().build(disabled_resources))
        self.assertEqual(
            current_cloud_run_gcs_bucket_topology_destruction_paths(
                active_workload,
                active_bucket,
                disabled_resources,
                disabled_context,
            ),
            [],
        )

    def test_authoritative_policy_is_a_distinct_valid_proof(self) -> None:
        _inventory, _workload, _bucket_resource, facts = _normalize(
            _cloud_run(),
            _bucket(),
            _bucket_policy(role="roles/storage.admin"),
        )
        self.assertEqual(len(facts.cloud_run_gcs_bucket_topology_destruction_paths), 1)
        path = facts.cloud_run_gcs_bucket_topology_destruction_paths[0]
        self.assertEqual(path["iam_resource_type"], GcpResourceType.STORAGE_BUCKET_IAM_POLICY)
        self.assertEqual(path["scope_type"], "bucket")
        self.assertEqual(path["grant_basis"], "gcs_bucket_iam")


if __name__ == "__main__":
    unittest.main()

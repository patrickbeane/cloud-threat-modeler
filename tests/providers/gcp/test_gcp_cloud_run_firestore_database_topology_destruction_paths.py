from __future__ import annotations

import json
import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _DATABASE_ADDRESS,
    _DATABASE_RESOURCE_NAME,
    _PROJECT,
    _SERVICE_ACCOUNT_EMAIL,
    _SERVICE_ACCOUNT_MEMBER,
    _WORKLOAD_ADDRESS,
    _cloud_run,
    _custom_role,
    _database,
    _project_iam_member,
)
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_decoration.cloud_run_firestore_database_topology_destruction_paths import (
    current_cloud_run_firestore_database_topology_destruction_paths,
)
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import (
    GcpDecorationContext,
    GcpResourceIndexBuilder,
)
from tfstride.providers.gcp.resource_types import GcpResourceType

_DELETE_DATABASE = "datastore.databases.delete"
_DELETE_ENTITY = "datastore.entities.delete"
_OTHER_PROJECT = "tfstride-foreign"
_CUSTOM_ROLE_NAME = f"projects/{_PROJECT}/roles/firestoreTopology"


def _tf(value: object) -> TerraformResource:
    assert isinstance(value, TerraformResource)
    return value


def _database_resource(
    *,
    address: str = _DATABASE_ADDRESS,
    name: str = "orders",
    project: str = _PROJECT,
    delete_protection: str | None = None,
    pitr: str | None = None,
    deletion_policy: str | None = None,
    unknown_delete_protection: bool = False,
    unknown_pitr: bool = False,
    unknown_deletion_policy: bool = False,
) -> TerraformResource:
    resource = _tf(_database(address=address, name=name))
    resource.values["project"] = project
    resource.values["id"] = f"projects/{project}/databases/{name}"
    if delete_protection is not None:
        resource.values["delete_protection_state"] = delete_protection
    if pitr is not None:
        resource.values["point_in_time_recovery_enablement"] = pitr
    if deletion_policy is not None:
        resource.values["deletion_policy"] = deletion_policy
    if unknown_delete_protection:
        resource.unknown_values["delete_protection_state"] = True
    if unknown_pitr:
        resource.unknown_values["point_in_time_recovery_enablement"] = True
    if unknown_deletion_policy:
        resource.unknown_values["deletion_policy"] = True
    return resource


def _custom_topology_role(
    *,
    permissions: list[str] | None = None,
    project: str = _PROJECT,
    stage: str | None = "GA",
    deleted: bool | None = False,
    unknown_stage: bool = False,
    unknown_deleted: bool = False,
    unknown_permissions: bool = False,
) -> TerraformResource:
    role = _tf(
        _custom_role(
            role_id="firestoreTopology",
            permissions=permissions or [_DELETE_DATABASE],
        )
    )
    role.values["project"] = project
    role.values["name"] = f"projects/{project}/roles/firestoreTopology"
    if stage is not None:
        role.values["stage"] = stage
    if deleted is not None:
        role.values["deleted"] = deleted
    if unknown_stage:
        role.unknown_values["stage"] = True
    if unknown_deleted:
        role.unknown_values["deleted"] = True
    if unknown_permissions:
        role.unknown_values["permissions"] = True
    return role


def _project_binding(
    *,
    role: str | None,
    members: list[str] | None = None,
    name: str = "topology",
    unknown_role: bool = False,
    unknown_project: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "project": _PROJECT,
        "members": members or [_SERVICE_ACCOUNT_MEMBER],
    }
    if role is not None:
        values["role"] = role
    unknown_values: dict[str, object] = {}
    if unknown_role:
        unknown_values["role"] = True
    if unknown_project:
        unknown_values["project"] = True
    return _terraform_resource(
        f"google_project_iam_binding.{name}",
        GcpResourceType.PROJECT_IAM_BINDING,
        values,
        unknown_values=unknown_values,
    )


def _project_policy(
    *,
    role: str,
    members: list[str] | None = None,
    unknown_policy: bool = False,
) -> TerraformResource:
    return _terraform_resource(
        "google_project_iam_policy.topology",
        GcpResourceType.PROJECT_IAM_POLICY,
        {
            "project": _PROJECT,
            "policy_data": json.dumps(
                {
                    "bindings": [
                        {
                            "role": role,
                            "members": members or [_SERVICE_ACCOUNT_MEMBER],
                        }
                    ]
                }
            ),
        },
        unknown_values={"policy_data": True} if unknown_policy else None,
    )


def _normalize(*resources: object):
    inventory = GcpNormalizer().normalize([_tf(resource) for resource in resources])
    workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
    database = inventory.get_by_address(_DATABASE_ADDRESS)
    assert workload is not None
    assert database is not None
    return inventory, workload, database, gcp_facts(workload)


class GcpCloudRunFirestoreDatabaseTopologyDestructionPathTests(unittest.TestCase):
    def test_exact_custom_role_preserves_authority_constraints_and_recovery_boundary(
        self,
    ) -> None:
        inventory, workload, _database_target, facts = _normalize(
            _cloud_run(),
            _database_resource(
                delete_protection="DELETE_PROTECTION_DISABLED",
                pitr="POINT_IN_TIME_RECOVERY_ENABLED",
                deletion_policy="DELETE",
            ),
            _custom_topology_role(
                permissions=[_DELETE_DATABASE, "datastore.databases.get"],
            ),
            _project_iam_member(role=_CUSTOM_ROLE_NAME),
        )

        self.assertFalse(workload.public_exposure)
        self.assertEqual(len(facts.cloud_run_firestore_database_topology_destruction_paths), 1)
        path = facts.cloud_run_firestore_database_topology_destruction_paths[0]
        self.assertEqual(path["workload_address"], _WORKLOAD_ADDRESS)
        self.assertEqual(path["service_account_email"], _SERVICE_ACCOUNT_EMAIL)
        self.assertEqual(path["service_account_member"], _SERVICE_ACCOUNT_MEMBER)
        self.assertEqual(path["identity_kind"], "cloud_run_service_account")
        self.assertEqual(path["credential_context"], "workload_runtime")
        self.assertEqual(path["firestore_database_address"], _DATABASE_ADDRESS)
        self.assertEqual(path["firestore_database_resource_name"], _DATABASE_RESOURCE_NAME)
        self.assertEqual(path["firestore_database_name"], "orders")
        self.assertEqual(path["firestore_database_project"], _PROJECT)
        self.assertEqual(path["firestore_database_type"], "FIRESTORE_NATIVE")
        self.assertEqual(path["operation"], _DELETE_DATABASE)
        self.assertEqual(path["matched_permissions"], [_DELETE_DATABASE])
        self.assertEqual(path["operation_class"], "database_deletion")
        self.assertEqual(path["target_granularity"], "database_topology")
        self.assertEqual(path["target_scope"], "exact_firestore_database")
        self.assertEqual(path["target_model_evidence_addresses"], [_DATABASE_ADDRESS])
        self.assertEqual(path["scope_type"], "project")
        self.assertEqual(path["scope"], _PROJECT)
        self.assertEqual(path["grant_basis"], "firestore_project_iam")
        self.assertEqual(path["condition_state"], "not_configured")
        self.assertEqual(path["authorization_state"], "granted")
        self.assertTrue(path["policy_complete"])
        self.assertEqual(path["iam_manager_ambiguity_state"], "not_detected")
        self.assertEqual(path["authorization_model"], "iam_authorized_server_api")
        self.assertFalse(path["firestore_security_rules_evaluated"])
        self.assertEqual(path["lifecycle_compatibility_state"], "compatible")

        role = path["role_evidence"]
        self.assertEqual(role["role_kind"], "custom")
        self.assertEqual(
            role["role_definition_address"],
            "google_project_iam_custom_role.cloud_run_firestore",
        )
        self.assertEqual(
            role["custom_role_permissions"],
            [_DELETE_DATABASE, "datastore.databases.get"],
        )
        self.assertEqual(role["custom_role_stage"], "GA")
        self.assertFalse(role["custom_role_deleted"])
        self.assertFalse(role["custom_role_wildcard_permissions_present"])
        self.assertEqual(
            role["custom_role_grant_scope_compatibility_state"],
            "compatible",
        )
        self.assertEqual(
            path["iam_source_addresses"],
            [
                "google_project_iam_member.orders_firestore",
                "google_project_iam_custom_role.cloud_run_firestore",
            ],
        )

        constraint = path["deletion_constraint_evidence"]
        self.assertEqual(constraint["delete_protection_enablement"], "disabled")
        self.assertFalse(constraint["delete_protection_enabled"])
        self.assertEqual(constraint["deletion_compatibility_state"], "compatible")
        terraform_policy = path["terraform_deletion_policy_evidence"]
        self.assertEqual(terraform_policy["policy_state"], "configured")
        self.assertEqual(terraform_policy["policy"], "DELETE")
        self.assertEqual(terraform_policy["runtime_api_authorization_effect"], "none")
        recovery = path["recovery_evidence"]
        self.assertEqual(recovery["pitr_state"], "enabled")
        self.assertTrue(recovery["pitr_enabled"])
        self.assertEqual(recovery["historical_version_retention_state"], "pitr_up_to_seven_days")
        self.assertFalse(recovery["successful_deletion_observed"])
        self.assertFalse(recovery["restoration_observed"])
        self.assertFalse(recovery["database_content_prerequisites_evaluated"])
        self.assertFalse(recovery["eventarc_trigger_impact_evaluated"])
        self.assertFalse(recovery["out_of_plan_topology_evaluated"])
        self.assertTrue(path["posture_uncertainties"])
        self.assertIsNotNone(inventory.get_by_address(path["iam_resource_address"]))

    def test_predefined_roles_respect_project_and_exact_database_scope(self) -> None:
        project_roles = {
            "roles/owner": "owner",
            "roles/datastore.owner": "datastore_owner",
            "roles/datastore.admin": "datastore_admin",
            "roles/firebase.admin": "firebase_admin",
            "roles/firebase.developAdmin": "firebase_develop_admin",
        }
        for role, role_kind in project_roles.items():
            with self.subTest(scope="project", role=role):
                _inventory, _workload, _database_target, facts = _normalize(
                    _cloud_run(),
                    _database_resource(),
                    _project_iam_member(role=role),
                )
                self.assertEqual(len(facts.cloud_run_firestore_database_topology_destruction_paths), 1)
                path = facts.cloud_run_firestore_database_topology_destruction_paths[0]
                self.assertEqual(path["scope_type"], "project")
                self.assertEqual(path["role_evidence"]["role_kind"], role_kind)

        condition = {
            "title": "orders-only",
            "expression": f'resource.name == "{_DATABASE_RESOURCE_NAME}"',
        }
        for role, role_kind in {key: value for key, value in project_roles.items() if key != "roles/owner"}.items():
            with self.subTest(scope="database", role=role):
                _inventory, _workload, _database_target, facts = _normalize(
                    _cloud_run(),
                    _database_resource(),
                    _project_iam_member(role=role, condition=condition),
                )
                self.assertEqual(len(facts.cloud_run_firestore_database_topology_destruction_paths), 1)
                path = facts.cloud_run_firestore_database_topology_destruction_paths[0]
                self.assertEqual(path["scope_type"], "database")
                self.assertEqual(path["scope"], _DATABASE_RESOURCE_NAME)
                self.assertEqual(path["role_evidence"]["role_kind"], role_kind)

        for role in ("roles/owner", "roles/datastore.user", "roles/datastore.bulkAdmin"):
            with self.subTest(incompatible_role=role):
                _inventory, _workload, _database_target, facts = _normalize(
                    _cloud_run(),
                    _database_resource(),
                    _project_iam_member(role=role, condition=condition),
                )
                self.assertEqual(facts.cloud_run_firestore_database_topology_destruction_paths, [])

        runtime_condition = {
            "title": "temporary",
            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
        }
        _inventory, _workload, _database_target, conditional = _normalize(
            _cloud_run(),
            _database_resource(),
            _project_iam_member(
                role="roles/datastore.admin",
                condition=runtime_condition,
            ),
        )
        self.assertEqual(conditional.cloud_run_firestore_database_topology_destruction_paths, [])
        self.assertTrue(conditional.cloud_run_firestore_database_topology_destruction_path_uncertainties)

    def test_project_and_exact_database_proofs_preserve_native_scope(self) -> None:
        condition = {
            "title": "orders-only",
            "description": "Only the orders database",
            "expression": f'"{_DATABASE_RESOURCE_NAME}" == resource.name',
        }
        _inventory, _workload, _database_target, facts = _normalize(
            _cloud_run(),
            _database_resource(),
            _custom_topology_role(),
            _project_iam_member(role=_CUSTOM_ROLE_NAME, name="project_delete"),
            _project_iam_member(
                role="google_project_iam_custom_role.cloud_run_firestore.name",
                name="database_delete",
                condition=condition,
            ),
        )

        paths = facts.cloud_run_firestore_database_topology_destruction_paths
        self.assertEqual(len(paths), 2)
        self.assertEqual({path["scope_type"] for path in paths}, {"project", "database"})
        exact = next(path for path in paths if path["scope_type"] == "database")
        self.assertEqual(exact["scope"], _DATABASE_RESOURCE_NAME)
        self.assertEqual(exact["resource_scope"], "exact_firestore_database")
        self.assertEqual(exact["grant_basis"], "firestore_project_iam_exact_database_condition")
        self.assertEqual(exact["condition"], condition)
        self.assertEqual(exact["condition_evaluation"], "exact_database_scope_match")
        project = next(path for path in paths if path["scope_type"] == "project")
        self.assertEqual(project["scope"], _PROJECT)
        self.assertEqual(project["condition"], None)

    def test_project_grant_fans_only_to_exact_same_project_databases(self) -> None:
        archive_address = "google_firestore_database.archive"
        foreign_address = "google_firestore_database.foreign"
        inventory = GcpNormalizer().normalize(
            [
                _tf(_cloud_run()),
                _database_resource(),
                _database_resource(address=archive_address, name="archive"),
                _database_resource(
                    address=foreign_address,
                    name="foreign",
                    project=_OTHER_PROJECT,
                ),
                _tf(_project_iam_member(role="roles/datastore.admin")),
            ]
        )
        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = gcp_facts(workload).cloud_run_firestore_database_topology_destruction_paths
        self.assertEqual(
            {path["firestore_database_address"] for path in paths},
            {_DATABASE_ADDRESS, archive_address},
        )
        self.assertNotIn(
            foreign_address,
            {path["firestore_database_address"] for path in paths},
        )

    def test_entity_and_database_deletion_authority_remain_operation_exact(self) -> None:
        _inventory, _workload, _database_target, mixed = _normalize(
            _cloud_run(),
            _database_resource(),
            _custom_topology_role(permissions=[_DELETE_DATABASE, _DELETE_ENTITY]),
            _project_iam_member(role=_CUSTOM_ROLE_NAME),
        )
        self.assertEqual(len(mixed.cloud_run_firestore_database_topology_destruction_paths), 1)
        self.assertEqual(
            mixed.cloud_run_firestore_database_topology_destruction_paths[0]["matched_permissions"],
            [_DELETE_DATABASE],
        )
        self.assertEqual(len(mixed.cloud_run_firestore_entity_deletion_paths), 1)
        self.assertEqual(
            mixed.cloud_run_firestore_entity_deletion_paths[0]["matched_permissions"],
            [_DELETE_ENTITY],
        )

        _inventory, _workload, _database_target, wildcard = _normalize(
            _cloud_run(),
            _database_resource(),
            _custom_topology_role(permissions=["datastore.databases.*"]),
            _project_iam_member(role=_CUSTOM_ROLE_NAME),
        )
        self.assertEqual(wildcard.cloud_run_firestore_database_topology_destruction_paths, [])
        self.assertTrue(wildcard.cloud_run_firestore_database_topology_destruction_path_uncertainties)

    def test_identity_custom_role_lifecycle_and_grant_scope_fail_closed(self) -> None:
        cases = {
            "unknown identity": (
                _cloud_run(service_account=None),
                _custom_topology_role(),
            ),
            "unknown stage": (
                _cloud_run(),
                _custom_topology_role(stage=None, unknown_stage=True),
            ),
            "unknown deleted": (
                _cloud_run(),
                _custom_topology_role(deleted=None, unknown_deleted=True),
            ),
            "unknown permissions": (
                _cloud_run(),
                _custom_topology_role(unknown_permissions=True),
            ),
            "incompatible project": (
                _cloud_run(),
                _custom_topology_role(project=_OTHER_PROJECT),
            ),
        }
        for case, (workload, role) in cases.items():
            with self.subTest(case=case):
                role_name = (
                    f"projects/{_OTHER_PROJECT}/roles/firestoreTopology"
                    if case == "incompatible project"
                    else _CUSTOM_ROLE_NAME
                )
                _inventory, _workload, _database_target, facts = _normalize(
                    workload,
                    _database_resource(),
                    role,
                    _project_iam_member(role=role_name),
                )
                self.assertEqual(facts.cloud_run_firestore_database_topology_destruction_paths, [])
                self.assertTrue(facts.cloud_run_firestore_database_topology_destruction_path_uncertainties)

        for stage, deleted in (("DISABLED", False), ("GA", True)):
            with self.subTest(stage=stage, deleted=deleted):
                _inventory, _workload, _database_target, facts = _normalize(
                    _cloud_run(),
                    _database_resource(),
                    _custom_topology_role(stage=stage, deleted=deleted),
                    _project_iam_member(role=_CUSTOM_ROLE_NAME),
                )
                self.assertEqual(facts.cloud_run_firestore_database_topology_destruction_paths, [])

    def test_manager_overlap_reconciles_custom_role_aliases_and_unknown_managers(self) -> None:
        _inventory, _workload, _database_target, ambiguous = _normalize(
            _cloud_run(),
            _database_resource(),
            _custom_topology_role(),
            _project_iam_member(
                role="google_project_iam_custom_role.cloud_run_firestore.name",
            ),
            _project_binding(
                role=_CUSTOM_ROLE_NAME,
                members=["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
            ),
        )
        self.assertEqual(ambiguous.cloud_run_firestore_database_topology_destruction_paths, [])
        self.assertTrue(
            any(
                "ambiguous" in uncertainty
                for uncertainty in ambiguous.cloud_run_firestore_database_topology_destruction_path_uncertainties
            )
        )

        _inventory, _workload, _database_target, compatible = _normalize(
            _cloud_run(),
            _database_resource(),
            _custom_topology_role(),
            _project_iam_member(
                role="google_project_iam_custom_role.cloud_run_firestore.name",
            ),
            _project_binding(
                role="roles/datastore.viewer",
                members=["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
            ),
        )
        self.assertEqual(len(compatible.cloud_run_firestore_database_topology_destruction_paths), 1)

        for case, manager in {
            "unknown role": _project_binding(
                role=None,
                members=["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
                unknown_role=True,
            ),
            "unknown project": _project_binding(
                role=_CUSTOM_ROLE_NAME,
                members=["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
                unknown_project=True,
            ),
        }.items():
            with self.subTest(case=case):
                _inventory, _workload, _database_target, unresolved = _normalize(
                    _cloud_run(),
                    _database_resource(),
                    _custom_topology_role(),
                    _project_iam_member(role=_CUSTOM_ROLE_NAME),
                    manager,
                )
                self.assertEqual(
                    unresolved.cloud_run_firestore_database_topology_destruction_paths,
                    [],
                )
                self.assertTrue(
                    any(
                        "unresolved" in uncertainty
                        for uncertainty in unresolved.cloud_run_firestore_database_topology_destruction_path_uncertainties
                    )
                )

    def test_authoritative_policy_is_a_distinct_valid_proof(self) -> None:
        _inventory, _workload, _database_target, facts = _normalize(
            _cloud_run(),
            _database_resource(),
            _project_policy(role="roles/datastore.admin"),
        )
        self.assertEqual(len(facts.cloud_run_firestore_database_topology_destruction_paths), 1)
        path = facts.cloud_run_firestore_database_topology_destruction_paths[0]
        self.assertEqual(path["iam_resource_type"], GcpResourceType.PROJECT_IAM_POLICY)
        self.assertEqual(path["scope_type"], "project")
        self.assertEqual(path["grant_basis"], "firestore_project_iam")

        _inventory, _workload, _database_target, unresolved = _normalize(
            _cloud_run(),
            _database_resource(),
            _project_policy(
                role="roles/datastore.admin",
                unknown_policy=True,
            ),
        )
        self.assertEqual(unresolved.cloud_run_firestore_database_topology_destruction_paths, [])
        self.assertTrue(unresolved.cloud_run_firestore_database_topology_destruction_path_uncertainties)

    def test_delete_protection_gates_authority_while_pitr_and_terraform_policy_do_not(self) -> None:
        _inventory, _workload, _database_target, protected = _normalize(
            _cloud_run(),
            _database_resource(delete_protection="DELETE_PROTECTION_ENABLED"),
            _project_iam_member(role="roles/datastore.admin"),
        )
        self.assertEqual(protected.cloud_run_firestore_database_topology_destruction_paths, [])

        _inventory, _workload, _database_target, unknown_constraint = _normalize(
            _cloud_run(),
            _database_resource(unknown_delete_protection=True),
            _project_iam_member(role="roles/datastore.admin"),
        )
        self.assertEqual(
            unknown_constraint.cloud_run_firestore_database_topology_destruction_paths,
            [],
        )
        self.assertTrue(unknown_constraint.cloud_run_firestore_database_topology_destruction_path_uncertainties)

        _inventory, _workload, _database_target, uncertain_recovery = _normalize(
            _cloud_run(),
            _database_resource(
                delete_protection="DELETE_PROTECTION_DISABLED",
                unknown_pitr=True,
                unknown_deletion_policy=True,
            ),
            _project_iam_member(role="roles/datastore.admin"),
        )
        self.assertEqual(
            len(uncertain_recovery.cloud_run_firestore_database_topology_destruction_paths),
            1,
        )
        path = uncertain_recovery.cloud_run_firestore_database_topology_destruction_paths[0]
        self.assertEqual(path["recovery_evidence"]["pitr_state"], "unknown")
        self.assertEqual(path["recovery_evidence"]["database_recovery_state"], "unknown")
        self.assertEqual(path["terraform_deletion_policy_evidence"]["policy_state"], "unknown")
        self.assertTrue(path["posture_uncertainties"])

        _inventory, _workload, _database_target, provider_defaults = _normalize(
            _cloud_run(),
            _database_resource(),
            _project_iam_member(role="roles/datastore.admin"),
        )
        default_path = provider_defaults.cloud_run_firestore_database_topology_destruction_paths[0]
        self.assertTrue(default_path["deletion_constraint_evidence"]["provider_default_applied"])
        self.assertFalse(default_path["deletion_constraint_evidence"]["delete_protection_enabled"])
        self.assertEqual(default_path["recovery_evidence"]["pitr_state"], "not_configured")
        self.assertFalse(default_path["recovery_evidence"]["pitr_enabled"])

    def test_unresolved_database_identity_fails_closed(self) -> None:
        database = _database_resource()
        database.values.pop("name")
        database.unknown_values["name"] = True
        _inventory, _workload, _database_target, facts = _normalize(
            _cloud_run(),
            database,
            _project_iam_member(role="roles/datastore.admin"),
        )
        self.assertEqual(facts.cloud_run_firestore_database_topology_destruction_paths, [])
        self.assertTrue(
            any(
                "unresolved exact native identity" in uncertainty
                for uncertainty in facts.cloud_run_firestore_database_topology_destruction_path_uncertainties
            )
        )

    def test_current_path_evaluator_recomputes_effective_iam(self) -> None:
        inventory, workload, database, facts = _normalize(
            _cloud_run(),
            _database_resource(),
            _custom_topology_role(),
            _project_iam_member(role=_CUSTOM_ROLE_NAME),
        )
        resources = list(inventory.resources)
        context = GcpDecorationContext(GcpResourceIndexBuilder().build(resources))
        self.assertEqual(
            current_cloud_run_firestore_database_topology_destruction_paths(
                workload,
                database,
                resources,
                context,
            ),
            facts.cloud_run_firestore_database_topology_destruction_paths,
        )

        revoked = [
            resource for resource in resources if resource.address != "google_project_iam_member.orders_firestore"
        ]
        revoked_context = GcpDecorationContext(GcpResourceIndexBuilder().build(revoked))
        self.assertEqual(
            current_cloud_run_firestore_database_topology_destruction_paths(
                workload,
                database,
                revoked,
                revoked_context,
            ),
            [],
        )

        disabled_inventory, _disabled_workload, _disabled_database, _disabled_facts = _normalize(
            _cloud_run(),
            _database_resource(),
            _custom_topology_role(stage="DISABLED"),
            _project_iam_member(role=_CUSTOM_ROLE_NAME),
        )
        disabled_resources = list(disabled_inventory.resources)
        disabled_context = GcpDecorationContext(GcpResourceIndexBuilder().build(disabled_resources))
        self.assertEqual(
            current_cloud_run_firestore_database_topology_destruction_paths(
                workload,
                database,
                disabled_resources,
                disabled_context,
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()

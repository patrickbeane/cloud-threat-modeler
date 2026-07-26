from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_PROJECT = "tfstride-demo"
_SERVICE_ACCOUNT_EMAIL = "orders@tfstride-demo.iam.gserviceaccount.com"
_SERVICE_ACCOUNT_MEMBER = f"serviceAccount:{_SERVICE_ACCOUNT_EMAIL}"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_DATABASE_ADDRESS = "google_firestore_database.orders"
_DATABASE_RESOURCE_NAME = f"projects/{_PROJECT}/databases/orders"
_IAM_ADDRESS = "google_project_iam_member.orders_firestore"


def _cloud_run(
    *,
    service_account: str | None = _SERVICE_ACCOUNT_EMAIL,
    resource_type: str = GcpResourceType.CLOUD_RUN_V2_SERVICE,
) -> object:
    if resource_type == GcpResourceType.CLOUD_RUN_SERVICE:
        spec: dict[str, object] = {}
        if service_account is not None:
            spec["service_account_name"] = service_account
        values: dict[str, object] = {
            "name": "orders",
            "project": _PROJECT,
            "location": "us-central1",
            "template": [{"spec": [spec]}],
        }
        address = "google_cloud_run_service.orders"
    else:
        template: dict[str, object] = {}
        if service_account is not None:
            template["service_account"] = service_account
        values = {
            "name": "orders",
            "project": _PROJECT,
            "location": "us-central1",
            "template": [template],
        }
        address = _WORKLOAD_ADDRESS
    return _terraform_resource(address, resource_type, values)


def _database(
    *,
    address: str = _DATABASE_ADDRESS,
    name: str = "orders",
) -> object:
    return _terraform_resource(
        address,
        GcpResourceType.FIRESTORE_DATABASE,
        {
            "id": f"projects/{_PROJECT}/databases/{name}",
            "name": name,
            "project": _PROJECT,
            "location_id": "nam5",
            "type": "FIRESTORE_NATIVE",
        },
    )


def _project_iam_member(
    *,
    role: str = "roles/datastore.user",
    member: str = _SERVICE_ACCOUNT_MEMBER,
    name: str = "orders_firestore",
    condition: dict[str, str] | None = None,
) -> object:
    values: dict[str, object] = {
        "project": _PROJECT,
        "role": role,
        "member": member,
    }
    if condition is not None:
        values["condition"] = [condition]
    return _terraform_resource(
        f"google_project_iam_member.{name}",
        GcpResourceType.PROJECT_IAM_MEMBER,
        values,
    )


def _custom_role(
    *,
    role_id: str = "cloudRunFirestore",
    permissions: list[str] | None = None,
) -> object:
    return _terraform_resource(
        "google_project_iam_custom_role.cloud_run_firestore",
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        {
            "project": _PROJECT,
            "role_id": role_id,
            "name": f"projects/{_PROJECT}/roles/{role_id}",
            "permissions": permissions
            or [
                "datastore.databases.update",
                "datastore.entities.create",
                "datastore.entities.delete",
                "resourcemanager.projects.get",
            ],
        },
    )


def _workload_facts(resources: list[object], *, address: str = _WORKLOAD_ADDRESS):
    inventory = GcpNormalizer().normalize(resources)
    workload = inventory.get_by_address(address)
    assert workload is not None
    return gcp_facts(workload)


class GcpCloudRunFirestoreAccessPathTests(unittest.TestCase):
    def test_exact_database_grant_models_runtime_identity_and_server_api_authorization(self) -> None:
        condition = {
            "title": "orders-only",
            "expression": f'resource.name == "{_DATABASE_RESOURCE_NAME}"',
        }
        facts = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _project_iam_member(condition=condition),
            ]
        )

        self.assertEqual(
            facts.cloud_run_firestore_access_paths,
            [
                {
                    "workload_address": _WORKLOAD_ADDRESS,
                    "workload_type": GcpResourceType.CLOUD_RUN_V2_SERVICE,
                    "service_account_email": _SERVICE_ACCOUNT_EMAIL,
                    "service_account_member": _SERVICE_ACCOUNT_MEMBER,
                    "identity_kind": "cloud_run_service_account",
                    "credential_context": "workload_runtime",
                    "firestore_database_address": _DATABASE_ADDRESS,
                    "firestore_database_resource_type": GcpResourceType.FIRESTORE_DATABASE,
                    "firestore_database_resource_name": _DATABASE_RESOURCE_NAME,
                    "firestore_database_name": "orders",
                    "firestore_database_project": _PROJECT,
                    "firestore_database_type": "FIRESTORE_NATIVE",
                    "iam_resource_address": _IAM_ADDRESS,
                    "iam_resource_type": GcpResourceType.PROJECT_IAM_MEMBER,
                    "role": "roles/datastore.user",
                    "role_kind": "user",
                    "access_classes": ["read", "entity_write", "entity_delete"],
                    "custom_role_permissions": [],
                    "matched_permissions": [
                        "datastore.entities.create",
                        "datastore.entities.delete",
                        "datastore.entities.get",
                        "datastore.entities.list",
                        "datastore.entities.update",
                    ],
                    "grant_basis": "project_iam_condition",
                    "scope_type": "database",
                    "scope": _DATABASE_RESOURCE_NAME,
                    "resource_scope": "exact_firestore_database",
                    "condition": condition,
                    "condition_state": "configured",
                    "condition_evaluation": "exact_database_scope_match",
                    "access_state": "granted",
                    "authorization_model": "iam_authorized_server_api",
                    "firestore_security_rules_evaluated": False,
                    "firestore_security_rules_applicability": ("not_in_server_api_authorization_path"),
                }
            ],
        )
        self.assertEqual(facts.cloud_run_firestore_access_path_uncertainties, [])

    def test_builtin_roles_preserve_distinct_firestore_capabilities(self) -> None:
        expectations = {
            "roles/datastore.viewer": ("viewer", ["read"]),
            "roles/datastore.user": (
                "user",
                ["read", "entity_write", "entity_delete"],
            ),
            "roles/firebase.editor": ("firebase_editor", ["read"]),
            "roles/firebase.viewer": ("firebase_viewer", ["read"]),
            "roles/firebase.developViewer": (
                "firebase_develop_viewer",
                ["read"],
            ),
            "roles/iam.dataScientist": ("data_scientist", ["read"]),
            "roles/iam.supportUser": ("support_user", ["read"]),
            "roles/iam.securityReviewer": ("security_reviewer", ["read"]),
            "roles/datastore.importExportAdmin": (
                "import_export_admin",
                ["read", "entity_write"],
            ),
            "roles/datastore.bulkAdmin": (
                "bulk_admin",
                ["entity_delete", "destructive_administration"],
            ),
            "roles/datastore.indexAdmin": (
                "index_admin",
                ["configuration_administration"],
            ),
            "roles/datastore.owner": (
                "owner",
                [
                    "read",
                    "entity_write",
                    "entity_delete",
                    "destructive_administration",
                    "configuration_administration",
                ],
            ),
        }

        for role, (role_kind, access_classes) in expectations.items():
            with self.subTest(role=role):
                facts = _workload_facts(
                    [
                        _cloud_run(),
                        _database(),
                        _project_iam_member(role=role),
                    ]
                )
                path = facts.cloud_run_firestore_access_paths[0]
                self.assertEqual(path["role_kind"], role_kind)
                self.assertEqual(path["access_classes"], access_classes)
                self.assertEqual(path["scope_type"], "project")

    def test_list_only_roles_retain_exact_firestore_permission(self) -> None:
        roles = (
            "roles/firebase.viewer",
            "roles/firebase.developViewer",
            "roles/iam.dataScientist",
            "roles/iam.supportUser",
            "roles/iam.securityAdmin",
            "roles/iam.securityReviewer",
            "roles/iam.securityAuditor",
        )

        for role in roles:
            with self.subTest(role=role):
                facts = _workload_facts(
                    [
                        _cloud_run(),
                        _database(),
                        _project_iam_member(role=role),
                    ]
                )

                path = facts.cloud_run_firestore_access_paths[0]
                self.assertEqual(
                    path["matched_permissions"],
                    ["datastore.entities.list"],
                )

    def test_import_export_role_retains_both_bulk_transfer_permissions(self) -> None:
        facts = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _project_iam_member(role="roles/datastore.importExportAdmin"),
            ]
        )

        path = facts.cloud_run_firestore_access_paths[0]
        self.assertEqual(path["access_classes"], ["read", "entity_write"])
        self.assertEqual(
            path["matched_permissions"],
            ["datastore.databases.export", "datastore.databases.import"],
        )

    def test_databases_admin_retains_exact_firestore_permissions(self) -> None:
        facts = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _project_iam_member(role="roles/iam.databasesAdmin"),
            ]
        )

        path = facts.cloud_run_firestore_access_paths[0]
        self.assertEqual(
            path["matched_permissions"],
            [
                "datastore.databases.bulkDelete",
                "datastore.databases.export",
                "datastore.databases.import",
                "datastore.databases.update",
                "datastore.schemas.create",
                "datastore.schemas.delete",
                "datastore.schemas.update",
            ],
        )

    def test_custom_role_preserves_permissions_and_classifies_exact_operations(self) -> None:
        role = f"projects/{_PROJECT}/roles/cloudRunFirestore"
        facts = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _custom_role(),
                _project_iam_member(role=role),
            ]
        )

        path = facts.cloud_run_firestore_access_paths[0]
        self.assertEqual(path["role_kind"], "custom")
        self.assertEqual(
            path["access_classes"],
            ["entity_write", "entity_delete", "configuration_administration"],
        )
        self.assertEqual(
            path["custom_role_permissions"],
            [
                "datastore.databases.update",
                "datastore.entities.create",
                "datastore.entities.delete",
                "resourcemanager.projects.get",
            ],
        )
        self.assertEqual(
            path["matched_permissions"],
            [
                "datastore.databases.update",
                "datastore.entities.create",
                "datastore.entities.delete",
            ],
        )

    def test_project_grant_applies_to_each_exact_database_without_erasing_scope(self) -> None:
        facts = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _database(
                    address="google_firestore_database.archive",
                    name="archive",
                ),
                _project_iam_member(role="roles/datastore.viewer"),
            ]
        )

        self.assertEqual(
            [
                (
                    path["firestore_database_address"],
                    path["scope_type"],
                    path["resource_scope"],
                )
                for path in facts.cloud_run_firestore_access_paths
            ],
            [
                (
                    "google_firestore_database.archive",
                    "project",
                    "firestore_project",
                ),
                (_DATABASE_ADDRESS, "project", "firestore_project"),
            ],
        )

    def test_v1_cloud_run_service_uses_its_runtime_service_account(self) -> None:
        address = "google_cloud_run_service.orders"
        facts = _workload_facts(
            [
                _cloud_run(resource_type=GcpResourceType.CLOUD_RUN_SERVICE),
                _database(),
                _project_iam_member(role="roles/datastore.viewer"),
            ],
            address=address,
        )

        path = facts.cloud_run_firestore_access_paths[0]
        self.assertEqual(path["workload_address"], address)
        self.assertEqual(path["workload_type"], GcpResourceType.CLOUD_RUN_SERVICE)
        self.assertEqual(path["service_account_member"], _SERVICE_ACCOUNT_MEMBER)

    def test_conditioned_basic_role_remains_uncertain_without_an_access_claim(self) -> None:
        condition = {
            "title": "orders-only",
            "expression": f'resource.name == "{_DATABASE_RESOURCE_NAME}"',
        }
        facts = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _project_iam_member(role="roles/editor", condition=condition),
            ]
        )

        self.assertEqual(facts.cloud_run_firestore_access_paths, [])
        self.assertEqual(
            facts.cloud_run_firestore_access_path_uncertainties,
            [
                (
                    f"{_WORKLOAD_ADDRESS}: Firestore IAM posture is incomplete: {_IAM_ADDRESS}: "
                    "basic IAM role roles/editor cannot use conditional database scope for "
                    f"{_DATABASE_RESOURCE_NAME}"
                )
            ],
        )

    def test_runtime_condition_remains_uncertain_without_an_access_claim(self) -> None:
        condition = {
            "title": "temporary",
            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
        }
        facts = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _project_iam_member(condition=condition),
            ]
        )

        self.assertEqual(facts.cloud_run_firestore_access_paths, [])
        self.assertEqual(
            facts.cloud_run_firestore_access_path_uncertainties,
            [
                (
                    f"{_WORKLOAD_ADDRESS}: Firestore IAM posture is incomplete: {_IAM_ADDRESS}: "
                    f"IAM condition applicability to {_DATABASE_RESOURCE_NAME} is not deterministic"
                )
            ],
        )

    def test_nonmatching_identity_does_not_create_an_access_path(self) -> None:
        facts = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _project_iam_member(member="serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"),
            ]
        )

        self.assertEqual(facts.cloud_run_firestore_access_paths, [])
        self.assertEqual(facts.cloud_run_firestore_access_path_uncertainties, [])

    def test_unresolved_custom_role_permissions_remain_uncertain(self) -> None:
        role = f"projects/{_PROJECT}/roles/externalFirestoreRole"
        facts = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _project_iam_member(role=role),
            ]
        )

        self.assertEqual(facts.cloud_run_firestore_access_paths, [])
        self.assertEqual(
            facts.cloud_run_firestore_access_path_uncertainties,
            [
                f"{_WORKLOAD_ADDRESS}: {_IAM_ADDRESS} custom IAM role {role} "
                "does not resolve to deterministic Firestore permissions"
            ],
        )

    def test_irrelevant_custom_role_is_deterministically_quiet(self) -> None:
        role = f"projects/{_PROJECT}/roles/cloudRunFirestore"
        facts = _workload_facts(
            [
                _cloud_run(),
                _database(),
                _custom_role(permissions=["logging.logEntries.create"]),
                _project_iam_member(role=role),
            ]
        )

        self.assertEqual(facts.cloud_run_firestore_access_paths, [])
        self.assertEqual(facts.cloud_run_firestore_access_path_uncertainties, [])

    def test_unresolved_service_account_does_not_create_an_access_claim(self) -> None:
        facts = _workload_facts(
            [
                _cloud_run(service_account=None),
                _database(),
                _project_iam_member(),
            ]
        )

        self.assertEqual(facts.cloud_run_firestore_access_paths, [])
        self.assertEqual(
            facts.cloud_run_firestore_access_path_uncertainties,
            [f"{_WORKLOAD_ADDRESS}: Cloud Run service account is unresolved"],
        )


if __name__ == "__main__":
    unittest.main()

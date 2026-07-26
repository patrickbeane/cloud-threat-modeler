from __future__ import annotations

import json
import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_PROJECT = "tfstride-demo"
_DATABASE_RESOURCE_NAME = f"projects/{_PROJECT}/databases/orders"
_SERVICE_ACCOUNT = "serviceAccount:orders@tfstride-demo.iam.gserviceaccount.com"


def _database(
    *,
    address: str = "google_firestore_database.orders",
    project: str = _PROJECT,
    name: str = "orders",
) -> TerraformResource:
    return _terraform_resource(
        address,
        GcpResourceType.FIRESTORE_DATABASE,
        {
            "id": f"projects/{project}/databases/{name}",
            "name": name,
            "project": project,
            "location_id": "nam5",
            "type": "FIRESTORE_NATIVE",
        },
    )


def _project_iam_member(
    address: str,
    *,
    project: str | None = _PROJECT,
    role: str | None = "roles/datastore.user",
    member: str | None = _SERVICE_ACCOUNT,
    condition: list[dict[str, str]] | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {}
    if project is not None:
        values["project"] = project
    if role is not None:
        values["role"] = role
    if member is not None:
        values["member"] = member
    if condition is not None:
        values["condition"] = condition
    return _terraform_resource(
        address,
        GcpResourceType.PROJECT_IAM_MEMBER,
        values,
        unknown_values=unknown_values,
    )


class GcpFirestoreIamNormalizationTests(unittest.TestCase):
    def test_exact_database_condition_and_project_grant_retain_distinct_scopes(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _database(),
                _project_iam_member(
                    "google_project_iam_member.database_user",
                    condition=[
                        {
                            "title": "orders-only",
                            "expression": f'resource.name == "{_DATABASE_RESOURCE_NAME}"',
                        }
                    ],
                ),
                _project_iam_member(
                    "google_project_iam_member.project_user",
                    role="roles/datastore.owner",
                ),
            ]
        )
        database = inventory.get_by_address("google_firestore_database.orders")
        assert database is not None

        facts = gcp_facts(database)
        self.assertEqual(facts.firestore_database_name, "orders")
        self.assertEqual(
            facts.firestore_iam_grants,
            [
                {
                    "role": "roles/datastore.user",
                    "members": [_SERVICE_ACCOUNT],
                    "source": "google_project_iam_member.database_user",
                    "source_type": "google_project_iam_member",
                    "scope_type": "database",
                    "scope": _DATABASE_RESOURCE_NAME,
                    "project": _PROJECT,
                    "database_resource_name": _DATABASE_RESOURCE_NAME,
                    "grant_basis": "project_iam_condition",
                    "condition_state": "configured",
                    "condition": {
                        "title": "orders-only",
                        "expression": f'resource.name == "{_DATABASE_RESOURCE_NAME}"',
                    },
                },
                {
                    "role": "roles/datastore.owner",
                    "members": [_SERVICE_ACCOUNT],
                    "source": "google_project_iam_member.project_user",
                    "source_type": "google_project_iam_member",
                    "scope_type": "project",
                    "scope": _PROJECT,
                    "project": _PROJECT,
                    "database_resource_name": _DATABASE_RESOURCE_NAME,
                    "grant_basis": "project_iam",
                    "condition_state": "not_configured",
                },
            ],
        )
        self.assertEqual(facts.firestore_iam_posture_uncertainties, [])

    def test_binding_and_policy_members_are_projected_without_losing_source_scope(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _database(),
                _terraform_resource(
                    "google_project_iam_binding.database_users",
                    GcpResourceType.PROJECT_IAM_BINDING,
                    {
                        "project": _PROJECT,
                        "role": "roles/datastore.user",
                        "members": [_SERVICE_ACCOUNT, "group:database@example.com"],
                        "condition": [
                            {
                                "title": "orders-only",
                                "expression": f'"{_DATABASE_RESOURCE_NAME}" == resource.name',
                            }
                        ],
                    },
                ),
                _terraform_resource(
                    "google_project_iam_policy.policy",
                    GcpResourceType.PROJECT_IAM_POLICY,
                    {
                        "project": _PROJECT,
                        "policy_data": json.dumps(
                            {
                                "bindings": [
                                    {
                                        "role": "roles/datastore.viewer",
                                        "members": [_SERVICE_ACCOUNT],
                                    }
                                ]
                            }
                        ),
                    },
                ),
            ]
        )
        database = inventory.get_by_address("google_firestore_database.orders")
        assert database is not None

        grants = gcp_facts(database).firestore_iam_grants
        self.assertEqual(
            [(grant["source_type"], grant["scope_type"]) for grant in grants],
            [
                ("google_project_iam_binding", "database"),
                ("google_project_iam_policy", "project"),
            ],
        )
        self.assertEqual(
            grants[0]["members"],
            [_SERVICE_ACCOUNT, "group:database@example.com"],
        )

    def test_other_database_and_other_project_grants_do_not_attach(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _database(),
                _database(
                    address="google_firestore_database.orders_archive",
                    name="orders-archive",
                ),
                _project_iam_member(
                    "google_project_iam_member.archive_user",
                    condition=[
                        {
                            "title": "archive-only",
                            "expression": ('resource.name == "projects/tfstride-demo/databases/orders-archive"'),
                        }
                    ],
                ),
                _project_iam_member(
                    "google_project_iam_member.other_project",
                    project="other-project",
                ),
            ]
        )
        orders = inventory.get_by_address("google_firestore_database.orders")
        archive = inventory.get_by_address("google_firestore_database.orders_archive")
        assert orders is not None
        assert archive is not None

        self.assertEqual(gcp_facts(orders).firestore_iam_grants, [])
        self.assertEqual(
            [grant["source"] for grant in gcp_facts(archive).firestore_iam_grants],
            ["google_project_iam_member.archive_user"],
        )

    def test_conditioned_basic_role_is_not_projected_as_a_database_grant(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _database(),
                _project_iam_member(
                    "google_project_iam_member.conditioned_editor",
                    role="roles/editor",
                    condition=[
                        {
                            "title": "orders-only",
                            "expression": f'resource.name == "{_DATABASE_RESOURCE_NAME}"',
                        }
                    ],
                ),
            ]
        )
        database = inventory.get_by_address("google_firestore_database.orders")
        assert database is not None

        facts = gcp_facts(database)
        self.assertEqual(facts.firestore_iam_grants, [])
        self.assertEqual(
            facts.firestore_iam_posture_uncertainties,
            [
                (
                    "google_project_iam_member.conditioned_editor: basic IAM role roles/editor "
                    "cannot use conditional database scope for "
                    f"{_DATABASE_RESOURCE_NAME}"
                )
            ],
        )

    def test_unknown_and_runtime_conditions_remain_uncertain_not_database_grants(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _database(),
                _project_iam_member(
                    "google_project_iam_member.unknown_condition",
                    unknown_values={"condition": True},
                ),
                _project_iam_member(
                    "google_project_iam_member.runtime_condition",
                    condition=[
                        {
                            "title": "temporary",
                            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
                        }
                    ],
                ),
            ]
        )
        database = inventory.get_by_address("google_firestore_database.orders")
        assert database is not None

        facts = gcp_facts(database)
        self.assertEqual(facts.firestore_iam_grants, [])
        self.assertEqual(
            facts.firestore_iam_posture_uncertainties,
            [
                (
                    "google_project_iam_member.unknown_condition: IAM condition applicability to "
                    f"{_DATABASE_RESOURCE_NAME} is unknown after planning"
                ),
                (
                    "google_project_iam_member.runtime_condition: IAM condition applicability to "
                    f"{_DATABASE_RESOURCE_NAME} is not deterministic"
                ),
            ],
        )

    def test_unknown_iam_project_remains_uncertain(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _database(),
                _project_iam_member(
                    "google_project_iam_member.unknown_project",
                    project=None,
                    unknown_values={"project": True},
                ),
            ]
        )
        database = inventory.get_by_address("google_firestore_database.orders")
        assert database is not None

        facts = gcp_facts(database)
        self.assertEqual(facts.firestore_iam_grants, [])
        self.assertEqual(
            facts.firestore_iam_posture_uncertainties,
            [f"google_project_iam_member.unknown_project: IAM project is unresolved for {_DATABASE_RESOURCE_NAME}"],
        )

    def test_unknown_iam_role_remains_uncertain(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _database(),
                _project_iam_member(
                    "google_project_iam_member.unknown_role",
                    role=None,
                    unknown_values={"role": True},
                ),
            ]
        )
        database = inventory.get_by_address("google_firestore_database.orders")
        iam_resource = inventory.get_by_address("google_project_iam_member.unknown_role")
        assert database is not None
        assert iam_resource is not None

        self.assertEqual(
            gcp_facts(iam_resource).bindings,
            [{"role": None, "members": [_SERVICE_ACCOUNT], "role_state": "unknown"}],
        )
        self.assertEqual(gcp_facts(database).firestore_iam_grants, [])
        self.assertEqual(
            gcp_facts(database).firestore_iam_posture_uncertainties,
            [f"google_project_iam_member.unknown_role: IAM role is unresolved for {_DATABASE_RESOURCE_NAME}"],
        )

    def test_unknown_iam_member_remains_uncertain(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _database(),
                _project_iam_member(
                    "google_project_iam_member.unknown_member",
                    member=None,
                    unknown_values={"member": True},
                ),
            ]
        )
        database = inventory.get_by_address("google_firestore_database.orders")
        iam_resource = inventory.get_by_address("google_project_iam_member.unknown_member")
        assert database is not None
        assert iam_resource is not None

        self.assertEqual(
            gcp_facts(iam_resource).bindings,
            [{"role": "roles/datastore.user", "members": [], "members_state": "unknown"}],
        )
        self.assertEqual(gcp_facts(database).firestore_iam_grants, [])
        self.assertEqual(
            gcp_facts(database).firestore_iam_posture_uncertainties,
            [f"google_project_iam_member.unknown_member: IAM members are unresolved for {_DATABASE_RESOURCE_NAME}"],
        )

    def test_unknown_and_invalid_policy_data_remain_uncertain(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _database(),
                _terraform_resource(
                    "google_project_iam_policy.unknown",
                    GcpResourceType.PROJECT_IAM_POLICY,
                    {"project": _PROJECT},
                    unknown_values={"policy_data": True},
                ),
                _terraform_resource(
                    "google_project_iam_policy.invalid",
                    GcpResourceType.PROJECT_IAM_POLICY,
                    {"project": _PROJECT, "policy_data": "{invalid"},
                ),
            ]
        )
        database = inventory.get_by_address("google_firestore_database.orders")
        unknown_policy = inventory.get_by_address("google_project_iam_policy.unknown")
        invalid_policy = inventory.get_by_address("google_project_iam_policy.invalid")
        assert database is not None
        assert unknown_policy is not None
        assert invalid_policy is not None

        self.assertEqual(gcp_facts(unknown_policy).iam_policy_data_state, "unknown")
        self.assertEqual(gcp_facts(invalid_policy).iam_policy_data_state, "invalid")
        self.assertEqual(gcp_facts(database).firestore_iam_grants, [])
        self.assertEqual(
            gcp_facts(database).firestore_iam_posture_uncertainties,
            [
                f"google_project_iam_policy.unknown: IAM policy_data is unknown for {_DATABASE_RESOURCE_NAME}",
                f"google_project_iam_policy.invalid: IAM policy_data is invalid for {_DATABASE_RESOURCE_NAME}",
            ],
        )

    def test_database_without_exact_identity_retains_uncertainty(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_firestore_database.unknown",
                    GcpResourceType.FIRESTORE_DATABASE,
                    {"project": _PROJECT, "location_id": "nam5", "type": "FIRESTORE_NATIVE"},
                    unknown_values={"id": True, "name": True},
                ),
                _project_iam_member("google_project_iam_member.project_user"),
            ]
        )
        database = inventory.get_by_address("google_firestore_database.unknown")
        assert database is not None

        facts = gcp_facts(database)
        self.assertEqual(facts.firestore_iam_grants, [])
        self.assertEqual(
            facts.firestore_iam_posture_uncertainties,
            ["google_firestore_database.unknown: exact Firestore database identity is unresolved"],
        )


if __name__ == "__main__":
    unittest.main()

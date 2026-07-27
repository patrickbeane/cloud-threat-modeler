from __future__ import annotations

import unittest

from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _DATABASE_ADDRESS,
    _DATABASE_RESOURCE_NAME,
    _IAM_ADDRESS,
    _PROJECT,
    _SERVICE_ACCOUNT_MEMBER,
    _WORKLOAD_ADDRESS,
    _custom_role,
    _database,
    _project_iam_member,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _PUBLIC_INVOKER_ADDRESS,
    _as_resource,
    _evidence,
    _public_cloud_run,
    _public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.gcp.cloud_run_firestore_rules import _path_entity_read_operations
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_RULE_ID = "gcp-public-cloud-run-firestore-read-access"
_CUSTOM_ROLE = f"projects/{_PROJECT}/roles/cloudRunFirestore"


def _evaluate(resources: list[TerraformResource]):
    inventory = GcpNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    return StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


class GcpPublicCloudRunFirestoreReadRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_project_applicable_entity_read_grant_is_reported(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(_project_iam_member(role="roles/datastore.viewer")),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.INFORMATION_DISCLOSURE)
        self.assertEqual(
            finding.affected_resources,
            [
                _WORKLOAD_ADDRESS,
                _PUBLIC_INVOKER_ADDRESS,
                _DATABASE_ADDRESS,
                _IAM_ADDRESS,
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            f"internet-to-service:internet->{_WORKLOAD_ADDRESS}",
        )
        self.assertIsNotNone(finding.severity_reasoning)
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)
        self.assertEqual(finding.severity_reasoning.privilege_breadth, 1)
        self.assertIn("datastore.entities.get, datastore.entities.list", finding.rationale)
        self.assertIn("grant is project-applicable", finding.rationale)
        self.assertIn(
            "Firestore Security Rules are not evaluated for server/API access",
            finding.rationale,
        )

        evidence = _evidence(finding)
        self.assertEqual(
            evidence["public_invoker_bindings"],
            [f"source={_PUBLIC_INVOKER_ADDRESS}; role=roles/run.invoker; member=allUsers; condition=none"],
        )
        self.assertIn(
            f"member={_SERVICE_ACCOUNT_MEMBER}",
            evidence["runtime_identity"][0],
        )
        path_evidence = evidence["firestore_read_paths"][0]
        self.assertIn(f"database_address={_DATABASE_ADDRESS}", path_evidence)
        self.assertIn("entity_read_operations=get,list", path_evidence)
        self.assertIn(
            "matched_permissions=datastore.entities.get,datastore.entities.list",
            path_evidence,
        )
        self.assertIn("scope_type=project", path_evidence)
        self.assertEqual(
            evidence["scope_breadth"],
            [
                "project_applicable_grants=1; exact_database_grants=0; "
                "modeled_databases=1; blast_radius_basis=project_applicable_grant"
            ],
        )
        self.assertIn(
            "firestore_security_rules=not evaluated for server/API access",
            evidence["authorization_scope"][1],
        )
        self.assertIn(
            "datastore.entities.list permits document-name enumeration",
            evidence["authorization_scope"][2],
        )
        self.assertIn(
            "excludes=datastore.databases.export",
            evidence["authorization_scope"][4],
        )

    def test_list_only_role_reports_name_enumeration_without_document_data(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(_project_iam_member(role="roles/firebase.viewer")),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        path_evidence = _evidence(finding)["firestore_read_paths"][0]
        self.assertIn("entity_read_operations=list", path_evidence)
        self.assertIn(
            "matched_permissions=datastore.entities.list",
            path_evidence,
        )
        self.assertIn(
            "enumerate document names without establishing access to document contents",
            finding.rationale,
        )
        self.assertNotIn("read document data", finding.rationale)

    def test_exact_database_read_grant_has_narrower_blast_radius(self) -> None:
        condition = {
            "title": "orders-only",
            "expression": f'resource.name == "{_DATABASE_RESOURCE_NAME}"',
        }
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(
                    _project_iam_member(
                        role="roles/datastore.viewer",
                        condition=condition,
                    )
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertIsNotNone(finding.severity_reasoning)
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.blast_radius, 1)
        self.assertIn(
            "limited by exact Firestore database-name conditions",
            finding.rationale,
        )
        path_evidence = _evidence(finding)["firestore_read_paths"][0]
        self.assertIn("scope_type=database", path_evidence)
        self.assertIn("resource_scope=exact_firestore_database", path_evidence)
        self.assertIn(
            "condition_evaluation=exact_database_scope_match",
            path_evidence,
        )

    def test_exact_entity_read_permissions_trigger(self) -> None:
        cases = {
            "get": (["datastore.entities.get"], "get"),
            "list": (["datastore.entities.list"], "list"),
        }

        for case, (permissions, operations) in cases.items():
            with self.subTest(case=case):
                findings = _evaluate(
                    [
                        _public_cloud_run(),
                        _public_invoker(),
                        _as_resource(_database()),
                        _as_resource(_custom_role(permissions=permissions)),
                        _as_resource(_project_iam_member(role=_CUSTOM_ROLE)),
                    ]
                )

                self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
                self.assertIn(
                    f"entity_read_operations={operations}",
                    _evidence(findings[0])["firestore_read_paths"][0],
                )

    def test_defensive_wildcard_classification_is_pinned_without_custom_role_fixture(self) -> None:
        for permission in ("*", "datastore.*", "datastore.entities.*"):
            with self.subTest(permission=permission):
                self.assertEqual(
                    _path_entity_read_operations({"matched_permissions": [permission]}),
                    ["get", "list"],
                )

    def test_supported_public_invocation_mechanisms_are_detected(self) -> None:
        cases = {
            "services invoker": (
                [
                    _public_cloud_run(),
                    _public_invoker(role="roles/run.servicesInvoker"),
                    _as_resource(_database()),
                    _as_resource(_project_iam_member(role="roles/datastore.viewer")),
                ],
                "public_invoker_bindings",
                "role=roles/run.servicesInvoker",
            ),
            "invoker IAM check disabled": (
                [
                    _public_cloud_run(invoker_iam_disabled=True),
                    _as_resource(_database()),
                    _as_resource(_project_iam_member(role="roles/datastore.viewer")),
                ],
                "public_exposure_configuration",
                "invoker_iam_check=disabled; ingress=INGRESS_TRAFFIC_ALL",
            ),
        }

        for case, (resources, evidence_key, expected) in cases.items():
            with self.subTest(case=case):
                findings = _evaluate(resources)
                self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
                self.assertIn(expected, _evidence(findings[0])[evidence_key][0])

    def test_export_mutation_and_uncertain_paths_remain_quiet(self) -> None:
        runtime_condition = {
            "title": "temporary",
            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
        }
        unknown_public_invoker = _public_invoker()
        unknown_public_invoker.unknown_values["condition"] = True
        cases = {
            "export workflow": [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(
                    _project_iam_member(
                        role="roles/datastore.importExportAdmin",
                    )
                ),
            ],
            "database administration with export": [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(_project_iam_member(role="roles/iam.databasesAdmin")),
            ],
            "mutation only": [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(_custom_role(permissions=["datastore.entities.create"])),
                _as_resource(_project_iam_member(role=_CUSTOM_ROLE)),
            ],
            "runtime IAM condition": [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(
                    _project_iam_member(
                        role="roles/datastore.viewer",
                        condition=runtime_condition,
                    )
                ),
            ],
            "private ingress": [
                _public_cloud_run(public_ingress=False),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(_project_iam_member(role="roles/datastore.viewer")),
            ],
            "non-public invoker": [
                _public_cloud_run(),
                _public_invoker(member="serviceAccount:caller@tfstride-demo.iam.gserviceaccount.com"),
                _as_resource(_database()),
                _as_resource(_project_iam_member(role="roles/datastore.viewer")),
            ],
            "unknown public invoker condition": [
                _public_cloud_run(),
                unknown_public_invoker,
                _as_resource(_database()),
                _as_resource(_project_iam_member(role="roles/datastore.viewer")),
            ],
            "unresolved custom role": [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_database()),
                _as_resource(_project_iam_member(role=f"projects/{_PROJECT}/roles/externalFirestore")),
            ],
        }

        for case, resources in cases.items():
            with self.subTest(case=case):
                self.assertEqual(_evaluate(resources), [])


if __name__ == "__main__":
    unittest.main()

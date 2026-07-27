from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _INDEX_ARN as AWS_INDEX_ARN,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _INDEX_PATTERN_ARN as AWS_INDEX_PATTERN_ARN,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _TABLE_ARN as AWS_TABLE_ARN,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _TASK_ROLE_ARN as AWS_TASK_ROLE_ARN,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _role as aws_role,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _role_policy_attachment as aws_role_policy_attachment,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _statement as aws_statement,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _table as aws_table,
)
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _task_definition as aws_task_definition,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _public_edge as aws_public_edge,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _service as aws_service,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _READER_ROLE_ID as AZURE_READER_ROLE_ID,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _SYSTEM_PRINCIPAL_ID as AZURE_SYSTEM_PRINCIPAL_ID,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _account as azure_account,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _container as azure_container,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _database as azure_database,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _native_assignment as azure_native_assignment,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _web_app as azure_web_app,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _DATABASE_RESOURCE_NAME as GCP_DATABASE_RESOURCE_NAME,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _SERVICE_ACCOUNT_MEMBER as GCP_SERVICE_ACCOUNT_MEMBER,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _database as gcp_database,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _project_iam_member as gcp_project_iam_member,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _public_cloud_run as gcp_cloud_run,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _public_invoker as gcp_public_invoker,
)
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts

_AWS_EXTERNAL_POLICY_ARN = "arn:aws:iam::aws:policy/ExternalDynamoDbRead"
_AZURE_METADATA_READ = "Microsoft.DocumentDB/databaseAccounts/readMetadata"
_AZURE_ITEM_READ = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/read"
_AZURE_EXECUTE_QUERY = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/executeQuery"
_AZURE_READ_CHANGE_FEED = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/readChangeFeed"


def _as_resource(value: object) -> TerraformResource:
    assert isinstance(value, TerraformResource)
    return value


def _azure_reader_resources(
    *,
    scope: str = "/",
    public: bool = True,
) -> list[TerraformResource]:
    resources = [azure_account()]
    if scope != "/":
        resources.append(azure_database())
    if "/colls/" in scope:
        resources.append(azure_container())

    workload = azure_web_app()
    workload.values["public_network_access_enabled"] = public
    resources.extend(
        [
            workload,
            azure_native_assignment(
                role_definition_id=AZURE_READER_ROLE_ID,
                scope=scope,
            ),
        ]
    )
    return resources


class ManagedNosqlReadAuthorityCharacterizationTests(unittest.TestCase):
    """Pin read-path prerequisites without introducing disclosure findings."""

    def test_aws_read_paths_preserve_index_policy_relationship_evidence(self) -> None:
        condition = {
            "ForAllValues:StringEquals": {
                "dynamodb:LeadingKeys": ["tenant-123"],
            }
        }
        inventory = AwsNormalizer().normalize(
            [
                *aws_public_edge(),
                aws_table(index_names=("by-status",)),
                aws_role(
                    "orders_task",
                    AWS_TASK_ROLE_ARN,
                    [
                        aws_statement(
                            "Allow",
                            "dynamodb:GetItem",
                            AWS_TABLE_ARN,
                        ),
                        aws_statement(
                            "Allow",
                            ["dynamodb:Query", "dynamodb:Scan"],
                            AWS_INDEX_ARN,
                            condition=condition,
                        ),
                        aws_statement(
                            "Deny",
                            "dynamodb:Scan",
                            AWS_INDEX_PATTERN_ARN,
                        ),
                    ],
                ),
                aws_role_policy_attachment(
                    AWS_TASK_ROLE_ARN,
                    _AWS_EXTERNAL_POLICY_ARN,
                ),
                aws_task_definition(execution_role_arn=None),
                aws_service(),
            ]
        )
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None

        facts = aws_facts(service)
        self.assertEqual(
            facts.internet_facing_load_balancer_addresses,
            ["aws_lb.public"],
        )
        self.assertEqual(facts.task_role_arn, AWS_TASK_ROLE_ARN)
        self.assertEqual(len(facts.ecs_dynamodb_access_paths), 2)
        table_path, index_path = facts.ecs_dynamodb_access_paths
        self.assertEqual(table_path["dynamodb_target_kind"], "table")
        self.assertEqual(table_path["matched_actions"], ["dynamodb:GetItem"])
        self.assertEqual(table_path["access_classes"], ["read"])
        self.assertEqual(table_path["modeled_access_state"], "allowed")
        self.assertEqual(table_path["access_state"], "unknown")
        self.assertFalse(table_path["role_policy_complete"])

        self.assertEqual(index_path["dynamodb_target_kind"], "index")
        self.assertEqual(index_path["dynamodb_index_name"], "by-status")
        self.assertEqual(index_path["dynamodb_index_arn"], AWS_INDEX_ARN)
        self.assertEqual(index_path["access_classes"], [])
        self.assertEqual(index_path["denied_actions"], ["dynamodb:Scan"])
        self.assertEqual(index_path["unknown_actions"], ["dynamodb:Query"])
        self.assertEqual(index_path["modeled_access_state"], "unknown")
        self.assertEqual(index_path["access_state"], "unknown")
        self.assertTrue(index_path["explicit_deny"])
        self.assertTrue(index_path["conditional_evaluation_required"])

        self.assertEqual(len(facts.ecs_dynamodb_index_relationships), 2)
        exact_index, index_pattern = facts.ecs_dynamodb_index_relationships
        self.assertEqual(
            (
                exact_index["workload_address"],
                exact_index["role_kind"],
                exact_index["credential_context"],
                exact_index["role_address"],
            ),
            (
                "aws_ecs_service.orders",
                "ecs_task_role",
                "workload_runtime",
                "aws_iam_role.orders_task",
            ),
        )
        self.assertEqual(
            (
                exact_index["dynamodb_table_address"],
                exact_index["dynamodb_table_arn"],
                exact_index["dynamodb_index_resource_arn"],
                exact_index["resource_scope"],
            ),
            (
                "aws_dynamodb_table.orders",
                AWS_TABLE_ARN,
                AWS_INDEX_ARN,
                "exact_index",
            ),
        )
        self.assertEqual(exact_index["effect"], "allow")
        self.assertEqual(
            exact_index["policy_actions"],
            ["dynamodb:Query", "dynamodb:Scan"],
        )
        self.assertTrue(exact_index["conditional"])
        self.assertEqual(
            exact_index["conditions"],
            [
                {
                    "operator": "ForAllValues:StringEquals",
                    "key": "dynamodb:LeadingKeys",
                    "values": ["tenant-123"],
                }
            ],
        )
        self.assertFalse(exact_index["role_policy_complete"])

        self.assertEqual(index_pattern["effect"], "deny")
        self.assertEqual(index_pattern["resource_scope"], "index_pattern")
        self.assertEqual(
            index_pattern["dynamodb_index_resource_arn"],
            AWS_INDEX_PATTERN_ARN,
        )
        self.assertFalse(index_pattern["conditional"])
        for relationship in facts.ecs_dynamodb_index_relationships:
            self.assertNotIn("access_state", relationship)
            self.assertNotIn("access_classes", relationship)
        self.assertTrue(
            any(_AWS_EXTERNAL_POLICY_ARN in uncertainty for uncertainty in facts.ecs_dynamodb_access_path_uncertainties)
        )

    def test_gcp_read_grants_preserve_project_and_database_scope(self) -> None:
        exact_condition = {
            "title": "orders-only",
            "expression": (f'resource.name == "{GCP_DATABASE_RESOURCE_NAME}"'),
        }
        cases = (
            (
                "project",
                gcp_project_iam_member(role="roles/datastore.viewer"),
                "project",
                "firestore_project",
                None,
                "not_configured",
            ),
            (
                "database",
                gcp_project_iam_member(
                    role="roles/datastore.viewer",
                    condition=exact_condition,
                ),
                "database",
                "exact_firestore_database",
                exact_condition,
                "configured",
            ),
        )

        for (
            case,
            iam_resource,
            scope_type,
            resource_scope,
            condition,
            condition_state,
        ) in cases:
            with self.subTest(case=case):
                inventory = GcpNormalizer().normalize(
                    [
                        gcp_cloud_run(),
                        gcp_public_invoker(),
                        _as_resource(gcp_database()),
                        _as_resource(iam_resource),
                    ]
                )
                workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
                assert workload is not None

                facts = gcp_facts(workload)
                self.assertTrue(workload.public_access_configured)
                self.assertTrue(workload.public_exposure)
                self.assertEqual(
                    facts.service_account_member,
                    GCP_SERVICE_ACCOUNT_MEMBER,
                )
                self.assertEqual(len(facts.cloud_run_firestore_access_paths), 1)
                path = facts.cloud_run_firestore_access_paths[0]
                self.assertEqual(
                    (
                        path["identity_kind"],
                        path["credential_context"],
                        path["service_account_member"],
                    ),
                    (
                        "cloud_run_service_account",
                        "workload_runtime",
                        GCP_SERVICE_ACCOUNT_MEMBER,
                    ),
                )
                self.assertEqual(
                    path["firestore_database_resource_name"],
                    GCP_DATABASE_RESOURCE_NAME,
                )
                self.assertEqual(path["role"], "roles/datastore.viewer")
                self.assertEqual(path["access_classes"], ["read"])
                self.assertEqual(
                    path["matched_permissions"],
                    [
                        "datastore.entities.get",
                        "datastore.entities.list",
                    ],
                )
                self.assertEqual(path["scope_type"], scope_type)
                self.assertEqual(path["resource_scope"], resource_scope)
                self.assertEqual(path["condition"], condition)
                self.assertEqual(path["condition_state"], condition_state)
                self.assertEqual(path["access_state"], "granted")
                self.assertEqual(
                    path["authorization_model"],
                    "iam_authorized_server_api",
                )
                self.assertFalse(
                    path["firestore_security_rules_evaluated"],
                )

    def test_gcp_runtime_condition_and_unresolved_role_do_not_claim_read(
        self,
    ) -> None:
        runtime_condition = {
            "title": "temporary",
            "expression": ("request.time < timestamp('2027-01-01T00:00:00Z')"),
        }
        unresolved_role = "projects/tfstride-demo/roles/externalFirestoreRead"
        cases = (
            (
                "runtime-condition",
                gcp_project_iam_member(
                    role="roles/datastore.viewer",
                    condition=runtime_condition,
                ),
                "condition applicability",
            ),
            (
                "unresolved-role",
                gcp_project_iam_member(role=unresolved_role),
                unresolved_role,
            ),
        )

        for case, iam_resource, uncertainty_fragment in cases:
            with self.subTest(case=case):
                inventory = GcpNormalizer().normalize(
                    [
                        gcp_cloud_run(),
                        gcp_public_invoker(),
                        _as_resource(gcp_database()),
                        _as_resource(iam_resource),
                    ]
                )
                workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
                assert workload is not None

                facts = gcp_facts(workload)
                self.assertTrue(workload.public_exposure)
                self.assertEqual(
                    facts.cloud_run_firestore_access_paths,
                    [],
                )
                self.assertTrue(
                    any(
                        uncertainty_fragment in uncertainty
                        for uncertainty in (facts.cloud_run_firestore_access_path_uncertainties)
                    )
                )

    def test_azure_reader_preserves_native_scope_and_runtime_identity(
        self,
    ) -> None:
        expected_actions = [
            _AZURE_METADATA_READ,
            _AZURE_ITEM_READ,
            _AZURE_EXECUTE_QUERY,
            _AZURE_READ_CHANGE_FEED,
        ]
        cases = (
            (
                "account",
                "/",
                "account",
                "exact_cosmosdb_for_nosql_account",
                "azurerm_cosmosdb_account.orders",
            ),
            (
                "database",
                "/dbs/app",
                "database",
                "exact_cosmosdb_for_nosql_database",
                "azurerm_cosmosdb_sql_database.app",
            ),
            (
                "container",
                "/dbs/app/colls/events",
                "container",
                "exact_cosmosdb_for_nosql_container",
                "azurerm_cosmosdb_sql_container.events",
            ),
        )

        for (
            case,
            scope,
            scope_type,
            resource_scope,
            target_address,
        ) in cases:
            with self.subTest(case=case):
                inventory = AzureNormalizer().normalize(_azure_reader_resources(scope=scope))
                workload = inventory.get_by_address("azurerm_linux_web_app.orders")
                assert workload is not None

                facts = azure_facts(workload)
                self.assertTrue(workload.public_access_configured)
                self.assertTrue(facts.public_network_access_enabled)
                self.assertEqual(len(facts.app_service_cosmosdb_access_paths), 1)
                path = facts.app_service_cosmosdb_access_paths[0]
                self.assertEqual(
                    (
                        path["identity_kind"],
                        path["credential_context"],
                        path["principal_id"],
                    ),
                    (
                        "system_assigned",
                        "workload_runtime",
                        AZURE_SYSTEM_PRINCIPAL_ID,
                    ),
                )
                self.assertEqual(
                    path["cosmosdb_resource_address"],
                    target_address,
                )
                self.assertEqual(
                    path["cosmosdb_account_address"],
                    "azurerm_cosmosdb_account.orders",
                )
                self.assertEqual(
                    path["role_kind"],
                    "built_in_data_reader",
                )
                self.assertEqual(
                    path["access_classes"],
                    ["metadata_read", "read"],
                )
                self.assertEqual(
                    path["matched_data_actions"],
                    expected_actions,
                )
                self.assertEqual(path["scope_type"], scope_type)
                self.assertEqual(path["resource_scope"], resource_scope)
                self.assertEqual(path["access_state"], "granted")
                self.assertEqual(
                    path["authorization_model"],
                    "cosmosdb_for_nosql_native_rbac",
                )

    def test_azure_unresolved_principal_and_scope_do_not_claim_read(
        self,
    ) -> None:
        cases = (
            (
                "principal",
                [
                    azure_account(),
                    azure_web_app(),
                    azure_native_assignment(
                        principal_id="",
                        role_definition_id=AZURE_READER_ROLE_ID,
                        unknown_values={"principal_id": True},
                    ),
                ],
                "native RBAC principal is unresolved",
            ),
            (
                "scope",
                [
                    azure_account(),
                    azure_web_app(),
                    azure_native_assignment(
                        role_definition_id=AZURE_READER_ROLE_ID,
                        scope="/dbs/external",
                    ),
                ],
                "does not resolve to an exact modeled Cosmos DB for NoSQL target",
            ),
        )

        for case, resources, uncertainty_fragment in cases:
            with self.subTest(case=case):
                workload = next(
                    resource for resource in resources if resource.address == "azurerm_linux_web_app.orders"
                )
                workload.values["public_network_access_enabled"] = True
                inventory = AzureNormalizer().normalize(resources)
                normalized = inventory.get_by_address(workload.address)
                assert normalized is not None

                facts = azure_facts(normalized)
                self.assertTrue(normalized.public_access_configured)
                self.assertEqual(
                    facts.app_service_cosmosdb_access_paths,
                    [],
                )
                self.assertTrue(
                    any(
                        uncertainty_fragment in uncertainty
                        for uncertainty in (facts.app_service_cosmosdb_access_path_uncertainties)
                    )
                )

    def test_read_authority_does_not_imply_public_exposure(self) -> None:
        aws_inventory = AwsNormalizer().normalize(
            [
                *aws_public_edge(internal=True),
                aws_table(),
                aws_role(
                    "orders_task",
                    AWS_TASK_ROLE_ARN,
                    [
                        aws_statement(
                            "Allow",
                            "dynamodb:Query",
                            AWS_INDEX_ARN,
                        )
                    ],
                ),
                aws_task_definition(execution_role_arn=None),
                aws_service(),
            ]
        )
        aws_workload = aws_inventory.get_by_address("aws_ecs_service.orders")
        assert aws_workload is not None
        self.assertEqual(
            aws_facts(aws_workload).internet_facing_load_balancer_addresses,
            [],
        )
        self.assertEqual(
            len(aws_facts(aws_workload).ecs_dynamodb_index_relationships),
            1,
        )

        gcp_inventory = GcpNormalizer().normalize(
            [
                gcp_cloud_run(public_ingress=False),
                gcp_public_invoker(),
                _as_resource(gcp_database()),
                _as_resource(
                    gcp_project_iam_member(
                        role="roles/datastore.viewer",
                    )
                ),
            ]
        )
        gcp_workload = gcp_inventory.get_by_address("google_cloud_run_v2_service.orders")
        assert gcp_workload is not None
        self.assertFalse(gcp_workload.public_exposure)
        self.assertEqual(
            len(gcp_facts(gcp_workload).cloud_run_firestore_access_paths),
            1,
        )

        azure_inventory = AzureNormalizer().normalize(_azure_reader_resources(public=False))
        azure_workload = azure_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert azure_workload is not None
        self.assertFalse(azure_workload.public_access_configured)
        self.assertEqual(
            len(azure_facts(azure_workload).app_service_cosmosdb_access_paths),
            1,
        )


if __name__ == "__main__":
    unittest.main()

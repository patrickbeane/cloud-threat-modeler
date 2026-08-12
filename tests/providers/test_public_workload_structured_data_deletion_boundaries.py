from __future__ import annotations

import unittest
from typing import Any

from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _EXECUTION_ROLE_ARN as AWS_EXECUTION_ROLE_ARN,
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
    _task_definition as aws_task_definition,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _public_edge as aws_public_edge,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _service as aws_service,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _ACCOUNT_ID as AZURE_ACCOUNT_ID,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _CUSTOM_ROLE_ID as AZURE_CUSTOM_ROLE_ID,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _SYSTEM_PRINCIPAL_ID as AZURE_SYSTEM_PRINCIPAL_ID,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _USER_PRINCIPAL_ID as AZURE_USER_PRINCIPAL_ID,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _container as azure_container,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _custom_role as azure_custom_role,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _database as azure_database,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _function_app as azure_function_app,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _native_assignment as azure_native_assignment,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _user_assigned_identity as azure_user_assigned_identity,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _web_app as azure_web_app,
)
from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _DATABASE_ADDRESS as GCP_DATABASE_ADDRESS,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _DATABASE_RESOURCE_NAME as GCP_DATABASE_RESOURCE_NAME,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _PROJECT as GCP_PROJECT,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _SERVICE_ACCOUNT_EMAIL as GCP_SERVICE_ACCOUNT_EMAIL,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _SERVICE_ACCOUNT_MEMBER as GCP_SERVICE_ACCOUNT_MEMBER,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _WORKLOAD_ADDRESS as GCP_WORKLOAD_ADDRESS,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _cloud_run as gcp_cloud_run,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _project_iam_member as gcp_project_iam_member,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _public_invoker as gcp_public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, StrideCategory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_AWS_MUTATION_RULE = "aws-public-ecs-dynamodb-mutation-access"
_GCP_MUTATION_RULE = "gcp-public-cloud-run-firestore-mutation-access"
_AZURE_MUTATION_RULE = "azure-public-app-service-cosmosdb-mutation-access"

_AWS_ITEM_WRITES = (
    "dynamodb:PutItem",
    "dynamodb:UpdateItem",
)
_AWS_ITEM_DELETES = (
    "dynamodb:DeleteItem",
    "dynamodb:PartiQLDelete",
)
_AWS_BATCH_WRITE = "dynamodb:BatchWriteItem"
_AWS_TRANSACTION_API_NAME = "dynamodb:TransactWriteItems"

_GCP_ENTITY_WRITES = (
    "datastore.entities.create",
    "datastore.entities.update",
)
_GCP_ENTITY_DELETE = "datastore.entities.delete"
_GCP_BULK_DELETE = "datastore.databases.bulkDelete"

_AZURE_ITEM_CREATE = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/create"
_AZURE_ITEM_REPLACE = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/replace"
_AZURE_ITEM_UPSERT = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/upsert"
_AZURE_ITEM_DELETE = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/delete"


def _aws_table(
    *,
    pitr_enabled: bool | None = None,
    recovery_period_days: int | None = None,
    deletion_protection_enabled: bool | None = None,
    unknown_pitr: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": "orders",
        "name": "orders",
        "arn": AWS_TABLE_ARN,
    }
    if pitr_enabled is not None:
        pitr: dict[str, object] = {"enabled": pitr_enabled}
        if recovery_period_days is not None:
            pitr["recovery_period_in_days"] = recovery_period_days
        values["point_in_time_recovery"] = [pitr]
    if deletion_protection_enabled is not None:
        values["deletion_protection_enabled"] = deletion_protection_enabled
    return TerraformResource(
        address="aws_dynamodb_table.orders",
        mode="managed",
        resource_type="aws_dynamodb_table",
        name="orders",
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=({"point_in_time_recovery": True} if unknown_pitr else {}),
    )


def _aws_resources(
    actions: str | list[str] | tuple[str, ...],
    *,
    public: bool = True,
    table: TerraformResource | None = None,
    condition: dict[str, object] | None = None,
) -> list[TerraformResource]:
    return [
        *aws_public_edge(internal=not public),
        table or _aws_table(),
        aws_role(
            "orders_task",
            AWS_TASK_ROLE_ARN,
            [
                aws_statement(
                    "Allow",
                    list(actions) if isinstance(actions, tuple) else actions,
                    AWS_TABLE_ARN,
                    condition=condition,
                )
            ],
        ),
        aws_task_definition(execution_role_arn=None),
        aws_service(),
    ]


def _gcp_database(
    *,
    address: str = GCP_DATABASE_ADDRESS,
    name: str = "orders",
    pitr_enablement: str | None = None,
    delete_protection_state: str | None = None,
    unknown_pitr: bool = False,
) -> TerraformResource:
    resource_name = f"projects/{GCP_PROJECT}/databases/{name}"
    values: dict[str, object] = {
        "id": resource_name,
        "name": name,
        "project": GCP_PROJECT,
        "location_id": "nam5",
        "type": "FIRESTORE_NATIVE",
    }
    if pitr_enablement is not None:
        values["point_in_time_recovery_enablement"] = pitr_enablement
    if delete_protection_state is not None:
        values["delete_protection_state"] = delete_protection_state
    return _terraform_resource(
        address,
        GcpResourceType.FIRESTORE_DATABASE,
        values,
        unknown_values=({"point_in_time_recovery_enablement": True} if unknown_pitr else None),
    )


def _gcp_custom_role(
    permissions: list[str],
    *,
    role_id: str = "structuredDataBoundary",
    stage: str = "GA",
    deleted: bool | None = False,
    unknown_permissions: bool = False,
    unknown_deleted: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "project": GCP_PROJECT,
        "role_id": role_id,
        "name": f"projects/{GCP_PROJECT}/roles/{role_id}",
        "permissions": permissions,
        "stage": stage,
    }
    if deleted is not None:
        values["deleted"] = deleted
    unknown_values: dict[str, object] = {}
    if unknown_permissions:
        unknown_values["permissions"] = True
    if unknown_deleted:
        unknown_values["deleted"] = True
    return _terraform_resource(
        f"google_project_iam_custom_role.{role_id}",
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        values,
        unknown_values=unknown_values or None,
    )


def _gcp_role_name(role_id: str = "structuredDataBoundary") -> str:
    return f"projects/{GCP_PROJECT}/roles/{role_id}"


def _gcp_workload(*, public: bool = True) -> TerraformResource:
    workload = gcp_cloud_run()
    assert isinstance(workload, TerraformResource)
    workload.values["ingress"] = "INGRESS_TRAFFIC_ALL" if public else "INGRESS_TRAFFIC_INTERNAL_ONLY"
    return workload


def _gcp_resources(
    permissions: list[str],
    *,
    public: bool = True,
    database: TerraformResource | None = None,
    condition: dict[str, str] | None = None,
) -> list[TerraformResource]:
    return [
        _gcp_workload(public=public),
        gcp_public_invoker(),
        database or _gcp_database(),
        _gcp_custom_role(permissions),
        gcp_project_iam_member(
            role=_gcp_role_name(),
            condition=condition,
        ),
    ]


def _azure_account(
    *,
    backup_type: str | None = None,
    backup_tier: str | None = None,
    interval_minutes: int | None = None,
    retention_hours: int | None = None,
    storage_redundancy: str | None = None,
    unknown_backup: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": AZURE_ACCOUNT_ID,
        "name": "orders",
        "resource_group_name": "data",
        "location": "eastus",
        "offer_type": "Standard",
    }
    if backup_type is not None:
        backup: dict[str, object] = {"type": backup_type}
        if backup_tier is not None:
            backup["tier"] = backup_tier
        if interval_minutes is not None:
            backup["interval_in_minutes"] = interval_minutes
        if retention_hours is not None:
            backup["retention_in_hours"] = retention_hours
        if storage_redundancy is not None:
            backup["storage_redundancy"] = storage_redundancy
        values["backup"] = [backup]
    return TerraformResource(
        address="azurerm_cosmosdb_account.orders",
        mode="managed",
        resource_type=AzureResourceType.COSMOSDB_ACCOUNT,
        name="orders",
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values={"backup": True} if unknown_backup else {},
    )


def _azure_workload(
    *,
    public: bool = True,
) -> TerraformResource:
    workload = azure_web_app()
    workload.values["public_network_access_enabled"] = public
    return workload


def _azure_resources(
    data_actions: list[str],
    *,
    target_kind: str = "account",
    public: bool = True,
    account: TerraformResource | None = None,
) -> list[TerraformResource]:
    resources = [account or _azure_account()]
    if target_kind in {"database", "container"}:
        resources.append(azure_database())
    if target_kind == "container":
        resources.append(azure_container())

    scope = {
        "account": "/",
        "database": "/dbs/app",
        "container": "/dbs/app/colls/events",
    }[target_kind]
    assignable_scope = {
        "account": AZURE_ACCOUNT_ID,
        "database": f"{AZURE_ACCOUNT_ID}/dbs/app",
        "container": f"{AZURE_ACCOUNT_ID}/dbs/app/colls/events",
    }[target_kind]
    resources.extend(
        [
            _azure_workload(public=public),
            azure_custom_role(
                data_actions=data_actions,
                assignable_scopes=[assignable_scope],
            ),
            azure_native_assignment(
                role_definition_id=AZURE_CUSTOM_ROLE_ID,
                scope=scope,
            ),
        ]
    )
    return resources


def _evaluate(
    normalizer: ProviderNormalizer,
    resources: list[Any],
    rule_id: str,
) -> list[Finding]:
    inventory = normalizer.normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({rule_id})),
    )


class PublicWorkloadStructuredDataDeletionBoundaryTests(unittest.TestCase):
    """Pin record-deletion prerequisites without constructing disruption paths."""

    def test_create_update_replace_and_upsert_remain_tampering(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(_AWS_ITEM_WRITES),
                _AWS_MUTATION_RULE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(list(_GCP_ENTITY_WRITES)),
                _GCP_MUTATION_RULE,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(
                    [
                        _AZURE_ITEM_CREATE,
                        _AZURE_ITEM_REPLACE,
                        _AZURE_ITEM_UPSERT,
                    ]
                ),
                _AZURE_MUTATION_RULE,
            ),
        )

        for provider, normalizer, resources, rule_id in cases:
            with self.subTest(provider=provider):
                findings = _evaluate(normalizer, resources, rule_id)
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [rule_id],
                )
                self.assertEqual(
                    findings[0].category,
                    StrideCategory.TAMPERING,
                )

    def test_write_and_delete_authority_preserves_both_effect_inputs(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize(_aws_resources(["dynamodb:PutItem", "dynamodb:DeleteItem"]))
        gcp_inventory = GcpNormalizer().normalize(_gcp_resources(["datastore.entities.create", _GCP_ENTITY_DELETE]))
        azure_inventory = AzureNormalizer().normalize(_azure_resources([_AZURE_ITEM_CREATE, _AZURE_ITEM_DELETE]))

        aws_workload = aws_inventory.get_by_address("aws_ecs_service.orders")
        gcp_workload_resource = gcp_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        azure_workload_resource = azure_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert aws_workload is not None
        assert gcp_workload_resource is not None
        assert azure_workload_resource is not None

        access_classes = (
            aws_facts(aws_workload).ecs_dynamodb_access_paths[0]["access_classes"],
            gcp_facts(gcp_workload_resource).cloud_run_firestore_access_paths[0]["access_classes"],
            azure_facts(azure_workload_resource).app_service_cosmosdb_access_paths[0]["access_classes"],
        )
        for provider, classes in zip(
            ("aws", "gcp", "azure"),
            access_classes,
            strict=True,
        ):
            with self.subTest(provider=provider):
                self.assertIn("entity_write", classes)
                self.assertIn("entity_delete", classes)

    def test_aws_deletion_capabilities_are_operation_exact(self) -> None:
        expectations = {
            "dynamodb:DeleteItem": [
                "return_value_read",
                "entity_delete",
            ],
            "dynamodb:PartiQLDelete": [
                "return_value_read",
                "entity_delete",
            ],
            "dynamodb:BatchWriteItem": [
                "entity_write",
                "entity_delete",
            ],
        }

        for action, access_classes in expectations.items():
            with self.subTest(action=action):
                inventory = AwsNormalizer().normalize(_aws_resources(action))
                service = inventory.get_by_address("aws_ecs_service.orders")
                assert service is not None

                paths = aws_facts(service).ecs_dynamodb_access_paths
                self.assertEqual(len(paths), 1)
                path = paths[0]
                self.assertEqual(path["matched_actions"], [action])
                self.assertEqual(path["access_classes"], access_classes)
                self.assertEqual(path["access_state"], "allowed")
                self.assertEqual(path["role_kind"], "ecs_task_role")
                self.assertEqual(path["credential_context"], "workload_runtime")
                self.assertEqual(path["role_arn"], AWS_TASK_ROLE_ARN)

    def test_aws_transaction_delete_uses_delete_item_authority(self) -> None:
        direct_inventory = AwsNormalizer().normalize(_aws_resources("dynamodb:DeleteItem"))
        synthetic_inventory = AwsNormalizer().normalize(_aws_resources(_AWS_TRANSACTION_API_NAME))
        direct_service = direct_inventory.get_by_address("aws_ecs_service.orders")
        synthetic_service = synthetic_inventory.get_by_address("aws_ecs_service.orders")
        assert direct_service is not None
        assert synthetic_service is not None

        direct_path = aws_facts(direct_service).ecs_dynamodb_access_paths[0]
        self.assertEqual(
            direct_path["matched_actions"],
            ["dynamodb:DeleteItem"],
        )
        self.assertIn("entity_delete", direct_path["access_classes"])
        self.assertEqual(
            aws_facts(synthetic_service).ecs_dynamodb_access_paths,
            [],
        )

        transaction_condition = {
            "ForAnyValue:StringEquals": {
                "dynamodb:EnclosingOperation": "TransactWriteItems",
            }
        }
        conditional_inventory = AwsNormalizer().normalize(
            _aws_resources(
                "dynamodb:DeleteItem",
                condition=transaction_condition,
            )
        )
        conditional_service = conditional_inventory.get_by_address("aws_ecs_service.orders")
        assert conditional_service is not None
        conditional_path = aws_facts(conditional_service).ecs_dynamodb_access_paths[0]
        self.assertEqual(conditional_path["access_state"], "unknown")
        self.assertEqual(conditional_path["matched_actions"], [])
        self.assertEqual(
            conditional_path["unknown_actions"],
            ["dynamodb:DeleteItem"],
        )
        self.assertTrue(conditional_path["conditional_evaluation_required"])

    def test_aws_preserves_exact_table_identity_and_recovery_posture(
        self,
    ) -> None:
        table_source = _aws_table(
            pitr_enabled=True,
            recovery_period_days=14,
            deletion_protection_enabled=True,
        )
        inventory = AwsNormalizer().normalize(_aws_resources("dynamodb:DeleteItem", table=table_source))
        service = inventory.get_by_address("aws_ecs_service.orders")
        table = inventory.get_by_address("aws_dynamodb_table.orders")
        load_balancer = inventory.get_by_address("aws_lb.public")
        assert service is not None
        assert table is not None
        assert load_balancer is not None

        self.assertTrue(load_balancer.public_exposure)
        path = aws_facts(service).ecs_dynamodb_access_paths[0]
        self.assertEqual(path["dynamodb_table_address"], table.address)
        self.assertEqual(path["dynamodb_table_arn"], AWS_TABLE_ARN)
        self.assertEqual(path["resource_scopes"], ["exact_table"])
        self.assertEqual(path["policy_resources"], [AWS_TABLE_ARN])
        self.assertNotIn("item_key", path)
        self.assertNotIn("recovery_evidence", path)

        table_facts = aws_facts(table)
        self.assertEqual(table_facts.dynamodb_pitr_state, "enabled")
        self.assertTrue(table_facts.dynamodb_pitr_enabled)
        self.assertEqual(
            table_facts.dynamodb_pitr_recovery_period_days,
            14,
        )
        self.assertEqual(
            table_facts.dynamodb_deletion_protection_state,
            "enabled",
        )
        self.assertTrue(table_facts.dynamodb_deletion_protection_enabled)

    def test_aws_pitr_states_remain_provider_native_and_plan_local(
        self,
    ) -> None:
        cases = (
            (
                "enabled",
                _aws_table(
                    pitr_enabled=True,
                    recovery_period_days=14,
                ),
                "enabled",
                True,
                14,
            ),
            (
                "disabled",
                _aws_table(pitr_enabled=False),
                "disabled",
                False,
                None,
            ),
            (
                "not-configured",
                _aws_table(),
                "not_configured",
                None,
                None,
            ),
            (
                "unknown",
                _aws_table(unknown_pitr=True),
                "unknown",
                None,
                None,
            ),
        )

        for (
            case,
            table_source,
            expected_state,
            expected_enabled,
            expected_period,
        ) in cases:
            with self.subTest(case=case):
                inventory = AwsNormalizer().normalize(
                    _aws_resources(
                        "dynamodb:DeleteItem",
                        table=table_source,
                    )
                )
                table = inventory.get_by_address("aws_dynamodb_table.orders")
                service = inventory.get_by_address("aws_ecs_service.orders")
                assert table is not None
                assert service is not None
                facts = aws_facts(table)
                self.assertEqual(facts.dynamodb_pitr_state, expected_state)
                self.assertIs(facts.dynamodb_pitr_enabled, expected_enabled)
                self.assertEqual(
                    facts.dynamodb_pitr_recovery_period_days,
                    expected_period,
                )
                self.assertEqual(
                    aws_facts(service).ecs_dynamodb_access_paths[0]["matched_actions"],
                    ["dynamodb:DeleteItem"],
                )

    def test_aws_denied_incomplete_and_non_exact_delete_evidence_stays_non_deterministic(
        self,
    ) -> None:
        denied_inventory = AwsNormalizer().normalize(
            [
                _aws_table(),
                aws_role(
                    "orders_task",
                    AWS_TASK_ROLE_ARN,
                    [
                        aws_statement(
                            "Allow",
                            "dynamodb:DeleteItem",
                            AWS_TABLE_ARN,
                        ),
                        aws_statement(
                            "Deny",
                            "dynamodb:DeleteItem",
                            AWS_TABLE_ARN,
                        ),
                    ],
                ),
                aws_task_definition(execution_role_arn=None),
            ]
        )
        denied_task = denied_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert denied_task is not None
        denied_path = aws_facts(denied_task).ecs_dynamodb_access_paths[0]
        self.assertEqual(denied_path["access_state"], "denied")
        self.assertEqual(denied_path["matched_actions"], [])
        self.assertEqual(
            denied_path["denied_actions"],
            ["dynamodb:DeleteItem"],
        )
        self.assertTrue(denied_path["explicit_deny"])

        policy_arn = "arn:aws:iam::aws:policy/ExternalDynamoDbAccess"
        incomplete_inventory = AwsNormalizer().normalize(
            [
                _aws_table(),
                aws_role(
                    "orders_task",
                    AWS_TASK_ROLE_ARN,
                    [
                        aws_statement(
                            "Allow",
                            "dynamodb:DeleteItem",
                            AWS_TABLE_ARN,
                        )
                    ],
                ),
                aws_role_policy_attachment(AWS_TASK_ROLE_ARN, policy_arn),
                aws_task_definition(execution_role_arn=None),
            ]
        )
        incomplete_task = incomplete_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert incomplete_task is not None
        incomplete_path = aws_facts(incomplete_task).ecs_dynamodb_access_paths[0]
        self.assertEqual(incomplete_path["modeled_access_state"], "allowed")
        self.assertEqual(incomplete_path["access_state"], "unknown")
        self.assertFalse(incomplete_path["role_policy_complete"])

        wildcard_inventory = AwsNormalizer().normalize(
            [
                _aws_table(),
                aws_role(
                    "orders_task",
                    AWS_TASK_ROLE_ARN,
                    [
                        aws_statement(
                            "Allow",
                            "dynamodb:DeleteItem",
                            "arn:aws:dynamodb:us-east-1:*:table/orders-*",
                        )
                    ],
                ),
                aws_task_definition(execution_role_arn=None),
            ]
        )
        wildcard_task = wildcard_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert wildcard_task is not None
        wildcard_facts = aws_facts(wildcard_task)
        self.assertEqual(wildcard_facts.ecs_dynamodb_access_paths, [])
        self.assertTrue(
            any(
                "does not identify an exact table" in uncertainty
                for uncertainty in wildcard_facts.ecs_dynamodb_access_path_uncertainties
            )
        )

    def test_aws_private_task_role_path_survives_and_execution_role_is_excluded(
        self,
    ) -> None:
        private_resources = _aws_resources(
            "dynamodb:DeleteItem",
            public=False,
        )
        private_inventory = AwsNormalizer().normalize(private_resources)
        private_service = private_inventory.get_by_address("aws_ecs_service.orders")
        private_edge = private_inventory.get_by_address("aws_lb.public")
        assert private_service is not None
        assert private_edge is not None
        self.assertFalse(private_edge.public_exposure)
        self.assertEqual(
            aws_facts(private_service).ecs_dynamodb_access_paths[0]["matched_actions"],
            ["dynamodb:DeleteItem"],
        )
        self.assertEqual(
            _evaluate(
                AwsNormalizer(),
                private_resources,
                _AWS_MUTATION_RULE,
            ),
            [],
        )

        execution_inventory = AwsNormalizer().normalize(
            [
                _aws_table(),
                aws_role("orders_task", AWS_TASK_ROLE_ARN, []),
                aws_role(
                    "orders_execution",
                    AWS_EXECUTION_ROLE_ARN,
                    [
                        aws_statement(
                            "Allow",
                            "dynamodb:DeleteItem",
                            AWS_TABLE_ARN,
                        )
                    ],
                ),
                aws_task_definition(),
                aws_service(),
            ]
        )
        execution_service = execution_inventory.get_by_address("aws_ecs_service.orders")
        assert execution_service is not None
        self.assertEqual(
            aws_facts(execution_service).ecs_dynamodb_access_paths,
            [],
        )

    def test_gcp_entity_and_bulk_deletion_permissions_remain_distinct(
        self,
    ) -> None:
        expectations = {
            _GCP_ENTITY_DELETE: ["entity_delete"],
            _GCP_BULK_DELETE: [
                "entity_delete",
                "destructive_administration",
            ],
            "datastore.databases.delete": [
                "destructive_administration",
            ],
        }
        for permission, access_classes in expectations.items():
            with self.subTest(permission=permission):
                inventory = GcpNormalizer().normalize(_gcp_resources([permission]))
                workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
                assert workload is not None
                path = gcp_facts(workload).cloud_run_firestore_access_paths[0]
                self.assertEqual(path["matched_permissions"], [permission])
                self.assertEqual(path["access_classes"], access_classes)
                self.assertEqual(path["access_state"], "granted")
                self.assertEqual(
                    path["service_account_email"],
                    GCP_SERVICE_ACCOUNT_EMAIL,
                )
                self.assertEqual(
                    path["service_account_member"],
                    GCP_SERVICE_ACCOUNT_MEMBER,
                )

    def test_gcp_current_predefined_roles_retain_exact_delete_permissions(
        self,
    ) -> None:
        cases = (
            (
                "roles/datastore.user",
                _GCP_ENTITY_DELETE,
                ["read", "entity_write", "entity_delete"],
            ),
            (
                "roles/datastore.bulkAdmin",
                _GCP_BULK_DELETE,
                ["entity_delete", "destructive_administration"],
            ),
        )
        for role, permission, expected_classes in cases:
            with self.subTest(role=role):
                inventory = GcpNormalizer().normalize(
                    [
                        _gcp_workload(),
                        _gcp_database(),
                        gcp_project_iam_member(role=role),
                    ]
                )
                workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
                assert workload is not None
                path = gcp_facts(workload).cloud_run_firestore_access_paths[0]
                self.assertIn(permission, path["matched_permissions"])
                self.assertEqual(path["access_classes"], expected_classes)

    def test_gcp_project_and_database_scopes_preserve_exact_ancestry(
        self,
    ) -> None:
        exact_condition = {
            "title": "orders-only",
            "expression": (f'resource.name == "{GCP_DATABASE_RESOURCE_NAME}"'),
        }
        inventory = GcpNormalizer().normalize(
            [
                _gcp_workload(),
                gcp_public_invoker(),
                _gcp_database(
                    pitr_enablement="POINT_IN_TIME_RECOVERY_ENABLED",
                    delete_protection_state="DELETE_PROTECTION_ENABLED",
                ),
                _gcp_custom_role([_GCP_ENTITY_DELETE]),
                gcp_project_iam_member(
                    role=_gcp_role_name(),
                    name="project_delete",
                ),
                gcp_project_iam_member(
                    role=_gcp_role_name(),
                    name="database_delete",
                    condition=exact_condition,
                ),
            ]
        )
        workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        database = inventory.get_by_address(GCP_DATABASE_ADDRESS)
        assert workload is not None
        assert database is not None

        paths = gcp_facts(workload).cloud_run_firestore_access_paths
        self.assertEqual(len(paths), 2)
        self.assertEqual(
            {path["scope_type"] for path in paths},
            {"project", "database"},
        )
        for path in paths:
            self.assertEqual(
                path["firestore_database_address"],
                database.address,
            )
            self.assertEqual(
                path["firestore_database_resource_name"],
                GCP_DATABASE_RESOURCE_NAME,
            )
            self.assertEqual(
                path["matched_permissions"],
                [_GCP_ENTITY_DELETE],
            )
            self.assertNotIn("document_name", path)
            self.assertNotIn("recovery_evidence", path)

        database_path = next(path for path in paths if path["scope_type"] == "database")
        self.assertEqual(database_path["condition_state"], "configured")
        self.assertEqual(
            database_path["condition_evaluation"],
            "exact_database_scope_match",
        )
        project_path = next(path for path in paths if path["scope_type"] == "project")
        self.assertEqual(project_path["condition_state"], "not_configured")
        self.assertEqual(project_path["resource_scope"], "firestore_project")

        database_facts = gcp_facts(database)
        self.assertEqual(database_facts.firestore_pitr_state, "enabled")
        self.assertTrue(database_facts.firestore_pitr_enabled)
        self.assertEqual(
            database_facts.firestore_delete_protection_enablement,
            "enabled",
        )
        self.assertTrue(database_facts.firestore_delete_protection_enabled)

    def test_gcp_project_scope_fans_only_to_exact_modeled_databases(
        self,
    ) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gcp_workload(),
                _gcp_database(),
                _gcp_database(
                    address="google_firestore_database.archive",
                    name="archive",
                ),
                _gcp_custom_role([_GCP_ENTITY_DELETE]),
                gcp_project_iam_member(role=_gcp_role_name()),
            ]
        )
        workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = gcp_facts(workload).cloud_run_firestore_access_paths
        self.assertEqual(
            [path["firestore_database_address"] for path in paths],
            [
                "google_firestore_database.archive",
                GCP_DATABASE_ADDRESS,
            ],
        )
        self.assertTrue(all(path["scope_type"] == "project" for path in paths))
        self.assertTrue(all(path["matched_permissions"] == [_GCP_ENTITY_DELETE] for path in paths))

    def test_gcp_pitr_states_remain_provider_native_and_plan_local(
        self,
    ) -> None:
        cases = (
            (
                "enabled",
                _gcp_database(pitr_enablement="POINT_IN_TIME_RECOVERY_ENABLED"),
                "enabled",
                True,
            ),
            (
                "disabled",
                _gcp_database(pitr_enablement="POINT_IN_TIME_RECOVERY_DISABLED"),
                "disabled",
                False,
            ),
            (
                "not-configured",
                _gcp_database(),
                "not_configured",
                None,
            ),
            (
                "unknown",
                _gcp_database(unknown_pitr=True),
                "unknown",
                None,
            ),
        )

        for case, source, expected_state, expected_enabled in cases:
            with self.subTest(case=case):
                inventory = GcpNormalizer().normalize([source])
                database = inventory.get_by_address(GCP_DATABASE_ADDRESS)
                assert database is not None
                facts = gcp_facts(database)
                self.assertEqual(facts.firestore_pitr_state, expected_state)
                self.assertIs(
                    facts.firestore_pitr_enabled,
                    expected_enabled,
                )

    def test_gcp_runtime_conditions_unresolved_roles_and_identities_remain_uncertain(
        self,
    ) -> None:
        runtime_condition = {
            "title": "temporary",
            "expression": ("request.time < timestamp('2027-01-01T00:00:00Z')"),
        }
        conditional_inventory = GcpNormalizer().normalize(
            _gcp_resources(
                [_GCP_ENTITY_DELETE],
                condition=runtime_condition,
            )
        )
        conditional_workload = conditional_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert conditional_workload is not None
        conditional_facts = gcp_facts(conditional_workload)
        self.assertEqual(
            conditional_facts.cloud_run_firestore_access_paths,
            [],
        )
        self.assertTrue(
            any(
                "not deterministic" in uncertainty
                for uncertainty in conditional_facts.cloud_run_firestore_access_path_uncertainties
            )
        )

        unknown_role_id = "unknownDeleteRole"
        unknown_role_inventory = GcpNormalizer().normalize(
            [
                _gcp_workload(),
                _gcp_database(),
                _gcp_custom_role(
                    [_GCP_ENTITY_DELETE],
                    role_id=unknown_role_id,
                    unknown_permissions=True,
                ),
                gcp_project_iam_member(role=_gcp_role_name(unknown_role_id)),
            ]
        )
        unknown_role_workload = unknown_role_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert unknown_role_workload is not None
        unknown_role_facts = gcp_facts(unknown_role_workload)
        self.assertEqual(
            unknown_role_facts.cloud_run_firestore_access_paths,
            [],
        )
        self.assertTrue(
            any(
                "does not resolve to deterministic Firestore permissions" in uncertainty
                for uncertainty in unknown_role_facts.cloud_run_firestore_access_path_uncertainties
            )
        )

        unresolved_identity = gcp_cloud_run(service_account=None)
        assert isinstance(unresolved_identity, TerraformResource)
        identity_inventory = GcpNormalizer().normalize(
            [
                unresolved_identity,
                _gcp_database(),
                _gcp_custom_role([_GCP_ENTITY_DELETE]),
                gcp_project_iam_member(role=_gcp_role_name()),
            ]
        )
        identity_workload = identity_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert identity_workload is not None
        identity_facts = gcp_facts(identity_workload)
        self.assertEqual(identity_facts.cloud_run_firestore_access_paths, [])
        self.assertEqual(
            identity_facts.cloud_run_firestore_access_path_uncertainties,
            [f"{GCP_WORKLOAD_ADDRESS}: Cloud Run service account is unresolved"],
        )

    def test_gcp_custom_role_lifecycle_remains_separate_from_permission_evidence(
        self,
    ) -> None:
        cases = (
            ("active", "GA", False, False, "GA", False),
            ("disabled", "DISABLED", False, False, "DISABLED", False),
            ("deleted", "GA", True, False, "GA", True),
            ("unknown-deleted", "GA", None, True, "GA", None),
        )
        for (
            case,
            stage,
            deleted,
            unknown_deleted,
            expected_stage,
            expected_deleted,
        ) in cases:
            with self.subTest(case=case):
                role_id = f"{case.replace('-', '_')}DeleteRole"
                role_source = _gcp_custom_role(
                    [_GCP_ENTITY_DELETE],
                    role_id=role_id,
                    stage=stage,
                    deleted=deleted,
                    unknown_deleted=unknown_deleted,
                )
                inventory = GcpNormalizer().normalize(
                    [
                        _gcp_workload(),
                        _gcp_database(),
                        role_source,
                        gcp_project_iam_member(role=_gcp_role_name(role_id)),
                    ]
                )
                role = inventory.get_by_address(role_source.address)
                workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
                assert role is not None
                assert workload is not None
                role_facts = gcp_facts(role)
                self.assertEqual(
                    role_facts.custom_role_stage,
                    expected_stage,
                )
                self.assertIs(
                    role_facts.custom_role_deleted,
                    expected_deleted,
                )
                workload_facts = gcp_facts(workload)
                paths = workload_facts.cloud_run_firestore_access_paths
                uncertainties = workload_facts.cloud_run_firestore_access_path_uncertainties

                if case == "active":
                    self.assertEqual(len(paths), 1)
                    self.assertEqual(
                        paths[0]["matched_permissions"],
                        [_GCP_ENTITY_DELETE],
                    )
                    self.assertEqual(uncertainties, [])
                else:
                    self.assertEqual(paths, [])
                    self.assertTrue(uncertainties)

                expected_uncertainty = {
                    "disabled": "is disabled",
                    "deleted": "is deleted",
                    "unknown-deleted": "unresolved deletion lifecycle",
                }.get(case)
                if expected_uncertainty is not None:
                    self.assertTrue(any(expected_uncertainty in uncertainty for uncertainty in uncertainties))

    def test_gcp_private_deletion_authority_survives_without_public_finding(
        self,
    ) -> None:
        resources = _gcp_resources(
            [_GCP_ENTITY_DELETE],
            public=False,
        )
        inventory = GcpNormalizer().normalize(resources)
        workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert workload is not None
        self.assertEqual(
            gcp_facts(workload).cloud_run_firestore_access_paths[0]["matched_permissions"],
            [_GCP_ENTITY_DELETE],
        )
        self.assertEqual(
            _evaluate(GcpNormalizer(), resources, _GCP_MUTATION_RULE),
            [],
        )

    def test_azure_item_delete_preserves_account_database_and_container_scopes(
        self,
    ) -> None:
        expectations = {
            "account": (
                "azurerm_cosmosdb_account.orders",
                "exact_cosmosdb_for_nosql_account",
            ),
            "database": (
                "azurerm_cosmosdb_sql_database.app",
                "exact_cosmosdb_for_nosql_database",
            ),
            "container": (
                "azurerm_cosmosdb_sql_container.events",
                "exact_cosmosdb_for_nosql_container",
            ),
        }
        for target_kind, (
            expected_address,
            expected_resource_scope,
        ) in expectations.items():
            with self.subTest(target_kind=target_kind):
                inventory = AzureNormalizer().normalize(
                    _azure_resources(
                        [_AZURE_ITEM_DELETE],
                        target_kind=target_kind,
                    )
                )
                workload = inventory.get_by_address("azurerm_linux_web_app.orders")
                assert workload is not None
                path = azure_facts(workload).app_service_cosmosdb_access_paths[0]
                self.assertEqual(
                    path["matched_data_actions"],
                    [_AZURE_ITEM_DELETE],
                )
                self.assertEqual(path["access_classes"], ["entity_delete"])
                self.assertEqual(path["access_state"], "granted")
                self.assertEqual(path["scope_type"], target_kind)
                self.assertEqual(
                    path["cosmosdb_resource_address"],
                    expected_address,
                )
                self.assertEqual(
                    path["resource_scope"],
                    expected_resource_scope,
                )
                self.assertEqual(
                    path["cosmosdb_account_address"],
                    "azurerm_cosmosdb_account.orders",
                )
                self.assertNotIn("item_id", path)
                self.assertNotIn("recovery_evidence", path)

    def test_azure_system_and_user_assigned_runtime_identities_remain_distinct(
        self,
    ) -> None:
        system_inventory = AzureNormalizer().normalize(
            _azure_resources(
                [_AZURE_ITEM_DELETE],
                target_kind="container",
            )
        )
        system_workload = system_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert system_workload is not None
        system_path = azure_facts(system_workload).app_service_cosmosdb_access_paths[0]
        self.assertEqual(system_path["identity_kind"], "system_assigned")
        self.assertEqual(
            system_path["identity_address"],
            "azurerm_linux_web_app.orders",
        )
        self.assertEqual(
            system_path["principal_id"],
            AZURE_SYSTEM_PRINCIPAL_ID,
        )

        function = azure_function_app()
        function.values["public_network_access_enabled"] = True
        user_inventory = AzureNormalizer().normalize(
            [
                _azure_account(),
                azure_database(),
                azure_container(),
                azure_user_assigned_identity(),
                function,
                azure_custom_role(
                    data_actions=[_AZURE_ITEM_DELETE],
                    assignable_scopes=[f"{AZURE_ACCOUNT_ID}/dbs/app/colls/events"],
                ),
                azure_native_assignment(
                    principal_id=AZURE_USER_PRINCIPAL_ID,
                    role_definition_id=AZURE_CUSTOM_ROLE_ID,
                    scope="/dbs/app/colls/events",
                ),
            ]
        )
        user_workload = user_inventory.get_by_address("azurerm_linux_function_app.orders_worker")
        assert user_workload is not None
        user_path = azure_facts(user_workload).app_service_cosmosdb_access_paths[0]
        self.assertEqual(user_path["identity_kind"], "user_assigned")
        self.assertEqual(
            user_path["identity_address"],
            "azurerm_user_assigned_identity.orders_runtime",
        )
        self.assertEqual(user_path["principal_id"], AZURE_USER_PRINCIPAL_ID)

    def test_azure_continuous_periodic_default_and_unknown_backup_remain_distinct(
        self,
    ) -> None:
        cases = (
            (
                "continuous",
                _azure_account(
                    backup_type="Continuous",
                    backup_tier="Continuous30Days",
                ),
                (
                    "configured",
                    "Continuous",
                    "Continuous30Days",
                    None,
                    None,
                ),
            ),
            (
                "periodic",
                _azure_account(
                    backup_type="Periodic",
                    interval_minutes=240,
                    retention_hours=168,
                    storage_redundancy="Geo",
                ),
                ("configured", "Periodic", None, 240, 168),
            ),
            (
                "provider-default",
                _azure_account(),
                ("not_configured", "Periodic", None, 240, 8),
            ),
            (
                "unknown",
                _azure_account(unknown_backup=True),
                ("unknown", None, None, None, None),
            ),
        )

        for case, source, expected in cases:
            with self.subTest(case=case):
                inventory = AzureNormalizer().normalize(
                    _azure_resources(
                        [_AZURE_ITEM_DELETE],
                        account=source,
                    )
                )
                account = inventory.get_by_address("azurerm_cosmosdb_account.orders")
                workload = inventory.get_by_address("azurerm_linux_web_app.orders")
                assert account is not None
                assert workload is not None
                facts = azure_facts(account)
                self.assertEqual(
                    (
                        facts.cosmosdb_backup_configuration_state,
                        facts.cosmosdb_backup_type,
                        facts.cosmosdb_backup_tier,
                        facts.cosmosdb_backup_interval_minutes,
                        facts.cosmosdb_backup_retention_hours,
                    ),
                    expected,
                )
                self.assertEqual(
                    azure_facts(workload).app_service_cosmosdb_access_paths[0]["matched_data_actions"],
                    [_AZURE_ITEM_DELETE],
                )

    def test_azure_unresolved_role_scope_principal_and_identity_fail_closed(
        self,
    ) -> None:
        permissions_inventory = AzureNormalizer().normalize(
            [
                _azure_account(),
                _azure_workload(),
                azure_custom_role(
                    data_actions=[_AZURE_ITEM_DELETE],
                    unknown_permissions=True,
                ),
                azure_native_assignment(role_definition_id=AZURE_CUSTOM_ROLE_ID),
            ]
        )
        permissions_workload = permissions_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert permissions_workload is not None
        permissions_facts = azure_facts(permissions_workload)
        self.assertEqual(
            permissions_facts.app_service_cosmosdb_access_paths,
            [],
        )
        self.assertTrue(
            any(
                "permissions are unresolved" in uncertainty
                for uncertainty in permissions_facts.app_service_cosmosdb_access_path_uncertainties
            )
        )

        scope_inventory = AzureNormalizer().normalize(
            [
                _azure_account(),
                _azure_workload(),
                azure_custom_role(data_actions=[_AZURE_ITEM_DELETE]),
                azure_native_assignment(
                    role_definition_id=AZURE_CUSTOM_ROLE_ID,
                    scope="/dbs/unmodeled",
                ),
            ]
        )
        scope_workload = scope_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert scope_workload is not None
        scope_facts = azure_facts(scope_workload)
        self.assertEqual(scope_facts.app_service_cosmosdb_access_paths, [])
        self.assertTrue(
            any(
                "does not resolve to an exact modeled Cosmos DB for NoSQL target" in uncertainty
                for uncertainty in scope_facts.app_service_cosmosdb_access_path_uncertainties
            )
        )

        principal_inventory = AzureNormalizer().normalize(
            [
                _azure_account(),
                _azure_workload(),
                azure_custom_role(data_actions=[_AZURE_ITEM_DELETE]),
                azure_native_assignment(
                    principal_id="",
                    role_definition_id=AZURE_CUSTOM_ROLE_ID,
                    unknown_values={"principal_id": True},
                ),
            ]
        )
        principal_workload = principal_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert principal_workload is not None
        principal_facts = azure_facts(principal_workload)
        self.assertEqual(
            principal_facts.app_service_cosmosdb_access_paths,
            [],
        )
        self.assertTrue(
            any(
                "native RBAC principal is unresolved" in uncertainty
                for uncertainty in principal_facts.app_service_cosmosdb_access_path_uncertainties
            )
        )

        identity_inventory = AzureNormalizer().normalize(
            [
                _azure_account(),
                azure_web_app(principal_id=None),
                azure_custom_role(data_actions=[_AZURE_ITEM_DELETE]),
                azure_native_assignment(role_definition_id=AZURE_CUSTOM_ROLE_ID),
            ]
        )
        identity_workload = identity_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert identity_workload is not None
        identity_facts = azure_facts(identity_workload)
        self.assertEqual(identity_facts.app_service_cosmosdb_access_paths, [])
        self.assertTrue(
            any(
                "system-assigned identity principal_id is unresolved" in uncertainty
                for uncertainty in identity_facts.app_service_cosmosdb_access_path_uncertainties
            )
        )

    def test_azure_private_deletion_authority_survives_without_public_finding(
        self,
    ) -> None:
        resources = _azure_resources(
            [_AZURE_ITEM_DELETE],
            target_kind="container",
            public=False,
        )
        inventory = AzureNormalizer().normalize(resources)
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None
        self.assertEqual(
            azure_facts(workload).app_service_cosmosdb_access_paths[0]["matched_data_actions"],
            [_AZURE_ITEM_DELETE],
        )
        self.assertEqual(
            _evaluate(AzureNormalizer(), resources, _AZURE_MUTATION_RULE),
            [],
        )

    def test_data_store_destruction_and_recovery_administration_stay_separate(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize(
            _aws_resources(
                [
                    "dynamodb:DeleteTable",
                    "dynamodb:UpdateContinuousBackups",
                ]
            )
        )
        aws_service_resource = aws_inventory.get_by_address("aws_ecs_service.orders")
        assert aws_service_resource is not None
        aws_path = aws_facts(aws_service_resource).ecs_dynamodb_access_paths[0]
        self.assertNotIn("entity_delete", aws_path["access_classes"])
        self.assertEqual(
            aws_path["access_classes"],
            [
                "destructive_administration",
                "configuration_administration",
            ],
        )

        gcp_inventory = GcpNormalizer().normalize(
            _gcp_resources(
                [
                    "datastore.databases.delete",
                    "datastore.databases.update",
                ]
            )
        )
        gcp_workload_resource = gcp_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert gcp_workload_resource is not None
        gcp_path = gcp_facts(gcp_workload_resource).cloud_run_firestore_access_paths[0]
        self.assertNotIn("entity_delete", gcp_path["access_classes"])
        self.assertEqual(
            gcp_path["access_classes"],
            [
                "destructive_administration",
                "configuration_administration",
            ],
        )

        azure_inventory = AzureNormalizer().normalize(
            _azure_resources(["Microsoft.DocumentDB/databaseAccounts/delete"])
        )
        azure_workload_resource = azure_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert azure_workload_resource is not None
        azure_facts_value = azure_facts(azure_workload_resource)
        self.assertEqual(
            azure_facts_value.app_service_cosmosdb_access_paths,
            [],
        )
        self.assertEqual(
            azure_facts_value.app_service_cosmosdb_access_path_uncertainties,
            [],
        )

    def test_provider_local_evidence_does_not_cross_structured_data_boundaries(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize(_aws_resources("dynamodb:DeleteItem"))
        gcp_inventory = GcpNormalizer().normalize(_gcp_resources([_GCP_ENTITY_DELETE]))
        azure_inventory = AzureNormalizer().normalize(
            _azure_resources(
                [_AZURE_ITEM_DELETE],
                target_kind="container",
            )
        )

        aws_workload = aws_inventory.get_by_address("aws_ecs_service.orders")
        gcp_workload_resource = gcp_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        azure_workload_resource = azure_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert aws_workload is not None
        assert gcp_workload_resource is not None
        assert azure_workload_resource is not None

        payloads = {
            "aws": repr(aws_facts(aws_workload).ecs_dynamodb_access_paths),
            "gcp": repr(gcp_facts(gcp_workload_resource).cloud_run_firestore_access_paths),
            "azure": repr(azure_facts(azure_workload_resource).app_service_cosmosdb_access_paths),
        }
        foreign_markers = {
            "aws": ("google_", "azurerm_", "datastore.", "Microsoft.DocumentDB"),
            "gcp": ("aws_", "azurerm_", "dynamodb:", "Microsoft.DocumentDB"),
            "azure": ("aws_", "google_", "dynamodb:", "datastore."),
        }
        for provider, payload in payloads.items():
            with self.subTest(provider=provider):
                for marker in foreign_markers[provider]:
                    self.assertNotIn(marker, payload)


if __name__ == "__main__":
    unittest.main()

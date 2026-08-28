from __future__ import annotations

import json
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
    _CONTAINER_ID as AZURE_CONTAINER_ID,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _CUSTOM_ROLE_ID as AZURE_NATIVE_CUSTOM_ROLE_ID,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _DATABASE_ID as AZURE_DATABASE_ID,
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
    _custom_role as azure_native_role,
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
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _resource as azure_resource,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _symbolic_resolution as azure_symbolic_resolution,
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
    _project_iam_member as gcp_project_iam_member,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _public_invoker as gcp_public_invoker,
)
from tests.providers.test_public_workload_structured_data_deletion_boundaries import (
    _aws_table,
    _azure_account,
    _gcp_custom_role,
    _gcp_database,
    _gcp_role_name,
    _gcp_workload,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, ResourceInventory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.arm_control_plane_authorization import (
    AzureArmControlPlaneAuthorityResult,
    model_arm_control_plane_action_authority,
)
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_decoration.workload_identities import (
    workload_managed_identities,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import (
    AzureDecorationContext,
    AzureResourceIndexBuilder,
)
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_AWS_ACCOUNT_ID = "111122223333"
_AWS_FOREIGN_ACCOUNT_ID = "444455556666"
_AWS_DELETE_TABLE = "dynamodb:DeleteTable"
_AWS_DELETE_TABLE_REPLICA = "dynamodb:DeleteTableReplica"
_AWS_DELETE_ITEM = "dynamodb:DeleteItem"
_AWS_PUT_ITEM = "dynamodb:PutItem"
_AWS_UPDATE_TABLE = "dynamodb:UpdateTable"

_GCP_DELETE_DATABASE = "datastore.databases.delete"
_GCP_DELETE_ENTITY = "datastore.entities.delete"
_GCP_CREATE_ENTITY = "datastore.entities.create"
_GCP_UPDATE_DATABASE = "datastore.databases.update"

_AZURE_DELETE_ACCOUNT = "Microsoft.DocumentDB/databaseAccounts/delete"
_AZURE_DELETE_DATABASE = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete"
_AZURE_DELETE_CONTAINER = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/delete"
_AZURE_DELETE_ITEM = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/delete"
_AZURE_CREATE_ITEM = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/create"
_AZURE_CONTROL_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/cosmos-topology-operator"
)

_AWS_MUTATION_RULE = "aws-public-ecs-dynamodb-mutation-access"
_AWS_ITEM_DISRUPTION_RULE = "aws-public-ecs-dynamodb-item-disruption"
_GCP_MUTATION_RULE = "gcp-public-cloud-run-firestore-mutation-access"
_GCP_ENTITY_DISRUPTION_RULE = "gcp-public-cloud-run-firestore-entity-disruption"
_AZURE_MUTATION_RULE = "azure-public-app-service-cosmosdb-mutation-access"
_AZURE_ITEM_DISRUPTION_RULE = "azure-public-app-service-cosmosdb-item-disruption"


def _evaluate(
    normalizer: ProviderNormalizer,
    resources: list[TerraformResource],
    rule_ids: frozenset[str],
) -> list[Finding]:
    inventory = normalizer.normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )


def _as_resource(value: object) -> TerraformResource:
    assert isinstance(value, TerraformResource)
    return value


def _aws_caller_identity(
    account_id: str = _AWS_ACCOUNT_ID,
) -> TerraformResource:
    return TerraformResource(
        address="data.aws_caller_identity.current",
        mode="data",
        resource_type="aws_caller_identity",
        name="current",
        provider_name="registry.terraform.io/hashicorp/aws",
        values={
            "account_id": account_id,
            "id": account_id,
            "arn": f"arn:aws:iam::{account_id}:root",
        },
        unknown_values={},
    )


def _aws_resources(
    actions: str | list[str],
    *,
    public: bool = True,
    table: TerraformResource | None = None,
    statements: list[dict[str, Any]] | None = None,
    execution_actions: str | list[str] | None = None,
    incomplete: bool = False,
) -> list[TerraformResource]:
    role_statements = (
        statements
        if statements is not None
        else [
            aws_statement(
                "Allow",
                actions,
                (aws_facts_arn(table) if table is not None else AWS_TABLE_ARN),
            )
        ]
    )
    resources = [
        _aws_caller_identity(),
        *aws_public_edge(internal=not public),
        table or _aws_table(),
        aws_role(
            "orders_task",
            AWS_TASK_ROLE_ARN,
            role_statements,
        ),
    ]
    if execution_actions is not None:
        resources.append(
            aws_role(
                "orders_execution",
                AWS_EXECUTION_ROLE_ARN,
                [
                    aws_statement(
                        "Allow",
                        execution_actions,
                        aws_facts_arn(table) if table is not None else AWS_TABLE_ARN,
                    )
                ],
            )
        )
    if incomplete:
        resources.append(
            aws_role_policy_attachment(
                AWS_TASK_ROLE_ARN,
                "arn:aws:iam::aws:policy/ExternalDynamoDbAdministration",
            )
        )
    resources.extend(
        [
            aws_task_definition(execution_role_arn=(AWS_EXECUTION_ROLE_ARN if execution_actions is not None else None)),
            aws_service(),
        ]
    )
    return resources


def aws_facts_arn(table: TerraformResource | None) -> str:
    if table is None:
        return AWS_TABLE_ARN
    value = table.values.get("arn")
    assert isinstance(value, str)
    return value


def _aws_resource_policy(
    *,
    table_arn: str = AWS_TABLE_ARN,
    principal_arn: str = AWS_TASK_ROLE_ARN,
    effect: str = "Allow",
    action: str = _AWS_DELETE_TABLE,
    condition: dict[str, object] | None = None,
) -> TerraformResource:
    statement: dict[str, object] = {
        "Effect": effect,
        "Principal": {"AWS": principal_arn},
        "Action": action,
        "Resource": table_arn,
    }
    if condition is not None:
        statement["Condition"] = condition
    return TerraformResource(
        address="aws_dynamodb_resource_policy.orders",
        mode="managed",
        resource_type="aws_dynamodb_resource_policy",
        name="orders",
        provider_name="registry.terraform.io/hashicorp/aws",
        values={
            "resource_arn": table_arn,
            "policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [statement],
                }
            ),
        },
        unknown_values={},
    )


def _gcp_resources(
    permissions: list[str],
    *,
    public: bool = True,
    database: TerraformResource | None = None,
    condition: dict[str, str] | None = None,
    role: TerraformResource | None = None,
    iam_source: TerraformResource | None = None,
) -> list[TerraformResource]:
    role_source = role or _gcp_custom_role(permissions)
    iam = iam_source or gcp_project_iam_member(
        role=_gcp_role_name(),
        condition=condition,
    )
    assert isinstance(iam, TerraformResource)
    return [
        _gcp_workload(public=public),
        gcp_public_invoker(),
        database or _gcp_database(),
        role_source,
        iam,
    ]


def _gcp_project_binding(
    *,
    role: str,
    members: list[str],
    name: str = "topology",
    unknown_role: bool = False,
) -> TerraformResource:
    return _terraform_resource(
        f"google_project_iam_binding.{name}",
        GcpResourceType.PROJECT_IAM_BINDING,
        {
            "project": GCP_PROJECT,
            "role": role,
            "members": members,
        },
        unknown_values={"role": True} if unknown_role else None,
    )


def _azure_workload(*, public: bool = True) -> TerraformResource:
    workload = azure_web_app()
    workload.values["public_network_access_enabled"] = public
    return workload


def _azure_control_role(
    *,
    actions: list[str],
    not_actions: list[str] | None = None,
    data_actions: list[str] | None = None,
    assignable_scopes: list[str] | None = None,
    unknown_permissions: bool = False,
) -> TerraformResource:
    return azure_resource(
        AzureResourceType.ROLE_DEFINITION,
        {
            "id": _AZURE_CONTROL_ROLE_ID,
            "role_definition_id": _AZURE_CONTROL_ROLE_ID,
            "name": "Cosmos Topology Operator",
            "scope": "/subscriptions/sub-0001",
            "assignable_scopes": (assignable_scopes if assignable_scopes is not None else ["/subscriptions/sub-0001"]),
            "permissions": [
                {
                    "actions": actions,
                    "not_actions": not_actions or [],
                    "data_actions": data_actions or [],
                    "not_data_actions": [],
                }
            ],
        },
        name="cosmos_topology",
        unknown_values=({"permissions": [{"actions": True}]} if unknown_permissions else None),
    )


def _azure_control_assignment(
    *,
    scope: object = AZURE_ACCOUNT_ID,
    principal_id: object = AZURE_SYSTEM_PRINCIPAL_ID,
    condition: object | None = None,
    name: str = "cosmos_topology",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    scope_reference = scope if isinstance(scope, str) and scope.startswith("azurerm_") else None
    values: dict[str, object] = {
        "scope": None if scope_reference is not None else scope,
        "role_definition_id": _AZURE_CONTROL_ROLE_ID,
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if condition is not None:
        values["condition"] = condition
        values["condition_version"] = "2.0"
    resolved_unknown_values = dict(unknown_values or {})
    reference_resolutions = ()
    if scope_reference is not None:
        resolved_unknown_values["scope"] = True
        reference_resolutions = (azure_symbolic_resolution(("scope",), scope_reference),)
    return azure_resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        values,
        name=name,
        unknown_values=resolved_unknown_values,
        reference_resolutions=reference_resolutions,
    )


def _azure_inventory_and_context(
    resources: list[TerraformResource],
) -> tuple[ResourceInventory, AzureDecorationContext]:
    inventory = AzureNormalizer().normalize(resources)
    return (
        inventory,
        AzureDecorationContext(index=AzureResourceIndexBuilder().build(list(inventory.resources))),
    )


def _azure_authority(
    inventory: ResourceInventory,
    context: AzureDecorationContext,
    *,
    target_arm_id: str,
    action: str,
    principal_id: str = AZURE_SYSTEM_PRINCIPAL_ID,
    assignment_address: str = "azurerm_role_assignment.cosmos_topology",
) -> AzureArmControlPlaneAuthorityResult:
    assignment = inventory.get_by_address(assignment_address)
    assert assignment is not None
    return model_arm_control_plane_action_authority(
        assignment,
        context,
        principal_id=principal_id,
        target_arm_id=target_arm_id,
        requested_actions=(action,),
    )


def _azure_management_lock(
    *,
    scope: str,
    level: str = "CanNotDelete",
    name: str = "protect_cosmos",
    unknown_scope: bool = False,
    unknown_level: bool = False,
) -> TerraformResource:
    return azure_resource(
        AzureResourceType.MANAGEMENT_LOCK,
        {
            "name": name,
            "scope": scope,
            "lock_level": level,
            "notes": "Protect structured-data topology",
        },
        name=name,
        unknown_values={
            **({"scope": True} if unknown_scope else {}),
            **({"lock_level": True} if unknown_level else {}),
        },
    )


class PublicWorkloadStructuredDataTopologyDestructionBoundaryTests(unittest.TestCase):
    """Pin structured-data topology inputs without constructing new paths."""

    def test_topology_deletion_remains_distinct_from_item_deletion(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize(_aws_resources([_AWS_DELETE_TABLE, _AWS_DELETE_ITEM]))
        aws_workload = aws_inventory.get_by_address("aws_ecs_service.orders")
        assert aws_workload is not None
        aws_workload_facts = aws_facts(aws_workload)
        self.assertEqual(
            aws_workload_facts.ecs_dynamodb_access_paths[0]["matched_actions"],
            [_AWS_DELETE_ITEM, _AWS_DELETE_TABLE],
        )
        self.assertEqual(
            [path["operation"] for path in aws_workload_facts.ecs_dynamodb_item_deletion_paths],
            [_AWS_DELETE_ITEM],
        )

        gcp_inventory = GcpNormalizer().normalize(_gcp_resources([_GCP_DELETE_DATABASE, _GCP_DELETE_ENTITY]))
        gcp_workload = gcp_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert gcp_workload is not None
        gcp_workload_facts = gcp_facts(gcp_workload)
        self.assertEqual(
            gcp_workload_facts.cloud_run_firestore_access_paths[0]["matched_permissions"],
            [_GCP_DELETE_DATABASE, _GCP_DELETE_ENTITY],
        )
        self.assertEqual(
            [path["operation"] for path in (gcp_workload_facts.cloud_run_firestore_entity_deletion_paths)],
            [_GCP_DELETE_ENTITY],
        )

        azure_resources = [
            _azure_account(),
            azure_database(),
            azure_container(),
            _azure_workload(),
            azure_native_role(
                data_actions=[_AZURE_DELETE_ITEM],
                assignable_scopes=[AZURE_CONTAINER_ID],
            ),
            azure_native_assignment(
                scope="/dbs/app/colls/events",
            ),
            _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
            _azure_control_assignment(
                scope="azurerm_cosmosdb_sql_container.events.id",
            ),
        ]
        azure_inventory, azure_context = _azure_inventory_and_context(azure_resources)
        azure_workload = azure_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert azure_workload is not None
        azure_item_paths = azure_facts(azure_workload).app_service_cosmosdb_item_deletion_paths
        self.assertEqual(
            [path["operation"] for path in azure_item_paths],
            [_AZURE_DELETE_ITEM],
        )
        self.assertNotIn(
            _AZURE_DELETE_CONTAINER,
            azure_item_paths[0]["matched_data_actions"],
        )
        self.assertEqual(
            _azure_authority(
                azure_inventory,
                azure_context,
                target_arm_id=AZURE_CONTAINER_ID,
                action=_AZURE_DELETE_CONTAINER,
            ).state,
            "granted",
        )

    def test_mutation_and_topology_authority_preserve_separate_effect_inputs(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize(_aws_resources([_AWS_PUT_ITEM, _AWS_DELETE_TABLE]))
        aws_workload = aws_inventory.get_by_address("aws_ecs_service.orders")
        assert aws_workload is not None
        aws_path = aws_facts(aws_workload).ecs_dynamodb_access_paths[0]
        self.assertEqual(
            aws_path["matched_actions"],
            [_AWS_PUT_ITEM, _AWS_DELETE_TABLE],
        )
        self.assertIn("entity_write", aws_path["access_classes"])
        self.assertIn(
            "destructive_administration",
            aws_path["access_classes"],
        )

        gcp_inventory = GcpNormalizer().normalize(
            _gcp_resources(
                [
                    _GCP_CREATE_ENTITY,
                    _GCP_DELETE_DATABASE,
                    _GCP_UPDATE_DATABASE,
                ]
            )
        )
        gcp_workload = gcp_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert gcp_workload is not None
        gcp_path = gcp_facts(gcp_workload).cloud_run_firestore_access_paths[0]
        self.assertEqual(
            gcp_path["matched_permissions"],
            [
                _GCP_DELETE_DATABASE,
                _GCP_UPDATE_DATABASE,
                _GCP_CREATE_ENTITY,
            ],
        )
        self.assertIn("entity_write", gcp_path["access_classes"])
        self.assertIn(
            "destructive_administration",
            gcp_path["access_classes"],
        )
        self.assertIn(
            "configuration_administration",
            gcp_path["access_classes"],
        )

        azure_inventory, azure_context = _azure_inventory_and_context(
            [
                _azure_account(),
                azure_database(),
                azure_container(),
                _azure_workload(),
                azure_native_role(
                    data_actions=[_AZURE_CREATE_ITEM],
                    assignable_scopes=[f"{AZURE_ACCOUNT_ID}/dbs/app/colls/events"],
                ),
                azure_native_assignment(
                    role_definition_id=AZURE_NATIVE_CUSTOM_ROLE_ID,
                    scope="/dbs/app/colls/events",
                ),
                _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
                _azure_control_assignment(
                    scope=("azurerm_cosmosdb_sql_container.events.id"),
                ),
            ]
        )
        azure_workload = azure_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert azure_workload is not None
        azure_path = azure_facts(azure_workload).app_service_cosmosdb_access_paths[0]
        self.assertEqual(
            azure_path["matched_data_actions"],
            [_AZURE_CREATE_ITEM],
        )
        self.assertEqual(
            azure_path["access_classes"],
            ["entity_write"],
        )
        self.assertEqual(
            _azure_authority(
                azure_inventory,
                azure_context,
                target_arm_id=AZURE_CONTAINER_ID,
                action=_AZURE_DELETE_CONTAINER,
            ).state,
            "granted",
        )

    def test_aws_task_role_preserves_exact_table_delete_authority(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            _aws_resources(
                _AWS_DELETE_TABLE,
                execution_actions=_AWS_DELETE_TABLE,
            )
        )
        workload = inventory.get_by_address("aws_ecs_service.orders")
        table = inventory.get_by_address("aws_dynamodb_table.orders")
        assert workload is not None
        assert table is not None

        self.assertEqual(inventory.primary_account_id, _AWS_ACCOUNT_ID)
        paths = aws_facts(workload).ecs_dynamodb_access_paths
        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(path["role_kind"], "ecs_task_role")
        self.assertEqual(path["credential_context"], "workload_runtime")
        self.assertEqual(path["role_arn"], AWS_TASK_ROLE_ARN)
        self.assertEqual(
            path["task_definition_address"],
            "aws_ecs_task_definition.orders",
        )
        self.assertEqual(path["dynamodb_table_address"], table.address)
        self.assertEqual(path["dynamodb_table_arn"], AWS_TABLE_ARN)
        self.assertEqual(path["dynamodb_target_kind"], "table")
        self.assertEqual(path["dynamodb_target_scope"], "exact_table")
        self.assertEqual(path["resource_scopes"], ["exact_table"])
        self.assertEqual(path["matched_actions"], [_AWS_DELETE_TABLE])
        self.assertEqual(
            path["access_classes"],
            ["destructive_administration"],
        )
        self.assertEqual(path["access_state"], "allowed")
        self.assertTrue(path["role_policy_complete"])
        self.assertFalse(path["explicit_deny"])
        self.assertFalse(path["conditional_evaluation_required"])
        self.assertEqual(
            aws_facts(workload).ecs_dynamodb_item_deletion_paths,
            [],
        )

    def test_aws_execution_role_cannot_substitute_for_task_role(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _aws_caller_identity(),
                *aws_public_edge(internal=False),
                _aws_table(),
                aws_role("orders_task", AWS_TASK_ROLE_ARN, []),
                aws_role(
                    "orders_execution",
                    AWS_EXECUTION_ROLE_ARN,
                    [
                        aws_statement(
                            "Allow",
                            _AWS_DELETE_TABLE,
                            AWS_TABLE_ARN,
                        )
                    ],
                ),
                aws_task_definition(),
                aws_service(),
            ]
        )
        workload = inventory.get_by_address("aws_ecs_service.orders")
        assert workload is not None
        self.assertEqual(
            aws_facts(workload).ecs_dynamodb_access_paths,
            [],
        )

    def test_aws_deny_condition_incomplete_and_non_exact_evidence_is_not_deterministic(
        self,
    ) -> None:
        cases = {
            "explicit deny": _aws_resources(
                _AWS_DELETE_TABLE,
                statements=[
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_TABLE,
                        AWS_TABLE_ARN,
                    ),
                    aws_statement(
                        "Deny",
                        _AWS_DELETE_TABLE,
                        AWS_TABLE_ARN,
                    ),
                ],
            ),
            "conditional allow": _aws_resources(
                _AWS_DELETE_TABLE,
                statements=[
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_TABLE,
                        AWS_TABLE_ARN,
                        condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                    )
                ],
            ),
            "incomplete identity policy": _aws_resources(
                _AWS_DELETE_TABLE,
                incomplete=True,
            ),
            "wildcard target": _aws_resources(
                _AWS_DELETE_TABLE,
                statements=[
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_TABLE,
                        "arn:aws:dynamodb:us-east-1:*:table/*",
                    )
                ],
            ),
            "index target": _aws_resources(
                _AWS_DELETE_TABLE,
                statements=[
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_TABLE,
                        f"{AWS_TABLE_ARN}/index/by-status",
                    )
                ],
            ),
        }

        for case, resources in cases.items():
            with self.subTest(case=case):
                inventory = AwsNormalizer().normalize(resources)
                workload = inventory.get_by_address("aws_ecs_service.orders")
                assert workload is not None
                facts = aws_facts(workload)
                deterministic = [
                    path
                    for path in facts.ecs_dynamodb_access_paths
                    if path["access_state"] == "allowed"
                    and path["role_policy_complete"] is True
                    and path["matched_actions"] == [_AWS_DELETE_TABLE]
                    and path["dynamodb_target_scope"] == "exact_table"
                    and path["explicit_deny"] is False
                    and path["conditional_evaluation_required"] is False
                ]
                self.assertEqual(deterministic, [])

    def test_aws_wildcard_actions_preserve_non_topology_authority_and_replica_delete_is_separate(
        self,
    ) -> None:
        wildcard_inventory = AwsNormalizer().normalize(_aws_resources("dynamodb:*"))
        wildcard_workload = wildcard_inventory.get_by_address("aws_ecs_service.orders")
        assert wildcard_workload is not None
        wildcard_path = aws_facts(wildcard_workload).ecs_dynamodb_access_paths[0]
        self.assertIn(_AWS_DELETE_TABLE, wildcard_path["matched_actions"])
        self.assertIn(_AWS_PUT_ITEM, wildcard_path["matched_actions"])
        self.assertIn(_AWS_UPDATE_TABLE, wildcard_path["matched_actions"])
        self.assertIn(
            "destructive_administration",
            wildcard_path["access_classes"],
        )
        self.assertIn("entity_write", wildcard_path["access_classes"])
        self.assertIn(
            "configuration_administration",
            wildcard_path["access_classes"],
        )

        replica_inventory = AwsNormalizer().normalize(_aws_resources(_AWS_DELETE_TABLE_REPLICA))
        replica_workload = replica_inventory.get_by_address("aws_ecs_service.orders")
        assert replica_workload is not None
        replica_path = aws_facts(replica_workload).ecs_dynamodb_access_paths[0]
        self.assertEqual(
            replica_path["matched_actions"],
            [_AWS_DELETE_TABLE_REPLICA],
        )
        self.assertNotIn(_AWS_DELETE_TABLE, replica_path["matched_actions"])
        self.assertEqual(
            replica_path["access_classes"],
            ["destructive_administration"],
        )

    def test_aws_resource_policy_and_cross_account_inputs_remain_explicit(
        self,
    ) -> None:
        foreign_table_arn = f"arn:aws:dynamodb:us-east-1:{_AWS_FOREIGN_ACCOUNT_ID}:table/orders"
        foreign_table = _aws_table()
        foreign_table.values["arn"] = foreign_table_arn
        resource_policy = _aws_resource_policy(
            table_arn=foreign_table_arn,
        )
        inventory = AwsNormalizer().normalize(
            [
                *_aws_resources(
                    _AWS_DELETE_TABLE,
                    table=foreign_table,
                ),
                resource_policy,
            ]
        )
        workload = inventory.get_by_address("aws_ecs_service.orders")
        assert workload is not None
        identity_path = aws_facts(workload).ecs_dynamodb_access_paths[0]
        self.assertEqual(identity_path["role_arn"], AWS_TASK_ROLE_ARN)
        self.assertEqual(
            identity_path["dynamodb_table_arn"],
            foreign_table_arn,
        )

        self.assertEqual(
            resource_policy.values["resource_arn"],
            foreign_table_arn,
        )
        policy = json.loads(str(resource_policy.values["policy"]))
        statement = policy["Statement"][0]
        self.assertEqual(statement["Principal"]["AWS"], AWS_TASK_ROLE_ARN)
        self.assertEqual(statement["Action"], _AWS_DELETE_TABLE)
        self.assertEqual(statement["Resource"], foreign_table_arn)

    def test_aws_deletion_protection_and_pitr_are_independent_inputs(
        self,
    ) -> None:
        cases = (
            (
                "protected-with-pitr",
                _aws_table(
                    deletion_protection_enabled=True,
                    pitr_enabled=True,
                    recovery_period_days=14,
                ),
                ("enabled", True, "enabled", True, 14),
            ),
            (
                "unprotected-without-pitr",
                _aws_table(
                    deletion_protection_enabled=False,
                    pitr_enabled=False,
                ),
                ("disabled", False, "disabled", False, None),
            ),
            (
                "not-configured",
                _aws_table(),
                ("not_configured", None, "not_configured", None, None),
            ),
        )
        unknown = _aws_table()
        unknown.unknown_values.update(
            {
                "deletion_protection_enabled": True,
                "point_in_time_recovery": True,
            }
        )
        cases += (
            (
                "unknown",
                unknown,
                ("unknown", None, "unknown", None, None),
            ),
        )

        for case, table_source, expected in cases:
            with self.subTest(case=case):
                inventory = AwsNormalizer().normalize(
                    _aws_resources(
                        _AWS_DELETE_TABLE,
                        table=table_source,
                    )
                )
                table = inventory.get_by_address("aws_dynamodb_table.orders")
                workload = inventory.get_by_address("aws_ecs_service.orders")
                assert table is not None
                assert workload is not None
                facts = aws_facts(table)
                self.assertEqual(
                    (
                        facts.dynamodb_deletion_protection_state,
                        facts.dynamodb_deletion_protection_enabled,
                        facts.dynamodb_pitr_state,
                        facts.dynamodb_pitr_enabled,
                        facts.dynamodb_pitr_recovery_period_days,
                    ),
                    expected,
                )
                self.assertEqual(
                    aws_facts(workload).ecs_dynamodb_access_paths[0]["matched_actions"],
                    [_AWS_DELETE_TABLE],
                )

    def test_aws_private_topology_authority_survives_without_public_findings(
        self,
    ) -> None:
        resources = _aws_resources(
            _AWS_DELETE_TABLE,
            public=False,
        )
        inventory = AwsNormalizer().normalize(resources)
        workload = inventory.get_by_address("aws_ecs_service.orders")
        assert workload is not None
        self.assertEqual(
            aws_facts(workload).ecs_dynamodb_access_paths[0]["matched_actions"],
            [_AWS_DELETE_TABLE],
        )
        self.assertEqual(
            _evaluate(
                AwsNormalizer(),
                resources,
                frozenset(
                    {
                        _AWS_MUTATION_RULE,
                        _AWS_ITEM_DISRUPTION_RULE,
                    }
                ),
            ),
            [],
        )

    def test_azure_arm_actions_and_cosmos_data_actions_remain_distinct(
        self,
    ) -> None:
        resources = [
            _azure_account(),
            azure_database(),
            azure_container(),
            _azure_workload(),
            azure_native_role(
                data_actions=[_AZURE_DELETE_ITEM],
                assignable_scopes=[AZURE_CONTAINER_ID],
            ),
            azure_native_assignment(
                scope="/dbs/app/colls/events",
            ),
            _azure_control_role(
                actions=[_AZURE_DELETE_CONTAINER],
                data_actions=[_AZURE_DELETE_ITEM],
            ),
            _azure_control_assignment(
                scope="azurerm_cosmosdb_sql_container.events.id",
            ),
        ]
        inventory, context = _azure_inventory_and_context(resources)
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None

        item_paths = azure_facts(workload).app_service_cosmosdb_item_deletion_paths
        self.assertEqual(len(item_paths), 1)
        self.assertEqual(
            item_paths[0]["matched_data_actions"],
            [_AZURE_DELETE_ITEM],
        )
        authority = _azure_authority(
            inventory,
            context,
            target_arm_id=AZURE_CONTAINER_ID,
            action=_AZURE_DELETE_CONTAINER,
        )
        self.assertEqual(authority.state, "granted")
        assert authority.grant is not None
        self.assertEqual(
            authority.grant["matched_actions"],
            [_AZURE_DELETE_CONTAINER],
        )
        self.assertNotIn(
            _AZURE_DELETE_ITEM,
            authority.grant["matched_actions"],
        )

        data_only_inventory, data_only_context = _azure_inventory_and_context(
            [
                _azure_account(),
                azure_database(),
                azure_container(),
                _azure_workload(),
                _azure_control_role(
                    actions=[],
                    data_actions=[_AZURE_DELETE_CONTAINER],
                ),
                _azure_control_assignment(
                    scope=("azurerm_cosmosdb_sql_container.events.id"),
                ),
            ]
        )
        self.assertEqual(
            _azure_authority(
                data_only_inventory,
                data_only_context,
                target_arm_id=AZURE_CONTAINER_ID,
                action=_AZURE_DELETE_CONTAINER,
            ).state,
            "not_granted",
        )

    def test_azure_account_scope_preserves_exact_modeled_cosmos_hierarchy(
        self,
    ) -> None:
        resources = [
            _azure_account(),
            azure_database(),
            azure_container(),
            _azure_workload(),
            _azure_control_role(
                actions=[
                    _AZURE_DELETE_ACCOUNT,
                    _AZURE_DELETE_DATABASE,
                    _AZURE_DELETE_CONTAINER,
                ]
            ),
            _azure_control_assignment(),
        ]
        inventory, context = _azure_inventory_and_context(resources)
        account = inventory.get_by_address("azurerm_cosmosdb_account.orders")
        database = inventory.get_by_address("azurerm_cosmosdb_sql_database.app")
        container = inventory.get_by_address("azurerm_cosmosdb_sql_container.events")
        assert account is not None
        assert database is not None
        assert container is not None

        self.assertEqual(
            azure_facts(database).resolved_cosmosdb_account_address,
            account.address,
        )
        self.assertEqual(
            azure_facts(container).resolved_cosmosdb_account_address,
            account.address,
        )
        self.assertEqual(
            azure_facts(container).resolved_cosmosdb_database_address,
            database.address,
        )
        expectations = (
            (account.address, AZURE_ACCOUNT_ID, _AZURE_DELETE_ACCOUNT),
            (
                database.address,
                AZURE_DATABASE_ID,
                _AZURE_DELETE_DATABASE,
            ),
            (
                container.address,
                AZURE_CONTAINER_ID,
                _AZURE_DELETE_CONTAINER,
            ),
        )
        for address, target_id, action in expectations:
            with self.subTest(address=address):
                result = _azure_authority(
                    inventory,
                    context,
                    target_arm_id=target_id,
                    action=action,
                )
                self.assertEqual(result.state, "granted")
                assert result.grant is not None
                self.assertEqual(result.grant["target_arm_id"], target_id)
                self.assertEqual(
                    result.grant["assignment_scope_arm_id"],
                    AZURE_ACCOUNT_ID,
                )
                self.assertEqual(
                    result.grant["matched_actions"],
                    [action],
                )

        modeled_targets = {
            resource.address
            for resource in inventory.resources
            if resource.resource_type
            in {
                AzureResourceType.COSMOSDB_ACCOUNT,
                AzureResourceType.COSMOSDB_SQL_DATABASE,
                AzureResourceType.COSMOSDB_SQL_CONTAINER,
            }
        }
        self.assertEqual(
            modeled_targets,
            {
                "azurerm_cosmosdb_account.orders",
                "azurerm_cosmosdb_sql_database.app",
                "azurerm_cosmosdb_sql_container.events",
            },
        )

    def test_azure_conditions_exclusions_assignable_scope_and_identity_fail_closed(
        self,
    ) -> None:
        scope = "azurerm_cosmosdb_sql_container.events.id"
        cases = {
            "condition": (
                _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
                _azure_control_assignment(
                    scope=scope,
                    condition=(
                        "@Resource[Microsoft.DocumentDB/databaseAccounts/"
                        "sqlDatabases/containers:Name] "
                        "StringEquals events"
                    ),
                ),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unknown",
            ),
            "unknown condition": (
                _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
                _azure_control_assignment(
                    scope=scope,
                    unknown_values={"condition": True},
                ),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unknown",
            ),
            "unknown condition version": (
                _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
                _azure_control_assignment(
                    scope=scope,
                    unknown_values={"condition_version": True},
                ),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unknown",
            ),
            "not action": (
                _azure_control_role(
                    actions=["Microsoft.DocumentDB/databaseAccounts/*"],
                    not_actions=[_AZURE_DELETE_CONTAINER],
                ),
                _azure_control_assignment(scope=scope),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "not_granted",
            ),
            "outside assignable scope": (
                _azure_control_role(
                    actions=[_AZURE_DELETE_CONTAINER],
                    assignable_scopes=["/subscriptions/other-subscription"],
                ),
                _azure_control_assignment(scope=scope),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unknown",
            ),
            "unknown role actions": (
                _azure_control_role(
                    actions=[_AZURE_DELETE_CONTAINER],
                    unknown_permissions=True,
                ),
                _azure_control_assignment(scope=scope),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unknown",
            ),
            "unknown principal": (
                _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
                _azure_control_assignment(
                    scope=scope,
                    principal_id=None,
                    unknown_values={"principal_id": True},
                ),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unknown",
            ),
            "other principal": (
                _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
                _azure_control_assignment(
                    scope=scope,
                    principal_id="other-principal",
                ),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unrelated",
            ),
        }
        for case, (
            role,
            assignment,
            principal_id,
            expected_state,
        ) in cases.items():
            with self.subTest(case=case):
                inventory, context = _azure_inventory_and_context(
                    [
                        _azure_account(),
                        azure_database(),
                        azure_container(),
                        _azure_workload(),
                        role,
                        assignment,
                    ]
                )
                self.assertEqual(
                    _azure_authority(
                        inventory,
                        context,
                        target_arm_id=AZURE_CONTAINER_ID,
                        action=_AZURE_DELETE_CONTAINER,
                        principal_id=principal_id,
                    ).state,
                    expected_state,
                )

    def test_azure_management_locks_and_backup_posture_are_separate_inputs(
        self,
    ) -> None:
        account_source = _azure_account(
            backup_type="Continuous",
            backup_tier="Continuous30Days",
        )
        lock_source = _azure_management_lock(
            scope=AZURE_ACCOUNT_ID,
            level="CanNotDelete",
        )
        inventory, context = _azure_inventory_and_context(
            [
                account_source,
                azure_database(),
                azure_container(),
                _azure_workload(),
                _azure_control_role(
                    actions=[
                        _AZURE_DELETE_ACCOUNT,
                        _AZURE_DELETE_DATABASE,
                        _AZURE_DELETE_CONTAINER,
                    ]
                ),
                _azure_control_assignment(),
                lock_source,
            ]
        )
        account = inventory.get_by_address("azurerm_cosmosdb_account.orders")
        lock = inventory.get_by_address(lock_source.address)
        assert account is not None
        assert lock is not None

        account_facts = azure_facts(account)
        self.assertEqual(
            account_facts.cosmosdb_backup_configuration_state,
            "configured",
        )
        self.assertEqual(account_facts.cosmosdb_backup_type, "Continuous")
        self.assertEqual(
            account_facts.cosmosdb_backup_tier,
            "Continuous30Days",
        )
        self.assertIsNone(account_facts.cosmosdb_backup_interval_minutes)
        self.assertIsNone(account_facts.cosmosdb_backup_retention_hours)

        lock_facts = azure_facts(lock)
        self.assertEqual(lock_facts.management_lock_scope, AZURE_ACCOUNT_ID)
        self.assertEqual(
            lock_facts.management_lock_level,
            "CanNotDelete",
        )
        self.assertEqual(
            _azure_authority(
                inventory,
                context,
                target_arm_id=AZURE_CONTAINER_ID,
                action=_AZURE_DELETE_CONTAINER,
            ).state,
            "granted",
        )
        evidence = json.dumps(
            {
                "account": account.metadata_snapshot(),
                "lock": lock.metadata_snapshot(),
            },
            sort_keys=True,
            default=str,
        )
        self.assertNotIn("successful_deletion", evidence)
        self.assertNotIn("successful_restore", evidence)
        self.assertNotIn("restored", evidence)

        unknown_lock_source = _azure_management_lock(
            scope=AZURE_ACCOUNT_ID,
            unknown_scope=True,
            unknown_level=True,
            name="unknown_cosmos_lock",
        )
        unknown_inventory = AzureNormalizer().normalize([unknown_lock_source])
        unknown_lock = unknown_inventory.get_by_address(unknown_lock_source.address)
        assert unknown_lock is not None
        unknown_lock_facts = azure_facts(unknown_lock)
        self.assertIsNone(unknown_lock_facts.management_lock_scope)
        self.assertIsNone(unknown_lock_facts.management_lock_level)
        self.assertTrue(unknown_lock_facts.management_lock_uncertainties)

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
                (
                    "configured",
                    "Periodic",
                    None,
                    240,
                    168,
                    "Geo",
                ),
            ),
            (
                "provider-default",
                _azure_account(),
                (
                    "not_configured",
                    "Periodic",
                    None,
                    240,
                    8,
                    "Geo",
                ),
            ),
            (
                "unknown",
                _azure_account(unknown_backup=True),
                ("unknown", None, None, None, None, None),
            ),
        )
        for case, account_source, expected in cases:
            with self.subTest(case=case):
                inventory = AzureNormalizer().normalize([account_source])
                account = inventory.get_by_address("azurerm_cosmosdb_account.orders")
                assert account is not None
                facts = azure_facts(account)
                self.assertEqual(
                    (
                        facts.cosmosdb_backup_configuration_state,
                        facts.cosmosdb_backup_type,
                        facts.cosmosdb_backup_tier,
                        facts.cosmosdb_backup_interval_minutes,
                        facts.cosmosdb_backup_retention_hours,
                        facts.cosmosdb_backup_storage_redundancy,
                    ),
                    expected,
                )

    def test_azure_system_and_user_assigned_runtime_identities_remain_distinct(
        self,
    ) -> None:
        system_inventory, system_context = _azure_inventory_and_context(
            [
                _azure_account(),
                _azure_workload(),
                _azure_control_role(actions=[_AZURE_DELETE_ACCOUNT]),
                _azure_control_assignment(
                    name="system_topology",
                ),
            ]
        )
        system_workload = system_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert system_workload is not None
        system_identities, system_uncertainties = workload_managed_identities(
            system_workload,
            system_context,
        )
        self.assertEqual(system_uncertainties, [])
        self.assertEqual(
            [(identity.address, identity_kind) for identity, identity_kind in system_identities],
            [
                (
                    "azurerm_linux_web_app.orders",
                    "system_assigned",
                )
            ],
        )
        self.assertEqual(
            _azure_authority(
                system_inventory,
                system_context,
                target_arm_id=AZURE_ACCOUNT_ID,
                action=_AZURE_DELETE_ACCOUNT,
                assignment_address=("azurerm_role_assignment.system_topology"),
            ).state,
            "granted",
        )

        function = azure_function_app()
        function.values["public_network_access_enabled"] = True
        user_inventory, user_context = _azure_inventory_and_context(
            [
                _azure_account(),
                azure_user_assigned_identity(),
                function,
                _azure_control_role(actions=[_AZURE_DELETE_ACCOUNT]),
                _azure_control_assignment(
                    principal_id=AZURE_USER_PRINCIPAL_ID,
                    name="user_topology",
                ),
            ]
        )
        user_workload = user_inventory.get_by_address("azurerm_linux_function_app.orders_worker")
        assert user_workload is not None
        user_identities, user_uncertainties = workload_managed_identities(
            user_workload,
            user_context,
        )
        self.assertEqual(user_uncertainties, [])
        self.assertEqual(
            [(identity.address, identity_kind) for identity, identity_kind in user_identities],
            [
                (
                    "azurerm_user_assigned_identity.orders_runtime",
                    "user_assigned",
                )
            ],
        )
        self.assertEqual(
            _azure_authority(
                user_inventory,
                user_context,
                target_arm_id=AZURE_ACCOUNT_ID,
                action=_AZURE_DELETE_ACCOUNT,
                principal_id=AZURE_USER_PRINCIPAL_ID,
                assignment_address=("azurerm_role_assignment.user_topology"),
            ).state,
            "granted",
        )

    def test_azure_private_topology_authority_is_independent_from_exposure(
        self,
    ) -> None:
        resources = [
            _azure_account(),
            _azure_workload(public=False),
            _azure_control_role(actions=[_AZURE_DELETE_ACCOUNT]),
            _azure_control_assignment(),
        ]
        inventory, context = _azure_inventory_and_context(resources)
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None
        self.assertFalse(azure_facts(workload).public_network_access_enabled)
        self.assertEqual(
            _azure_authority(
                inventory,
                context,
                target_arm_id=AZURE_ACCOUNT_ID,
                action=_AZURE_DELETE_ACCOUNT,
            ).state,
            "granted",
        )
        self.assertEqual(
            _evaluate(
                AzureNormalizer(),
                resources,
                frozenset(
                    {
                        _AZURE_MUTATION_RULE,
                        _AZURE_ITEM_DISRUPTION_RULE,
                    }
                ),
            ),
            [],
        )

    def test_provider_local_evidence_does_not_cross_structured_data_topology_boundaries(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize(_aws_resources(_AWS_DELETE_TABLE))
        aws_workload = aws_inventory.get_by_address("aws_ecs_service.orders")
        assert aws_workload is not None
        aws_payload = json.dumps(
            aws_facts(aws_workload).ecs_dynamodb_access_paths,
            sort_keys=True,
        )

        gcp_inventory = GcpNormalizer().normalize(_gcp_resources([_GCP_DELETE_DATABASE]))
        gcp_workload = gcp_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert gcp_workload is not None
        gcp_payload = json.dumps(
            gcp_facts(gcp_workload).cloud_run_firestore_access_paths,
            sort_keys=True,
        )

        azure_inventory, azure_context = _azure_inventory_and_context(
            [
                _azure_account(),
                _azure_workload(),
                _azure_control_role(actions=[_AZURE_DELETE_ACCOUNT]),
                _azure_control_assignment(),
            ]
        )
        azure_result = _azure_authority(
            azure_inventory,
            azure_context,
            target_arm_id=AZURE_ACCOUNT_ID,
            action=_AZURE_DELETE_ACCOUNT,
        )
        assert azure_result.grant is not None
        azure_payload = json.dumps(
            azure_result.grant,
            sort_keys=True,
        )

        payloads = {
            "aws": aws_payload,
            "gcp": gcp_payload,
            "azure": azure_payload,
        }
        foreign_markers = {
            "aws": (
                "google_",
                "azurerm_",
                "datastore.",
                "Microsoft.DocumentDB",
            ),
            "gcp": (
                "aws_",
                "azurerm_",
                "dynamodb:",
                "Microsoft.DocumentDB",
            ),
            "azure": (
                "aws_",
                "google_",
                "dynamodb:",
                "datastore.",
            ),
        }
        for provider, payload in payloads.items():
            with self.subTest(provider=provider):
                for marker in foreign_markers[provider]:
                    self.assertNotIn(marker, payload)

    def test_gcp_delete_database_permission_preserves_runtime_identity_and_exact_database(
        self,
    ) -> None:
        inventory = GcpNormalizer().normalize(_gcp_resources([_GCP_DELETE_DATABASE]))
        workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        database = inventory.get_by_address(GCP_DATABASE_ADDRESS)
        assert workload is not None
        assert database is not None

        paths = gcp_facts(workload).cloud_run_firestore_access_paths
        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(
            path["service_account_email"],
            GCP_SERVICE_ACCOUNT_EMAIL,
        )
        self.assertEqual(
            path["service_account_member"],
            GCP_SERVICE_ACCOUNT_MEMBER,
        )
        self.assertEqual(path["identity_kind"], "cloud_run_service_account")
        self.assertEqual(path["credential_context"], "workload_runtime")
        self.assertEqual(path["firestore_database_address"], database.address)
        self.assertEqual(
            path["firestore_database_resource_name"],
            GCP_DATABASE_RESOURCE_NAME,
        )
        self.assertEqual(path["firestore_database_project"], GCP_PROJECT)
        self.assertEqual(
            path["matched_permissions"],
            [_GCP_DELETE_DATABASE],
        )
        self.assertEqual(
            path["access_classes"],
            ["destructive_administration"],
        )
        self.assertEqual(path["scope_type"], "project")
        self.assertEqual(path["scope"], GCP_PROJECT)
        self.assertEqual(path["access_state"], "granted")
        self.assertEqual(
            gcp_facts(workload).cloud_run_firestore_entity_deletion_paths,
            [],
        )

    def test_gcp_predefined_and_custom_roles_keep_database_delete_operation_exact(
        self,
    ) -> None:
        cases = (
            ("roles/datastore.owner", True),
            ("roles/datastore.admin", True),
            ("roles/owner", True),
            ("roles/datastore.user", False),
            ("roles/datastore.bulkAdmin", False),
        )
        for role, grants_delete in cases:
            with self.subTest(role=role):
                iam = gcp_project_iam_member(role=role)
                assert isinstance(iam, TerraformResource)
                inventory = GcpNormalizer().normalize(
                    [
                        _gcp_workload(),
                        _gcp_database(),
                        iam,
                    ]
                )
                workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
                assert workload is not None
                paths = gcp_facts(workload).cloud_run_firestore_access_paths
                matching = [path for path in paths if _GCP_DELETE_DATABASE in path["matched_permissions"]]
                self.assertIs(bool(matching), grants_delete)

        wildcard_role = _gcp_custom_role(["datastore.databases.*"])
        wildcard_inventory = GcpNormalizer().normalize(
            _gcp_resources(
                ["datastore.databases.*"],
                role=wildcard_role,
            )
        )
        wildcard_workload = wildcard_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert wildcard_workload is not None
        wildcard_paths = gcp_facts(wildcard_workload).cloud_run_firestore_access_paths
        self.assertEqual(len(wildcard_paths), 1)
        self.assertEqual(
            wildcard_paths[0]["matched_permissions"],
            ["datastore.databases.*"],
        )
        self.assertNotIn(
            _GCP_DELETE_DATABASE,
            wildcard_paths[0]["matched_permissions"],
        )

    def test_gcp_project_and_exact_database_scopes_preserve_native_ancestry(
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
                _gcp_database(),
                _gcp_custom_role([_GCP_DELETE_DATABASE]),
                _as_resource(
                    gcp_project_iam_member(
                        role=_gcp_role_name(),
                        name="project_delete",
                    )
                ),
                _as_resource(
                    gcp_project_iam_member(
                        role=_gcp_role_name(),
                        name="database_delete",
                        condition=exact_condition,
                    )
                ),
            ]
        )
        workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = gcp_facts(workload).cloud_run_firestore_access_paths
        self.assertEqual(len(paths), 2)
        self.assertEqual(
            {path["scope_type"] for path in paths},
            {"project", "database"},
        )
        for path in paths:
            self.assertEqual(
                path["firestore_database_address"],
                GCP_DATABASE_ADDRESS,
            )
            self.assertEqual(
                path["firestore_database_resource_name"],
                GCP_DATABASE_RESOURCE_NAME,
            )
            self.assertEqual(
                path["matched_permissions"],
                [_GCP_DELETE_DATABASE],
            )
            self.assertNotIn("document_name", path)

        exact_path = next(path for path in paths if path["scope_type"] == "database")
        self.assertEqual(exact_path["scope"], GCP_DATABASE_RESOURCE_NAME)
        self.assertEqual(
            exact_path["condition_evaluation"],
            "exact_database_scope_match",
        )
        project_path = next(path for path in paths if path["scope_type"] == "project")
        self.assertEqual(project_path["scope"], GCP_PROJECT)
        self.assertEqual(
            project_path["condition_state"],
            "not_configured",
        )

    def test_gcp_project_scope_fans_only_to_exact_modeled_databases(
        self,
    ) -> None:
        foreign_database = _gcp_database(
            address="google_firestore_database.foreign",
            name="foreign",
        )
        foreign_database.values["project"] = "foreign-project"
        foreign_database.values["id"] = "projects/foreign-project/databases/foreign"
        inventory = GcpNormalizer().normalize(
            [
                _gcp_workload(),
                _gcp_database(),
                _gcp_database(
                    address="google_firestore_database.archive",
                    name="archive",
                ),
                foreign_database,
                _gcp_custom_role([_GCP_DELETE_DATABASE]),
                _as_resource(gcp_project_iam_member(role=_gcp_role_name())),
            ]
        )
        workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = gcp_facts(workload).cloud_run_firestore_access_paths
        self.assertEqual(
            [
                path["firestore_database_address"]
                for path in paths
                if _GCP_DELETE_DATABASE in path["matched_permissions"]
            ],
            [
                "google_firestore_database.archive",
                GCP_DATABASE_ADDRESS,
            ],
        )
        self.assertNotIn(
            "google_firestore_database.foreign",
            {path["firestore_database_address"] for path in paths},
        )

    def test_gcp_conditions_custom_role_lifecycle_and_unresolved_identity_fail_closed(
        self,
    ) -> None:
        runtime_condition = {
            "title": "temporary",
            "expression": ("request.time < timestamp(2027-01-01T00:00:00Z)"),
        }
        conditional_inventory = GcpNormalizer().normalize(
            _gcp_resources(
                [_GCP_DELETE_DATABASE],
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
                for uncertainty in (conditional_facts.cloud_run_firestore_access_path_uncertainties)
            )
        )

        lifecycle_cases = (
            (
                "disabled",
                _gcp_custom_role(
                    [_GCP_DELETE_DATABASE],
                    stage="DISABLED",
                ),
            ),
            (
                "deleted",
                _gcp_custom_role(
                    [_GCP_DELETE_DATABASE],
                    deleted=True,
                ),
            ),
            (
                "unknown permissions",
                _gcp_custom_role(
                    [_GCP_DELETE_DATABASE],
                    unknown_permissions=True,
                ),
            ),
            (
                "unknown deletion state",
                _gcp_custom_role(
                    [_GCP_DELETE_DATABASE],
                    deleted=None,
                    unknown_deleted=True,
                ),
            ),
        )
        for case, role in lifecycle_cases:
            with self.subTest(case=case):
                inventory = GcpNormalizer().normalize(
                    _gcp_resources(
                        [_GCP_DELETE_DATABASE],
                        role=role,
                    )
                )
                workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
                assert workload is not None
                facts = gcp_facts(workload)
                self.assertEqual(
                    facts.cloud_run_firestore_access_paths,
                    [],
                )
                self.assertTrue(facts.cloud_run_firestore_access_path_uncertainties)

        unresolved_workload = _gcp_workload()
        unresolved_workload.values["template"] = [{}]
        identity_inventory = GcpNormalizer().normalize(
            [
                unresolved_workload,
                _gcp_database(),
                _gcp_custom_role([_GCP_DELETE_DATABASE]),
                _as_resource(gcp_project_iam_member(role=_gcp_role_name())),
            ]
        )
        identity_workload = identity_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert identity_workload is not None
        identity_facts = gcp_facts(identity_workload)
        self.assertEqual(
            identity_facts.cloud_run_firestore_access_paths,
            [],
        )
        self.assertTrue(
            any(
                "service account is unresolved" in uncertainty
                for uncertainty in (identity_facts.cloud_run_firestore_access_path_uncertainties)
            )
        )

    def test_gcp_competing_iam_manager_inputs_remain_distinguishable(
        self,
    ) -> None:
        role_name = _gcp_role_name()
        member = gcp_project_iam_member(
            role=role_name,
            name="topology_member",
        )
        assert isinstance(member, TerraformResource)
        binding = _gcp_project_binding(
            role=role_name,
            members=["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
        )
        inventory = GcpNormalizer().normalize(
            [
                _gcp_workload(),
                _gcp_database(),
                _gcp_custom_role([_GCP_DELETE_DATABASE]),
                member,
                binding,
            ]
        )
        normalized_member = inventory.get_by_address(member.address)
        normalized_binding = inventory.get_by_address(binding.address)
        assert normalized_member is not None
        assert normalized_binding is not None
        self.assertEqual(
            normalized_member.resource_type,
            GcpResourceType.PROJECT_IAM_MEMBER,
        )
        self.assertEqual(
            normalized_binding.resource_type,
            GcpResourceType.PROJECT_IAM_BINDING,
        )
        self.assertEqual(
            iam_bindings(normalized_member)[0]["role"],
            role_name,
        )
        self.assertEqual(
            iam_bindings(normalized_binding)[0]["role"],
            role_name,
        )
        self.assertIn(
            GCP_SERVICE_ACCOUNT_MEMBER,
            iam_bindings(normalized_member)[0]["members"],
        )
        self.assertNotIn(
            GCP_SERVICE_ACCOUNT_MEMBER,
            iam_bindings(normalized_binding)[0]["members"],
        )

    def test_gcp_delete_protection_pitr_and_terraform_deletion_policy_are_separate(
        self,
    ) -> None:
        cases = (
            (
                "protected-with-pitr",
                "DELETE_PROTECTION_ENABLED",
                "POINT_IN_TIME_RECOVERY_ENABLED",
                ("enabled", True, "enabled", True),
            ),
            (
                "unprotected-without-pitr",
                "DELETE_PROTECTION_DISABLED",
                "POINT_IN_TIME_RECOVERY_DISABLED",
                ("disabled", False, "disabled", False),
            ),
            (
                "not-configured",
                None,
                None,
                ("not_configured", None, "not_configured", None),
            ),
        )
        for (
            case,
            delete_protection,
            pitr,
            expected,
        ) in cases:
            with self.subTest(case=case):
                source = _gcp_database(
                    delete_protection_state=delete_protection,
                    pitr_enablement=pitr,
                )
                source.values["deletion_policy"] = "DELETE"
                inventory = GcpNormalizer().normalize([source])
                database = inventory.get_by_address(GCP_DATABASE_ADDRESS)
                assert database is not None
                facts = gcp_facts(database)
                self.assertEqual(
                    (
                        facts.firestore_delete_protection_enablement,
                        facts.firestore_delete_protection_enabled,
                        facts.firestore_pitr_state,
                        facts.firestore_pitr_enabled,
                    ),
                    expected,
                )
                self.assertEqual(
                    facts.firestore_terraform_deletion_policy,
                    "DELETE",
                )
                self.assertEqual(
                    facts.firestore_terraform_deletion_policy_state,
                    "configured",
                )

        unknown = _gcp_database()
        unknown.unknown_values.update(
            {
                "delete_protection_state": True,
                "point_in_time_recovery_enablement": True,
                "deletion_policy": True,
            }
        )
        unknown_inventory = GcpNormalizer().normalize([unknown])
        unknown_database = unknown_inventory.get_by_address(GCP_DATABASE_ADDRESS)
        assert unknown_database is not None
        unknown_facts = gcp_facts(unknown_database)
        self.assertEqual(
            unknown_facts.firestore_delete_protection_enablement,
            "unknown",
        )
        self.assertIsNone(unknown_facts.firestore_delete_protection_enabled)
        self.assertEqual(unknown_facts.firestore_pitr_state, "unknown")
        self.assertEqual(
            unknown_facts.firestore_terraform_deletion_policy_state,
            "unknown",
        )

    def test_gcp_private_topology_authority_survives_without_public_findings(
        self,
    ) -> None:
        resources = _gcp_resources(
            [_GCP_DELETE_DATABASE],
            public=False,
        )
        inventory = GcpNormalizer().normalize(resources)
        workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert workload is not None
        self.assertEqual(
            gcp_facts(workload).cloud_run_firestore_access_paths[0]["matched_permissions"],
            [_GCP_DELETE_DATABASE],
        )
        self.assertEqual(
            _evaluate(
                GcpNormalizer(),
                resources,
                frozenset(
                    {
                        _GCP_MUTATION_RULE,
                        _GCP_ENTITY_DISRUPTION_RULE,
                    }
                ),
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest
from typing import Any

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
    _SERVICE_ACCOUNT_EMAIL as GCP_SERVICE_ACCOUNT_EMAIL,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _cloud_run as gcp_cloud_run,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _database as gcp_database,
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
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer

_MUTATION_RULE_IDS = frozenset(
    {
        "aws-public-ecs-dynamodb-mutation-access",
        "gcp-public-cloud-run-firestore-mutation-access",
        "azure-public-app-service-cosmosdb-mutation-access",
    }
)


def _evaluate(
    normalizer: ProviderNormalizer,
    resources: list[Any],
) -> list[Finding]:
    inventory = normalizer.normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=_MUTATION_RULE_IDS),
    )


def _aws_resources(
    *,
    public: bool = True,
    runtime_identity: bool = True,
    mutation_authority: bool = True,
    modeled_target: bool = True,
) -> list[TerraformResource]:
    resources = [*aws_public_edge(internal=not public)]
    if modeled_target:
        resources.append(aws_table())
    resources.extend(
        [
            aws_role(
                "orders_task",
                AWS_TASK_ROLE_ARN,
                [
                    aws_statement(
                        "Allow",
                        ("dynamodb:PutItem" if mutation_authority else "dynamodb:GetItem"),
                        AWS_TABLE_ARN,
                    )
                ],
            ),
            aws_task_definition(
                task_role_arn=(AWS_TASK_ROLE_ARN if runtime_identity else None),
                execution_role_arn=None,
            ),
            aws_service(),
        ]
    )
    return resources


def _gcp_workload(
    *,
    public: bool,
    runtime_identity: bool,
) -> TerraformResource:
    workload = gcp_cloud_run(service_account=(GCP_SERVICE_ACCOUNT_EMAIL if runtime_identity else None))
    assert isinstance(workload, TerraformResource)
    workload.values["ingress"] = "INGRESS_TRAFFIC_ALL" if public else "INGRESS_TRAFFIC_INTERNAL_ONLY"
    return workload


def _gcp_resources(
    *,
    public: bool = True,
    runtime_identity: bool = True,
    mutation_authority: bool = True,
    modeled_target: bool = True,
) -> list[Any]:
    resources: list[Any] = [
        _gcp_workload(public=public, runtime_identity=runtime_identity),
        gcp_public_invoker(),
    ]
    if modeled_target:
        resources.append(gcp_database())
    resources.append(
        gcp_project_iam_member(role=("roles/datastore.user" if mutation_authority else "roles/datastore.viewer"))
    )
    return resources


def _azure_resources(
    *,
    target_kind: str = "account",
    public: bool = True,
    runtime_identity: bool = True,
    mutation_authority: bool = True,
    modeled_target: bool = True,
) -> list[TerraformResource]:
    resources: list[TerraformResource] = []
    if modeled_target:
        resources.append(azure_account())
        if target_kind in {"database", "container"}:
            resources.append(azure_database())
        if target_kind == "container":
            resources.append(azure_container())

    workload = azure_web_app(principal_id=(AZURE_SYSTEM_PRINCIPAL_ID if runtime_identity else None))
    workload.values["public_network_access_enabled"] = public
    resources.append(workload)

    scope = {
        "account": "/",
        "database": "/dbs/app",
        "container": "/dbs/app/colls/events",
    }[target_kind]
    resources.append(
        azure_native_assignment(scope=scope)
        if mutation_authority
        else azure_native_assignment(
            role_definition_id=AZURE_READER_ROLE_ID,
            scope=scope,
        )
    )
    return resources


class PublicWorkloadManagedNosqlMutationPathParityTests(unittest.TestCase):
    """Pins equivalent coverage outcomes while retaining provider-native models."""

    def test_complete_provider_native_paths_emit_tampering_findings(self) -> None:
        cases = (
            (
                "aws-table",
                AwsNormalizer(),
                _aws_resources(),
                {
                    "aws_ecs_service.orders",
                    "aws_iam_role.orders_task",
                    "aws_dynamodb_table.orders",
                },
            ),
            (
                "gcp-database",
                GcpNormalizer(),
                _gcp_resources(),
                {
                    "google_cloud_run_v2_service.orders",
                    "google_firestore_database.orders",
                    "google_project_iam_member.orders_firestore",
                },
            ),
            (
                "azure-account",
                AzureNormalizer(),
                _azure_resources(target_kind="account"),
                {
                    "azurerm_linux_web_app.orders",
                    "azurerm_cosmosdb_account.orders",
                    "azurerm_cosmosdb_sql_role_assignment.workload",
                },
            ),
            (
                "azure-database",
                AzureNormalizer(),
                _azure_resources(target_kind="database"),
                {
                    "azurerm_linux_web_app.orders",
                    "azurerm_cosmosdb_account.orders",
                    "azurerm_cosmosdb_sql_database.app",
                    "azurerm_cosmosdb_sql_role_assignment.workload",
                },
            ),
            (
                "azure-container",
                AzureNormalizer(),
                _azure_resources(target_kind="container"),
                {
                    "azurerm_linux_web_app.orders",
                    "azurerm_cosmosdb_account.orders",
                    "azurerm_cosmosdb_sql_database.app",
                    "azurerm_cosmosdb_sql_container.events",
                    "azurerm_cosmosdb_sql_role_assignment.workload",
                },
            ),
        )

        for case, normalizer, resources, native_resources in cases:
            with self.subTest(case=case):
                findings = _evaluate(normalizer, resources)

                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].category, StrideCategory.TAMPERING)
                self.assertLessEqual(
                    native_resources,
                    set(findings[0].affected_resources),
                )

    def test_each_coverage_prerequisite_is_required(self) -> None:
        cases = (
            ("aws-private", AwsNormalizer(), _aws_resources(public=False)),
            (
                "aws-no-runtime-identity",
                AwsNormalizer(),
                _aws_resources(runtime_identity=False),
            ),
            (
                "aws-read-only",
                AwsNormalizer(),
                _aws_resources(mutation_authority=False),
            ),
            (
                "aws-unmodeled-target",
                AwsNormalizer(),
                _aws_resources(modeled_target=False),
            ),
            ("gcp-private", GcpNormalizer(), _gcp_resources(public=False)),
            (
                "gcp-no-runtime-identity",
                GcpNormalizer(),
                _gcp_resources(runtime_identity=False),
            ),
            (
                "gcp-read-only",
                GcpNormalizer(),
                _gcp_resources(mutation_authority=False),
            ),
            (
                "gcp-unmodeled-target",
                GcpNormalizer(),
                _gcp_resources(modeled_target=False),
            ),
            ("azure-private", AzureNormalizer(), _azure_resources(public=False)),
            (
                "azure-no-runtime-identity",
                AzureNormalizer(),
                _azure_resources(runtime_identity=False),
            ),
            (
                "azure-read-only",
                AzureNormalizer(),
                _azure_resources(mutation_authority=False),
            ),
            (
                "azure-unmodeled-target",
                AzureNormalizer(),
                _azure_resources(modeled_target=False),
            ),
        )

        for case, normalizer, resources in cases:
            with self.subTest(case=case):
                self.assertEqual(_evaluate(normalizer, resources), [])


if __name__ == "__main__":
    unittest.main()

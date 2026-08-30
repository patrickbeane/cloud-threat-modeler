from __future__ import annotations

import json
import unittest
from collections.abc import Mapping, Sequence
from typing import Any, cast

from tests.providers.aws.test_aws_ecs_dynamodb_table_topology_destruction_paths import (
    _TABLE_ARN as AWS_TABLE_ARN,
)
from tests.providers.aws.test_aws_ecs_dynamodb_table_topology_destruction_paths import (
    _role as aws_role,
)
from tests.providers.aws.test_aws_ecs_dynamodb_table_topology_destruction_paths import (
    _statement as aws_statement,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_table_topology_disruption_rules import (
    _runtime_resources as aws_runtime_resources,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _ACCOUNT_ID as AZURE_ACCOUNT_ID,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _CUSTOM_ROLE_ID as AZURE_NATIVE_CUSTOM_ROLE_ID,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _custom_role as azure_native_role,
)
from tests.providers.azure.test_azure_app_service_cosmosdb_access_paths import (
    _native_assignment as azure_native_assignment,
)
from tests.providers.azure.test_azure_public_app_service_cosmosdb_topology_disruption_rules import (
    _resources as azure_topology_resources,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _DATABASE_ADDRESS as GCP_DATABASE_ADDRESS,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_access_paths import (
    _PROJECT as GCP_PROJECT,
)
from tests.providers.gcp.test_gcp_cloud_run_firestore_database_topology_destruction_paths import (
    _database_resource as gcp_database,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_database_topology_disruption_rules import (
    _resources as gcp_topology_resources,
)
from tests.providers.test_public_workload_structured_data_deletion_boundaries import (
    _AZURE_ITEM_CREATE,
    _AZURE_ITEM_DELETE,
)
from tests.providers.test_public_workload_structured_data_deletion_boundaries import (
    _azure_account as azure_account,
)
from tests.providers.test_public_workload_structured_data_deletion_boundaries import (
    _azure_resources as azure_native_resources,
)
from tests.providers.test_public_workload_structured_data_topology_destruction_boundaries import (
    _AZURE_DELETE_ACCOUNT,
    _AZURE_DELETE_CONTAINER,
    _AZURE_DELETE_DATABASE,
    _GCP_CREATE_ENTITY,
    _GCP_DELETE_DATABASE,
    _GCP_DELETE_ENTITY,
)
from tests.providers.test_public_workload_structured_data_topology_destruction_boundaries import (
    _aws_resources as aws_boundary_resources,
)
from tests.providers.test_public_workload_structured_data_topology_destruction_boundaries import (
    _azure_control_assignment as azure_control_assignment,
)
from tests.providers.test_public_workload_structured_data_topology_destruction_boundaries import (
    _gcp_resources as gcp_boundary_resources,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, ResourceInventory, StrideCategory, TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_TAMPERING_RULE = "aws-public-ecs-dynamodb-mutation-access"
AWS_ITEM_DISRUPTION_RULE = "aws-public-ecs-dynamodb-item-disruption"
AWS_TOPOLOGY_DISRUPTION_RULE = "aws-public-ecs-dynamodb-table-topology-disruption"

GCP_TAMPERING_RULE = "gcp-public-cloud-run-firestore-mutation-access"
GCP_ITEM_DISRUPTION_RULE = "gcp-public-cloud-run-firestore-entity-disruption"
GCP_TOPOLOGY_DISRUPTION_RULE = "gcp-public-cloud-run-firestore-database-topology-disruption"

AZURE_TAMPERING_RULE = "azure-public-app-service-cosmosdb-mutation-access"
AZURE_ITEM_DISRUPTION_RULE = "azure-public-app-service-cosmosdb-item-disruption"
AZURE_TOPOLOGY_DISRUPTION_RULE = "azure-public-app-service-cosmosdb-topology-disruption"

_RULE_IDS = frozenset(
    {
        AWS_TAMPERING_RULE,
        AWS_ITEM_DISRUPTION_RULE,
        AWS_TOPOLOGY_DISRUPTION_RULE,
        GCP_TAMPERING_RULE,
        GCP_ITEM_DISRUPTION_RULE,
        GCP_TOPOLOGY_DISRUPTION_RULE,
        AZURE_TAMPERING_RULE,
        AZURE_ITEM_DISRUPTION_RULE,
        AZURE_TOPOLOGY_DISRUPTION_RULE,
    }
)

_AWS_WORKLOAD_ADDRESS = "aws_ecs_service.orders"
_GCP_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_AZURE_WORKLOAD_ADDRESS = "azurerm_linux_web_app.orders"

_AWS_DELETE_TABLE = "dynamodb:DeleteTable"
_AWS_DELETE_ITEM = "dynamodb:DeleteItem"
_AWS_PUT_ITEM = "dynamodb:PutItem"
_GCP_IAM_ADDRESS = "google_project_iam_member.orders_firestore"
_AZURE_ROLE_ADDRESS = "azurerm_role_definition.cosmos_topology"

_AWS_TABLE_ADDRESS = "aws_dynamodb_table.orders"
_AZURE_ACCOUNT_ADDRESS = "azurerm_cosmosdb_account.orders"
_AZURE_DATABASE_ADDRESS = "azurerm_cosmosdb_sql_database.app"
_AZURE_CONTAINER_ADDRESS = "azurerm_cosmosdb_sql_container.events"


def _flatten(groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for group in groups for rule_id in group)


def _analyze(
    normalizer: ProviderNormalizer,
    resources: list[TerraformResource],
    *,
    engine: StrideRuleEngine | None = None,
) -> tuple[ResourceInventory, list[Finding]]:
    inventory = normalizer.normalize(resources)
    return inventory, _evaluate_inventory(inventory, engine=engine)


def _evaluate_inventory(
    inventory: ResourceInventory,
    *,
    engine: StrideRuleEngine | None = None,
) -> list[Finding]:
    return (engine or StrideRuleEngine()).evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=_RULE_IDS),
    )


def _evidence(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


def _finding_by_rule(findings: Sequence[Finding], rule_id: str) -> Finding:
    matches = [finding for finding in findings if finding.rule_id == rule_id]
    assert len(matches) == 1
    return matches[0]


def _blast_radius(finding: Finding) -> int:
    assert finding.severity_reasoning is not None
    return finding.severity_reasoning.blast_radius


def _topology_state(
    provider: str,
    inventory: ResourceInventory,
) -> tuple[list[Mapping[str, object]], list[str]]:
    if provider == "aws":
        workload = inventory.get_by_address(_AWS_WORKLOAD_ADDRESS)
        assert workload is not None
        facts = aws_facts(workload)
        return (
            [cast(Mapping[str, object], path) for path in facts.ecs_dynamodb_table_topology_destruction_paths],
            list(facts.ecs_dynamodb_table_topology_destruction_path_uncertainties),
        )
    if provider == "gcp":
        workload = inventory.get_by_address(_GCP_WORKLOAD_ADDRESS)
        assert workload is not None
        facts = gcp_facts(workload)
        return (
            [
                cast(Mapping[str, object], path)
                for path in facts.cloud_run_firestore_database_topology_destruction_paths
            ],
            list(facts.cloud_run_firestore_database_topology_destruction_path_uncertainties),
        )

    workload = inventory.get_by_address(_AZURE_WORKLOAD_ADDRESS)
    assert workload is not None
    facts = azure_facts(workload)
    return (
        [cast(Mapping[str, object], path) for path in facts.app_service_cosmosdb_topology_destruction_paths],
        list(facts.app_service_cosmosdb_topology_destruction_path_uncertainties),
    )


def _replace_topology_paths(
    provider: str,
    inventory: ResourceInventory,
    paths: Sequence[Mapping[str, object]],
) -> None:
    records = [dict(path) for path in paths]
    if provider == "aws":
        workload = inventory.get_by_address(_AWS_WORKLOAD_ADDRESS)
        assert workload is not None
        aws_facts(workload).set_ecs_dynamodb_table_topology_destruction_paths(cast(Any, records))
        return
    if provider == "gcp":
        workload = inventory.get_by_address(_GCP_WORKLOAD_ADDRESS)
        assert workload is not None
        gcp_facts(workload).set_cloud_run_firestore_database_topology_destruction_paths(cast(Any, records))
        return

    workload = inventory.get_by_address(_AZURE_WORKLOAD_ADDRESS)
    assert workload is not None
    azure_facts(workload).set_app_service_cosmosdb_topology_destruction_paths(cast(Any, records))


def _topology_fingerprint(
    provider: str,
    path: Mapping[str, object],
) -> tuple[object, ...]:
    if provider == "aws":
        identity = path.get("role_arn")
        target = path.get("table_address")
        sources = path.get("authorization_source_addresses")
    elif provider == "gcp":
        identity = path.get("service_account_email")
        target = path.get("firestore_database_address")
        sources = path.get("iam_source_addresses")
    else:
        identity = path.get("principal_id")
        target = path.get("cosmosdb_resource_address")
        sources = path.get("authorization_source_addresses")
    source_values = tuple(value for value in sources if isinstance(value, str)) if isinstance(sources, list) else ()
    return (
        provider,
        path.get("operation"),
        path.get("target_scope"),
        target,
        identity,
        source_values,
    )


def _aws_topology_resources(
    *,
    public: bool = True,
    actions: str | list[str] = _AWS_DELETE_TABLE,
    pitr: str = "enabled",
) -> list[TerraformResource]:
    resources = aws_runtime_resources(actions, pitr=pitr)
    if public:
        return resources
    return [resource for resource in resources if resource.resource_type != "aws_lb"]


def _gcp_topology_resources(
    *,
    public: bool = True,
    permissions: list[str] | None = None,
    unknown_pitr: bool = False,
) -> list[TerraformResource]:
    return gcp_topology_resources(
        public_ingress=public,
        role_permissions=permissions or [_GCP_DELETE_DATABASE],
        unknown_pitr=unknown_pitr,
    )


def _azure_topology_resources(
    *,
    public: bool = True,
    actions: list[str] | None = None,
    account: TerraformResource | None = None,
) -> list[TerraformResource]:
    return azure_topology_resources(
        public=public,
        account=account,
        actions=actions
        or [
            _AZURE_DELETE_ACCOUNT,
            _AZURE_DELETE_DATABASE,
            _AZURE_DELETE_CONTAINER,
        ],
    )


def _azure_native_and_topology_resources(
    *,
    data_actions: list[str],
    control_actions: list[str],
) -> list[TerraformResource]:
    return [
        *_azure_topology_resources(actions=control_actions),
        azure_native_role(
            data_actions=data_actions,
            assignable_scopes=[f"{AZURE_ACCOUNT_ID}/dbs/app/colls/events"],
        ),
        azure_native_assignment(
            role_definition_id=AZURE_NATIVE_CUSTOM_ROLE_ID,
            scope="/dbs/app/colls/events",
        ),
    ]


def _aws_archive_table() -> TerraformResource:
    arn = "arn:aws:dynamodb:us-east-1:111122223333:table/archive"
    return TerraformResource(
        address="aws_dynamodb_table.archive",
        mode="managed",
        resource_type="aws_dynamodb_table",
        name="archive",
        provider_name="registry.terraform.io/hashicorp/aws",
        values={
            "id": "archive",
            "name": "archive",
            "arn": arn,
            "point_in_time_recovery": [
                {
                    "enabled": True,
                    "recovery_period_in_days": 14,
                }
            ],
        },
        unknown_values={},
    )


def _broad_scope_cases() -> tuple[
    tuple[
        str,
        ProviderNormalizer,
        list[TerraformResource],
        str,
        set[str],
        str,
        int,
    ],
    ...,
]:
    archive_arn = "arn:aws:dynamodb:us-east-1:111122223333:table/archive"
    aws_resources = [
        resource for resource in _aws_topology_resources() if resource.address != "aws_iam_role.orders_task"
    ]
    aws_resources.extend(
        [
            _aws_archive_table(),
            aws_role(
                [
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_TABLE,
                        [AWS_TABLE_ARN, archive_arn],
                    )
                ]
            ),
        ]
    )

    gcp_resources = _gcp_topology_resources()
    gcp_resources.append(
        gcp_database(
            address="google_firestore_database.audit",
            name="audit",
            project=GCP_PROJECT,
        )
    )

    return (
        (
            "aws",
            AwsNormalizer(),
            aws_resources,
            AWS_TOPOLOGY_DISRUPTION_RULE,
            {_AWS_TABLE_ADDRESS, "aws_dynamodb_table.archive"},
            "dynamodb_table_topology_destruction_paths",
            2,
        ),
        (
            "gcp",
            GcpNormalizer(),
            gcp_resources,
            GCP_TOPOLOGY_DISRUPTION_RULE,
            {GCP_DATABASE_ADDRESS, "google_firestore_database.audit"},
            "firestore_database_topology_destruction_paths",
            2,
        ),
        (
            "azure",
            AzureNormalizer(),
            _azure_topology_resources(),
            AZURE_TOPOLOGY_DISRUPTION_RULE,
            {
                _AZURE_ACCOUNT_ADDRESS,
                _AZURE_DATABASE_ADDRESS,
                _AZURE_CONTAINER_ADDRESS,
            },
            "cosmosdb_topology_destruction_paths",
            2,
        ),
    )


def _finding_payload(findings: Sequence[Finding]) -> list[dict[str, object]]:
    return [
        {
            "rule_id": finding.rule_id,
            "category": finding.category.value,
            "affected_resources": finding.affected_resources,
            "rationale": finding.rationale,
            "evidence": _evidence(finding),
        }
        for finding in findings
    ]


class PublicWorkloadStructuredDataTopologyDisruptionParityTests(unittest.TestCase):
    """Pin shared topology DoS outcomes without flattening native recovery."""

    def test_provider_local_topology_rules_are_registered(self) -> None:
        self.assertIn(AWS_TOPOLOGY_DISRUPTION_RULE, _flatten(AWS_RULE_GROUP_IDS))
        self.assertIn(GCP_TOPOLOGY_DISRUPTION_RULE, _flatten(GCP_RULE_GROUP_IDS))
        self.assertIn(AZURE_TOPOLOGY_DISRUPTION_RULE, _flatten(AZURE_RULE_GROUP_IDS))

    def test_topology_deletion_emits_only_provider_local_denial_of_service(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_topology_resources(),
                AWS_TOPOLOGY_DISRUPTION_RULE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_topology_resources(),
                GCP_TOPOLOGY_DISRUPTION_RULE,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_topology_resources(actions=[_AZURE_DELETE_CONTAINER]),
                AZURE_TOPOLOGY_DISRUPTION_RULE,
            ),
        )

        for provider, normalizer, resources, rule_id in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, _uncertainties = _topology_state(provider, inventory)

                self.assertEqual(len(paths), 1)
                self.assertEqual([finding.rule_id for finding in findings], [rule_id])
                self.assertEqual(findings[0].category, StrideCategory.DENIAL_OF_SERVICE)
                self.assertEqual(
                    len(findings[0].affected_resources),
                    len(set(findings[0].affected_resources)),
                )

    def test_item_write_and_delete_do_not_become_topology_disruption(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_topology_resources(actions=[_AWS_PUT_ITEM, _AWS_DELETE_ITEM]),
                {AWS_TAMPERING_RULE, AWS_ITEM_DISRUPTION_RULE},
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_topology_resources(permissions=[_GCP_CREATE_ENTITY, _GCP_DELETE_ENTITY]),
                {GCP_TAMPERING_RULE, GCP_ITEM_DISRUPTION_RULE},
            ),
            (
                "azure",
                AzureNormalizer(),
                azure_native_resources(
                    [_AZURE_ITEM_CREATE, _AZURE_ITEM_DELETE],
                    target_kind="container",
                ),
                {AZURE_TAMPERING_RULE, AZURE_ITEM_DISRUPTION_RULE},
            ),
        )
        topology_rules = {
            "aws": AWS_TOPOLOGY_DISRUPTION_RULE,
            "gcp": GCP_TOPOLOGY_DISRUPTION_RULE,
            "azure": AZURE_TOPOLOGY_DISRUPTION_RULE,
        }

        for provider, normalizer, resources, expected_rules in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, _uncertainties = _topology_state(provider, inventory)
                rule_ids = {finding.rule_id for finding in findings}

                self.assertEqual(paths, [])
                self.assertEqual(rule_ids, expected_rules)
                self.assertNotIn(topology_rules[provider], rule_ids)
                self.assertEqual(
                    {finding.category for finding in findings},
                    {StrideCategory.TAMPERING, StrideCategory.DENIAL_OF_SERVICE},
                )

    def test_write_and_topology_delete_emit_separate_findings(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_topology_resources(actions=[_AWS_PUT_ITEM, _AWS_DELETE_TABLE]),
                AWS_TAMPERING_RULE,
                AWS_TOPOLOGY_DISRUPTION_RULE,
                "dynamodb_mutation_paths",
                "dynamodb_table_topology_destruction_paths",
                _AWS_DELETE_TABLE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_topology_resources(permissions=[_GCP_CREATE_ENTITY, _GCP_DELETE_DATABASE]),
                GCP_TAMPERING_RULE,
                GCP_TOPOLOGY_DISRUPTION_RULE,
                "firestore_mutation_paths",
                "firestore_database_topology_destruction_paths",
                _GCP_DELETE_DATABASE,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_native_and_topology_resources(
                    data_actions=[_AZURE_ITEM_CREATE],
                    control_actions=[_AZURE_DELETE_CONTAINER],
                ),
                AZURE_TAMPERING_RULE,
                AZURE_TOPOLOGY_DISRUPTION_RULE,
                "cosmosdb_mutation_paths",
                "cosmosdb_topology_destruction_paths",
                _AZURE_DELETE_CONTAINER,
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            mutation_rule,
            topology_rule,
            mutation_key,
            topology_key,
            topology_operation,
        ) in cases:
            with self.subTest(provider=provider):
                _inventory, findings = _analyze(normalizer, resources)
                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    {mutation_rule, topology_rule},
                )
                mutation = _finding_by_rule(findings, mutation_rule)
                topology = _finding_by_rule(findings, topology_rule)
                mutation_payload = json.dumps(
                    _evidence(mutation)[mutation_key],
                    sort_keys=True,
                )
                topology_payload = json.dumps(
                    _evidence(topology)[topology_key],
                    sort_keys=True,
                )

                self.assertNotIn(topology_operation, mutation_payload)
                self.assertIn(topology_operation, topology_payload)
                self.assertEqual(mutation.category, StrideCategory.TAMPERING)
                self.assertEqual(topology.category, StrideCategory.DENIAL_OF_SERVICE)

    def test_item_and_topology_delete_emit_distinct_dos_findings(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_topology_resources(actions=[_AWS_DELETE_ITEM, _AWS_DELETE_TABLE]),
                AWS_ITEM_DISRUPTION_RULE,
                AWS_TOPOLOGY_DISRUPTION_RULE,
                "dynamodb_item_deletion_paths",
                "dynamodb_table_topology_destruction_paths",
                _AWS_DELETE_TABLE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_topology_resources(permissions=[_GCP_DELETE_ENTITY, _GCP_DELETE_DATABASE]),
                GCP_ITEM_DISRUPTION_RULE,
                GCP_TOPOLOGY_DISRUPTION_RULE,
                "firestore_entity_deletion_paths",
                "firestore_database_topology_destruction_paths",
                _GCP_DELETE_DATABASE,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_native_and_topology_resources(
                    data_actions=[_AZURE_ITEM_DELETE],
                    control_actions=[_AZURE_DELETE_CONTAINER],
                ),
                AZURE_ITEM_DISRUPTION_RULE,
                AZURE_TOPOLOGY_DISRUPTION_RULE,
                "cosmosdb_item_deletion_paths",
                "cosmosdb_topology_destruction_paths",
                _AZURE_DELETE_CONTAINER,
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            item_rule,
            topology_rule,
            item_key,
            topology_key,
            topology_operation,
        ) in cases:
            with self.subTest(provider=provider):
                _inventory, findings = _analyze(normalizer, resources)
                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    {item_rule, topology_rule},
                )
                item = _finding_by_rule(findings, item_rule)
                topology = _finding_by_rule(findings, topology_rule)
                item_payload = json.dumps(_evidence(item)[item_key], sort_keys=True)
                topology_payload = json.dumps(
                    _evidence(topology)[topology_key],
                    sort_keys=True,
                )

                self.assertNotIn(topology_operation, item_payload)
                self.assertIn(topology_operation, topology_payload)
                self.assertEqual(item.category, StrideCategory.DENIAL_OF_SERVICE)
                self.assertEqual(topology.category, StrideCategory.DENIAL_OF_SERVICE)

    def test_native_target_constraints_and_recovery_remain_provider_specific(self) -> None:
        aws_inventory, aws_findings = _analyze(
            AwsNormalizer(),
            _aws_topology_resources(),
        )
        aws_paths, _ = _topology_state("aws", aws_inventory)
        aws_path = aws_paths[0]
        self.assertEqual(aws_path["operation"], _AWS_DELETE_TABLE)
        self.assertEqual(aws_path["target_scope"], "exact_dynamodb_table")
        self.assertEqual(
            aws_path["target_model_evidence_addresses"],
            [_AWS_TABLE_ADDRESS],
        )
        self.assertEqual(aws_path["account_relationship"], "same_account")
        aws_constraints = cast(
            Mapping[str, object],
            aws_path["deletion_constraint_evidence"],
        )
        self.assertEqual(aws_constraints["deletion_protection_state"], "not_configured")
        aws_recovery = cast(Mapping[str, object], aws_path["recovery_evidence"])
        self.assertEqual(aws_recovery["pitr_state"], "enabled")
        self.assertEqual(aws_recovery["restore_target_kind"], "new_table")

        gcp_inventory, gcp_findings = _analyze(
            GcpNormalizer(),
            _gcp_topology_resources(),
        )
        gcp_paths, _ = _topology_state("gcp", gcp_inventory)
        gcp_path = gcp_paths[0]
        self.assertEqual(gcp_path["operation"], _GCP_DELETE_DATABASE)
        self.assertEqual(gcp_path["target_scope"], "exact_firestore_database")
        self.assertEqual(
            gcp_path["target_model_evidence_addresses"],
            [GCP_DATABASE_ADDRESS],
        )
        self.assertEqual(gcp_path["scope_type"], "project")
        gcp_constraints = cast(
            Mapping[str, object],
            gcp_path["deletion_constraint_evidence"],
        )
        self.assertEqual(
            gcp_constraints["delete_protection_enablement"],
            "not_configured",
        )
        gcp_recovery = cast(Mapping[str, object], gcp_path["recovery_evidence"])
        self.assertEqual(gcp_recovery["pitr_state"], "not_configured")
        self.assertEqual(
            gcp_recovery["historical_version_retention_state"],
            "native_approximately_one_hour",
        )

        azure_inventory, azure_findings = _analyze(
            AzureNormalizer(),
            _azure_topology_resources(actions=[_AZURE_DELETE_CONTAINER]),
        )
        azure_paths, _ = _topology_state("azure", azure_inventory)
        azure_path = azure_paths[0]
        self.assertEqual(azure_path["operation"], _AZURE_DELETE_CONTAINER)
        self.assertEqual(
            azure_path["target_scope"],
            "exact_cosmosdb_sql_container",
        )
        self.assertEqual(
            azure_path["target_model_evidence_addresses"],
            [
                _AZURE_ACCOUNT_ADDRESS,
                _AZURE_DATABASE_ADDRESS,
                _AZURE_CONTAINER_ADDRESS,
            ],
        )
        azure_lock = cast(
            Mapping[str, object],
            azure_path["management_lock_evidence"],
        )
        self.assertEqual(azure_lock["modeled_management_lock_state"], "not_observed")
        azure_recovery = cast(
            Mapping[str, object],
            azure_path["recovery_evidence"],
        )
        self.assertEqual(
            azure_recovery["backup_posture_state"],
            "provider_default_periodic",
        )

        for provider, paths in (
            ("aws", aws_paths),
            ("gcp", gcp_paths),
            ("azure", azure_paths),
        ):
            fingerprints = [_topology_fingerprint(provider, path) for path in paths]
            self.assertEqual(len(fingerprints), len(set(fingerprints)))

        for finding, rule_id in (
            (aws_findings[0], AWS_TOPOLOGY_DISRUPTION_RULE),
            (gcp_findings[0], GCP_TOPOLOGY_DISRUPTION_RULE),
            (azure_findings[0], AZURE_TOPOLOGY_DISRUPTION_RULE),
        ):
            self.assertEqual(finding.rule_id, rule_id)

    def test_private_workloads_keep_topology_paths_without_public_findings(self) -> None:
        cases = (
            ("aws", AwsNormalizer(), _aws_topology_resources(public=False)),
            ("gcp", GcpNormalizer(), _gcp_topology_resources(public=False)),
            (
                "azure",
                AzureNormalizer(),
                _azure_topology_resources(
                    public=False,
                    actions=[_AZURE_DELETE_CONTAINER],
                ),
            ),
        )

        for provider, normalizer, resources in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, _uncertainties = _topology_state(provider, inventory)

                self.assertTrue(paths)
                self.assertEqual(findings, [])

    def test_conditional_or_unresolved_authority_fails_closed(self) -> None:
        azure_resources = _azure_topology_resources(actions=[_AZURE_DELETE_CONTAINER])
        azure_resources[-1] = azure_control_assignment(
            unknown_values={"condition_version": True},
        )
        cases = (
            (
                "aws-condition",
                "aws",
                AwsNormalizer(),
                aws_boundary_resources(
                    _AWS_DELETE_TABLE,
                    statements=[
                        aws_statement(
                            "Allow",
                            _AWS_DELETE_TABLE,
                            AWS_TABLE_ARN,
                            condition={
                                "StringEquals": {
                                    "aws:RequestedRegion": "us-east-1",
                                }
                            },
                        )
                    ],
                ),
            ),
            (
                "gcp-condition",
                "gcp",
                GcpNormalizer(),
                gcp_boundary_resources(
                    [_GCP_DELETE_DATABASE],
                    condition={
                        "title": "runtime-window",
                        "expression": ('request.time < timestamp("2030-01-01T00:00:00Z")'),
                    },
                ),
            ),
            (
                "azure-condition-version",
                "azure",
                AzureNormalizer(),
                azure_resources,
            ),
        )
        topology_rules = {
            "aws": AWS_TOPOLOGY_DISRUPTION_RULE,
            "gcp": GCP_TOPOLOGY_DISRUPTION_RULE,
            "azure": AZURE_TOPOLOGY_DISRUPTION_RULE,
        }

        for label, provider, normalizer, resources in cases:
            with self.subTest(case=label):
                inventory, findings = _analyze(normalizer, resources)
                paths, uncertainties = _topology_state(provider, inventory)

                self.assertEqual(paths, [])
                self.assertTrue(uncertainties)
                self.assertNotIn(
                    topology_rules[provider],
                    {finding.rule_id for finding in findings},
                )

    def test_recovery_uncertainty_qualifies_but_does_not_suppress_authority(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_topology_resources(pitr="unknown"),
                AWS_TOPOLOGY_DISRUPTION_RULE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_topology_resources(unknown_pitr=True),
                GCP_TOPOLOGY_DISRUPTION_RULE,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_topology_resources(
                    account=azure_account(unknown_backup=True),
                    actions=[_AZURE_DELETE_ACCOUNT],
                ),
                AZURE_TOPOLOGY_DISRUPTION_RULE,
            ),
        )

        for provider, normalizer, resources, rule_id in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, _uncertainties = _topology_state(provider, inventory)
                finding = _finding_by_rule(findings, rule_id)

                self.assertEqual(len(paths), 1)
                self.assertTrue(paths[0]["posture_uncertainties"])
                payload = json.dumps(
                    {
                        "paths": paths,
                        "finding": _finding_payload([finding]),
                    },
                    sort_keys=True,
                )
                self.assertNotIn('"successful_deletion_observed": true', payload)
                self.assertNotIn('"restoration_observed": true', payload)
                self.assertNotIn("successful restoration observed", payload.casefold())
                self.assertNotIn("permanent deletion", payload.casefold())

    def test_broad_scopes_fan_out_only_to_exact_modeled_targets(self) -> None:
        for (
            provider,
            normalizer,
            resources,
            rule_id,
            targets,
            evidence_key,
            expected_blast_radius,
        ) in _broad_scope_cases():
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, _uncertainties = _topology_state(provider, inventory)
                finding = _finding_by_rule(findings, rule_id)
                path_targets = {
                    str(
                        path.get("table_address")
                        or path.get("firestore_database_address")
                        or path.get("cosmosdb_resource_address")
                    )
                    for path in paths
                }

                self.assertEqual(path_targets, targets)
                self.assertEqual(len(paths), len(targets))
                self.assertEqual(
                    len(_evidence(finding)[evidence_key]),
                    len(targets),
                )
                self.assertEqual(
                    _blast_radius(finding),
                    expected_blast_radius,
                )
                for target in targets:
                    self.assertEqual(finding.affected_resources.count(target), 1)
                fingerprints = [_topology_fingerprint(provider, path) for path in paths]
                self.assertEqual(len(fingerprints), len(set(fingerprints)))

    def test_duplicate_cached_paths_do_not_duplicate_targets_or_evidence(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_topology_resources(),
                AWS_TOPOLOGY_DISRUPTION_RULE,
                _AWS_TABLE_ADDRESS,
                "dynamodb_table_topology_destruction_paths",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_topology_resources(),
                GCP_TOPOLOGY_DISRUPTION_RULE,
                GCP_DATABASE_ADDRESS,
                "firestore_database_topology_destruction_paths",
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_topology_resources(actions=[_AZURE_DELETE_CONTAINER]),
                AZURE_TOPOLOGY_DISRUPTION_RULE,
                _AZURE_CONTAINER_ADDRESS,
                "cosmosdb_topology_destruction_paths",
            ),
        )

        for provider, normalizer, resources, rule_id, target, evidence_key in cases:
            with self.subTest(provider=provider):
                inventory, initial_findings = _analyze(normalizer, resources)
                initial_finding = _finding_by_rule(initial_findings, rule_id)
                initial_blast_radius = _blast_radius(initial_finding)
                paths, _uncertainties = _topology_state(provider, inventory)
                self.assertEqual(len(paths), 1)
                _replace_topology_paths(
                    provider,
                    inventory,
                    [*paths, dict(paths[0])],
                )

                finding = _finding_by_rule(
                    _evaluate_inventory(inventory),
                    rule_id,
                )
                self.assertEqual(finding.affected_resources.count(target), 1)
                self.assertEqual(len(_evidence(finding)[evidence_key]), 1)
                self.assertEqual(
                    _blast_radius(finding),
                    initial_blast_radius,
                )

    def test_stale_projected_targets_are_rejected_for_every_provider(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_topology_resources(),
                AWS_TOPOLOGY_DISRUPTION_RULE,
                "table_address",
                "aws_dynamodb_table.stale",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_topology_resources(),
                GCP_TOPOLOGY_DISRUPTION_RULE,
                "firestore_database_address",
                "google_firestore_database.stale",
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_topology_resources(actions=[_AZURE_DELETE_CONTAINER]),
                AZURE_TOPOLOGY_DISRUPTION_RULE,
                "cosmosdb_resource_address",
                "azurerm_cosmosdb_sql_container.stale",
            ),
        )

        for provider, normalizer, resources, rule_id, field, stale_value in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                self.assertIsNotNone(_finding_by_rule(findings, rule_id))
                paths, _uncertainties = _topology_state(provider, inventory)
                stale_paths = [dict(path) for path in paths]
                stale_paths[0][field] = stale_value
                _replace_topology_paths(provider, inventory, stale_paths)

                self.assertNotIn(
                    rule_id,
                    {finding.rule_id for finding in _evaluate_inventory(inventory)},
                )

    def test_stale_authority_is_rejected_for_every_provider(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_topology_resources(),
                AWS_TOPOLOGY_DISRUPTION_RULE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_topology_resources(),
                GCP_TOPOLOGY_DISRUPTION_RULE,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_topology_resources(actions=[_AZURE_DELETE_CONTAINER]),
                AZURE_TOPOLOGY_DISRUPTION_RULE,
            ),
        )

        for provider, normalizer, resources, rule_id in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                self.assertIsNotNone(_finding_by_rule(findings, rule_id))
                cached_paths, _uncertainties = _topology_state(
                    provider,
                    inventory,
                )
                self.assertEqual(len(cached_paths), 1)

                if provider == "aws":
                    role = inventory.get_by_address("aws_iam_role.orders_task")
                    assert role is not None
                    role.policy_statements = ()
                elif provider == "gcp":
                    source = inventory.get_by_address(_GCP_IAM_ADDRESS)
                    assert source is not None
                    gcp_facts(source).set(GcpResourceMetadata.IAM_BINDINGS, [])
                    gcp_facts(source).set(GcpResourceMetadata.IAM_ROLE, None)
                    gcp_facts(source).set(GcpResourceMetadata.IAM_MEMBER, None)
                else:
                    role = inventory.get_by_address(_AZURE_ROLE_ADDRESS)
                    assert role is not None
                    azure_facts(role).set(
                        AzureResourceMetadata.ROLE_DEFINITION_ACTIONS,
                        [],
                    )

                retained_paths, _uncertainties = _topology_state(
                    provider,
                    inventory,
                )
                self.assertEqual(retained_paths, cached_paths)
                self.assertNotIn(
                    rule_id,
                    {finding.rule_id for finding in _evaluate_inventory(inventory)},
                )

    def test_recovery_drift_refreshes_evidence_without_losing_authority(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_topology_resources(pitr="unknown"),
                AWS_TOPOLOGY_DISRUPTION_RULE,
                "table_deletion_recovery_evidence",
                "pitr_state=unknown",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_topology_resources(unknown_pitr=True),
                GCP_TOPOLOGY_DISRUPTION_RULE,
                "firestore_database_recovery_evidence",
                "pitr_state=unknown",
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_topology_resources(
                    account=azure_account(unknown_backup=True),
                    actions=[_AZURE_DELETE_ACCOUNT],
                ),
                AZURE_TOPOLOGY_DISRUPTION_RULE,
                "cosmosdb_backup_recovery_evidence",
                "backup_posture_state=unknown",
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            rule_id,
            evidence_key,
            stale_state,
        ) in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                initial = _evidence(_finding_by_rule(findings, rule_id))[evidence_key][0]
                self.assertIn("unknown", initial)

                if provider == "aws":
                    target = inventory.get_by_address(_AWS_TABLE_ADDRESS)
                    assert target is not None
                    facts = aws_facts(target)
                    facts.set(AwsResourceMetadata.DYNAMODB_PITR_STATE, "enabled")
                    facts.set(
                        AwsResourceMetadata.DYNAMODB_PITR_RECOVERY_PERIOD_DAYS,
                        14,
                    )
                    facts.set(
                        AwsResourceMetadata.DYNAMODB_POSTURE_UNCERTAINTIES,
                        [],
                    )
                    expected = "pitr_state=enabled"
                elif provider == "gcp":
                    target = inventory.get_by_address(GCP_DATABASE_ADDRESS)
                    assert target is not None
                    facts = gcp_facts(target)
                    facts.set(GcpResourceMetadata.FIRESTORE_PITR_STATE, "enabled")
                    facts.set(
                        GcpResourceMetadata.FIRESTORE_PITR_ENABLEMENT,
                        "POINT_IN_TIME_RECOVERY_ENABLED",
                    )
                    facts.set(
                        GcpResourceMetadata.FIRESTORE_POSTURE_UNCERTAINTIES,
                        [],
                    )
                    expected = "pitr_state=enabled"
                else:
                    target = inventory.get_by_address(_AZURE_ACCOUNT_ADDRESS)
                    assert target is not None
                    facts = azure_facts(target)
                    facts.set(
                        AzureResourceMetadata.COSMOSDB_BACKUP_TYPE,
                        "Continuous",
                    )
                    facts.set(
                        AzureResourceMetadata.COSMOSDB_BACKUP_CONFIGURATION_STATE,
                        "configured",
                    )
                    facts.set(
                        AzureResourceMetadata.COSMOSDB_POSTURE_UNCERTAINTIES,
                        [],
                    )
                    expected = "backup_posture_state=continuous"

                current = _finding_by_rule(
                    _evaluate_inventory(inventory),
                    rule_id,
                )
                current_evidence = _evidence(current)
                recovery = current_evidence[evidence_key][0]
                self.assertIn(expected, recovery)
                self.assertNotIn(stale_state, recovery)
                uncertainty_payload = " ".join(
                    value
                    for key, values in current_evidence.items()
                    if key.endswith("_uncertainties")
                    for value in values
                )
                self.assertNotIn("is unknown", uncertainty_payload)

    def test_reused_rule_engine_preserves_provider_isolation_and_payload_exclusion(
        self,
    ) -> None:
        aws_resources = _aws_topology_resources()
        aws_target = next(resource for resource in aws_resources if resource.address == _AWS_TABLE_ADDRESS)
        aws_target.values["tags"] = {"payload": "aws-structured-topology-payload-must-not-leak"}

        gcp_resources = _gcp_topology_resources()
        gcp_target = next(resource for resource in gcp_resources if resource.address == GCP_DATABASE_ADDRESS)
        gcp_target.values["labels"] = {"payload": "gcp-structured-topology-payload-must-not-leak"}

        azure_resources = _azure_topology_resources(actions=[_AZURE_DELETE_CONTAINER])
        azure_target = next(resource for resource in azure_resources if resource.address == _AZURE_CONTAINER_ADDRESS)
        azure_target.values["tags"] = {"payload": "azure-structured-topology-payload-must-not-leak"}

        cases = (
            (
                "aws",
                AwsNormalizer(),
                aws_resources,
                AWS_TOPOLOGY_DISRUPTION_RULE,
                (
                    "google_",
                    "azurerm_",
                    _GCP_DELETE_DATABASE,
                    _AZURE_DELETE_CONTAINER,
                ),
                "aws-structured-topology-payload-must-not-leak",
            ),
            (
                "gcp",
                GcpNormalizer(),
                gcp_resources,
                GCP_TOPOLOGY_DISRUPTION_RULE,
                (
                    "aws_",
                    "azurerm_",
                    _AWS_DELETE_TABLE,
                    _AZURE_DELETE_CONTAINER,
                ),
                "gcp-structured-topology-payload-must-not-leak",
            ),
            (
                "azure",
                AzureNormalizer(),
                azure_resources,
                AZURE_TOPOLOGY_DISRUPTION_RULE,
                (
                    "aws_",
                    "google_",
                    _AWS_DELETE_TABLE,
                    _GCP_DELETE_DATABASE,
                ),
                "azure-structured-topology-payload-must-not-leak",
            ),
            (
                "aws-second-pass",
                AwsNormalizer(),
                aws_resources,
                AWS_TOPOLOGY_DISRUPTION_RULE,
                (
                    "google_",
                    "azurerm_",
                    _GCP_DELETE_DATABASE,
                    _AZURE_DELETE_CONTAINER,
                ),
                "aws-structured-topology-payload-must-not-leak",
            ),
        )
        engine = StrideRuleEngine()

        for label, normalizer, resources, rule_id, foreign_values, sentinel in cases:
            with self.subTest(provider=label):
                provider = label.removesuffix("-second-pass")
                inventory, findings = _analyze(
                    normalizer,
                    resources,
                    engine=engine,
                )
                paths, _uncertainties = _topology_state(provider, inventory)

                self.assertTrue(paths)
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [rule_id],
                )
                payload = json.dumps(
                    {
                        "paths": paths,
                        "findings": _finding_payload(findings),
                    },
                    sort_keys=True,
                )
                self.assertNotIn(sentinel, payload)
                for foreign_value in foreign_values:
                    self.assertNotIn(foreign_value, payload)


if __name__ == "__main__":
    unittest.main()

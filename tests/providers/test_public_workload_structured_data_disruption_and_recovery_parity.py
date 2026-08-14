from __future__ import annotations

import json
import unittest
from collections.abc import Mapping, Sequence
from typing import cast

from tests.providers.test_public_workload_structured_data_deletion_boundaries import (
    _AZURE_ITEM_CREATE,
    _AZURE_ITEM_DELETE,
    _GCP_BULK_DELETE,
    _GCP_ENTITY_DELETE,
    AWS_TABLE_ARN,
    AWS_TASK_ROLE_ARN,
    AZURE_CUSTOM_ROLE_ID,
    GCP_WORKLOAD_ADDRESS,
    _aws_resources,
    _aws_table,
    _azure_account,
    _azure_resources,
    _azure_workload,
    _gcp_custom_role,
    _gcp_database,
    _gcp_resources,
    aws_role,
    aws_role_policy_attachment,
    aws_statement,
    azure_custom_role,
    azure_native_assignment,
    gcp_cloud_run,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import (
    Finding,
    ResourceInventory,
    StrideCategory,
    TerraformResource,
)
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_TAMPERING_RULE = "aws-public-ecs-dynamodb-mutation-access"
AWS_DISRUPTION_RULE = "aws-public-ecs-dynamodb-item-disruption"
GCP_TAMPERING_RULE = "gcp-public-cloud-run-firestore-mutation-access"
GCP_DISRUPTION_RULE = "gcp-public-cloud-run-firestore-entity-disruption"
AZURE_TAMPERING_RULE = "azure-public-app-service-cosmosdb-mutation-access"
AZURE_DISRUPTION_RULE = "azure-public-app-service-cosmosdb-item-disruption"

_RULE_IDS = frozenset(
    {
        AWS_TAMPERING_RULE,
        AWS_DISRUPTION_RULE,
        GCP_TAMPERING_RULE,
        GCP_DISRUPTION_RULE,
        AZURE_TAMPERING_RULE,
        AZURE_DISRUPTION_RULE,
    }
)

_AWS_WORKLOAD_ADDRESS = "aws_ecs_service.orders"
_AZURE_WORKLOAD_ADDRESS = "azurerm_linux_web_app.orders"


def _flatten(groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for group in groups for rule_id in group)


def _analyze(
    normalizer: ProviderNormalizer,
    resources: list[TerraformResource],
    *,
    engine: StrideRuleEngine | None = None,
) -> tuple[ResourceInventory, list[Finding]]:
    inventory = normalizer.normalize(resources)
    findings = (engine or StrideRuleEngine()).evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=_RULE_IDS),
    )
    return inventory, findings


def _evidence(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


def _finding_by_rule(
    findings: Sequence[Finding],
    rule_id: str,
) -> Finding:
    matches = [finding for finding in findings if finding.rule_id == rule_id]
    assert len(matches) == 1
    return matches[0]


def _path_state(
    provider: str,
    inventory: ResourceInventory,
) -> tuple[list[Mapping[str, object]], list[str]]:
    if provider == "aws":
        workload = inventory.get_by_address(_AWS_WORKLOAD_ADDRESS)
        assert workload is not None
        facts = aws_facts(workload)
        return (
            [cast(Mapping[str, object], path) for path in facts.ecs_dynamodb_item_deletion_paths],
            list(facts.ecs_dynamodb_item_deletion_path_uncertainties),
        )
    if provider == "gcp":
        workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert workload is not None
        facts = gcp_facts(workload)
        return (
            [cast(Mapping[str, object], path) for path in facts.cloud_run_firestore_entity_deletion_paths],
            list(facts.cloud_run_firestore_entity_deletion_path_uncertainties),
        )
    workload = inventory.get_by_address(_AZURE_WORKLOAD_ADDRESS)
    assert workload is not None
    facts = azure_facts(workload)
    return (
        [cast(Mapping[str, object], path) for path in facts.app_service_cosmosdb_item_deletion_paths],
        list(facts.app_service_cosmosdb_item_deletion_path_uncertainties),
    )


def _path_fingerprint(
    provider: str,
    path: Mapping[str, object],
) -> tuple[object, ...]:
    if provider == "aws":
        target = path.get("dynamodb_table_address")
        identity = path.get("role_arn")
        sources = path.get("authorization_source_addresses")
    elif provider == "gcp":
        target = path.get("firestore_database_address")
        identity = path.get("service_account_email")
        sources = path.get("iam_source_addresses")
    else:
        target = path.get("cosmosdb_resource_address")
        identity = path.get("principal_id")
        sources = path.get("authorization_source_addresses")
    source_tuple = tuple(value for value in sources if isinstance(value, str)) if isinstance(sources, list) else ()
    return (
        provider,
        path.get("operation"),
        path.get("operation_class"),
        target,
        identity,
        source_tuple,
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


class PublicWorkloadStructuredDataDisruptionAndRecoveryParityTests(unittest.TestCase):
    """Pins shared threat outcomes without flattening native recovery."""

    def test_provider_local_rule_families_are_registered(self) -> None:
        self.assertTrue({AWS_TAMPERING_RULE, AWS_DISRUPTION_RULE} <= _flatten(AWS_RULE_GROUP_IDS))
        self.assertTrue({GCP_TAMPERING_RULE, GCP_DISRUPTION_RULE} <= _flatten(GCP_RULE_GROUP_IDS))
        self.assertTrue({AZURE_TAMPERING_RULE, AZURE_DISRUPTION_RULE} <= _flatten(AZURE_RULE_GROUP_IDS))

    def test_write_only_emits_tampering_only(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources("dynamodb:PutItem"),
                AWS_TAMPERING_RULE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(["datastore.entities.create"]),
                GCP_TAMPERING_RULE,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources([_AZURE_ITEM_CREATE]),
                AZURE_TAMPERING_RULE,
            ),
        )

        for provider, normalizer, resources, expected_rule in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, _uncertainties = _path_state(provider, inventory)

                self.assertEqual(paths, [])
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [expected_rule],
                )
                self.assertEqual(
                    findings[0].category,
                    StrideCategory.TAMPERING,
                )

    def test_delete_only_emits_dos_with_native_target_granularity(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources("dynamodb:DeleteItem"),
                AWS_DISRUPTION_RULE,
                "dynamodb:DeleteItem",
                "table_item_namespace",
                "exact_table_item_namespace",
                1,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources([_GCP_ENTITY_DELETE]),
                GCP_DISRUPTION_RULE,
                _GCP_ENTITY_DELETE,
                "database_entity_namespace",
                "firestore_project",
                2,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(
                    [_AZURE_ITEM_DELETE],
                    target_kind="container",
                ),
                AZURE_DISRUPTION_RULE,
                _AZURE_ITEM_DELETE,
                "container_item_namespace",
                "exact_cosmosdb_for_nosql_container",
                1,
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            expected_rule,
            operation,
            target_granularity,
            target_scope,
            expected_blast_radius,
        ) in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, _uncertainties = _path_state(provider, inventory)

                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [expected_rule],
                )
                self.assertEqual(
                    findings[0].category,
                    StrideCategory.DENIAL_OF_SERVICE,
                )
                self.assertEqual(
                    findings[0].severity_reasoning.blast_radius,
                    expected_blast_radius,
                )
                self.assertEqual(len(paths), 1)
                self.assertEqual(paths[0]["operation"], operation)
                self.assertEqual(
                    paths[0]["target_granularity"],
                    target_granularity,
                )
                self.assertEqual(
                    paths[0].get("target_scope") or paths[0].get("resource_scope"),
                    target_scope,
                )
                self.assertFalse({"item_id", "document_id", "partition_key_value"} & set(paths[0]))

    def test_write_and_delete_emit_both_without_cross_effect_evidence(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources("dynamodb:BatchWriteItem"),
                AWS_TAMPERING_RULE,
                AWS_DISRUPTION_RULE,
                "dynamodb_mutation_paths",
                "dynamodb_item_deletion_paths",
                "recovery_evidence",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    [
                        "datastore.entities.create",
                        _GCP_ENTITY_DELETE,
                    ]
                ),
                GCP_TAMPERING_RULE,
                GCP_DISRUPTION_RULE,
                "firestore_mutation_paths",
                "firestore_entity_deletion_paths",
                "recovery_posture",
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources([_AZURE_ITEM_CREATE, _AZURE_ITEM_DELETE]),
                AZURE_TAMPERING_RULE,
                AZURE_DISRUPTION_RULE,
                "cosmosdb_mutation_paths",
                "cosmosdb_item_deletion_paths",
                "recovery_posture",
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            tampering_rule,
            disruption_rule,
            mutation_key,
            disruption_key,
            recovery_key,
        ) in cases:
            with self.subTest(provider=provider):
                _inventory, findings = _analyze(normalizer, resources)
                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    {tampering_rule, disruption_rule},
                )

                tampering = _finding_by_rule(findings, tampering_rule)
                disruption = _finding_by_rule(findings, disruption_rule)
                tampering_evidence = _evidence(tampering)
                disruption_evidence = _evidence(disruption)

                self.assertEqual(
                    tampering.category,
                    StrideCategory.TAMPERING,
                )
                self.assertEqual(
                    disruption.category,
                    StrideCategory.DENIAL_OF_SERVICE,
                )
                self.assertIn(mutation_key, tampering_evidence)
                self.assertNotIn(disruption_key, tampering_evidence)
                self.assertNotIn(recovery_key, tampering_evidence)
                self.assertIn(disruption_key, disruption_evidence)
                self.assertIn(recovery_key, disruption_evidence)
                self.assertNotIn(mutation_key, disruption_evidence)

    def test_private_workloads_keep_paths_without_public_findings(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources("dynamodb:DeleteItem", public=False),
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources([_GCP_ENTITY_DELETE], public=False),
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(
                    [_AZURE_ITEM_DELETE],
                    target_kind="container",
                    public=False,
                ),
            ),
        )

        for provider, normalizer, resources in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, _uncertainties = _path_state(provider, inventory)

                self.assertTrue(paths)
                self.assertEqual(findings, [])

    def test_nondeterministic_denied_incomplete_and_unresolved_authority_is_not_promoted(
        self,
    ) -> None:
        runtime_condition = {
            "title": "temporary",
            "expression": ("request.time < timestamp('2030-01-01T00:00:00Z')"),
        }

        aws_denied = _aws_resources("dynamodb:DeleteItem")
        denied_role = aws_role(
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
        )
        aws_denied = [denied_role if resource.address == denied_role.address else resource for resource in aws_denied]
        aws_incomplete = [
            *_aws_resources("dynamodb:DeleteItem"),
            aws_role_policy_attachment(
                AWS_TASK_ROLE_ARN,
                "arn:aws:iam::aws:policy/ExternalDynamoDbDelete",
            ),
        ]

        gcp_unknown_role = _gcp_resources([_GCP_ENTITY_DELETE])
        unresolved_role = _gcp_custom_role(
            [_GCP_ENTITY_DELETE],
            unknown_permissions=True,
        )
        gcp_unknown_role = [
            unresolved_role if resource.address == unresolved_role.address else resource
            for resource in gcp_unknown_role
        ]
        gcp_unresolved_identity = _gcp_resources([_GCP_ENTITY_DELETE])
        unresolved_workload = cast(
            TerraformResource,
            gcp_cloud_run(service_account=None),
        )
        unresolved_workload.values["ingress"] = "INGRESS_TRAFFIC_ALL"
        gcp_unresolved_identity = [
            unresolved_workload if resource.address == unresolved_workload.address else resource
            for resource in gcp_unresolved_identity
        ]

        azure_incomplete = [
            _azure_account(),
            _azure_workload(),
            azure_custom_role(
                data_actions=[_AZURE_ITEM_DELETE],
                unknown_permissions=True,
            ),
            azure_native_assignment(
                role_definition_id=AZURE_CUSTOM_ROLE_ID,
            ),
        ]
        azure_unresolved_scope = [
            _azure_account(),
            _azure_workload(),
            azure_custom_role(data_actions=[_AZURE_ITEM_DELETE]),
            azure_native_assignment(
                role_definition_id=AZURE_CUSTOM_ROLE_ID,
                scope="/dbs/unmodeled",
            ),
        ]
        cases = (
            (
                "aws-conditional",
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    "dynamodb:DeleteItem",
                    condition={"StringEquals": {"aws:PrincipalTag/environment": "production"}},
                ),
                True,
            ),
            (
                "aws-denied",
                "aws",
                AwsNormalizer(),
                aws_denied,
                False,
            ),
            (
                "aws-incomplete",
                "aws",
                AwsNormalizer(),
                aws_incomplete,
                True,
            ),
            (
                "gcp-runtime-condition",
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    [_GCP_ENTITY_DELETE],
                    condition=runtime_condition,
                ),
                True,
            ),
            (
                "gcp-unresolved-role",
                "gcp",
                GcpNormalizer(),
                gcp_unknown_role,
                True,
            ),
            (
                "gcp-unresolved-identity",
                "gcp",
                GcpNormalizer(),
                gcp_unresolved_identity,
                True,
            ),
            (
                "azure-incomplete",
                "azure",
                AzureNormalizer(),
                azure_incomplete,
                True,
            ),
            (
                "azure-unresolved-scope",
                "azure",
                AzureNormalizer(),
                azure_unresolved_scope,
                True,
            ),
        )

        for label, provider, normalizer, resources, expect_uncertainty in cases:
            with self.subTest(case=label):
                inventory, findings = _analyze(normalizer, resources)
                paths, uncertainties = _path_state(provider, inventory)

                self.assertEqual(paths, [])
                self.assertEqual(findings, [])
                self.assertEqual(bool(uncertainties), expect_uncertainty)

    def test_data_store_destruction_stays_out_of_item_disruption(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources("dynamodb:DeleteTable"),
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(["datastore.databases.delete"]),
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(["Microsoft.DocumentDB/databaseAccounts/delete"]),
            ),
        )

        for provider, normalizer, resources in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, _uncertainties = _path_state(provider, inventory)

                self.assertEqual(paths, [])
                self.assertNotIn(
                    {
                        "aws": AWS_DISRUPTION_RULE,
                        "gcp": GCP_DISRUPTION_RULE,
                        "azure": AZURE_DISRUPTION_RULE,
                    }[provider],
                    {finding.rule_id for finding in findings},
                )

    def test_provider_native_recovery_semantics_remain_distinct(self) -> None:
        cases = (
            (
                "aws-pitr",
                AwsNormalizer(),
                _aws_resources(
                    "dynamodb:DeleteItem",
                    table=_aws_table(
                        pitr_enabled=True,
                        recovery_period_days=35,
                    ),
                ),
                AWS_DISRUPTION_RULE,
                "recovery_evidence",
                (
                    "pitr_state=enabled",
                    "pitr_recovery_period_days=35",
                    "recovery_state=point_in_time_recovery_enabled",
                    "successful_recovery_not_established=true",
                ),
            ),
            (
                "gcp-default-history",
                GcpNormalizer(),
                _gcp_resources(
                    [_GCP_ENTITY_DELETE],
                    database=_gcp_database(),
                ),
                GCP_DISRUPTION_RULE,
                "recovery_posture",
                (
                    "pitr_state=not_configured",
                    ("historical_version_retention_state=native_approximately_one_hour"),
                    "recovery_state=pitr_not_enabled",
                ),
            ),
            (
                "gcp-pitr",
                GcpNormalizer(),
                _gcp_resources(
                    [_GCP_ENTITY_DELETE],
                    database=_gcp_database(pitr_enablement=("POINT_IN_TIME_RECOVERY_ENABLED")),
                ),
                GCP_DISRUPTION_RULE,
                "recovery_posture",
                (
                    "pitr_state=enabled",
                    ("historical_version_retention_state=pitr_up_to_seven_days"),
                    "recovery_state=pitr_enabled",
                ),
            ),
            (
                "azure-continuous",
                AzureNormalizer(),
                _azure_resources(
                    [_AZURE_ITEM_DELETE],
                    account=_azure_account(
                        backup_type="Continuous",
                        backup_tier="Continuous30Days",
                    ),
                ),
                AZURE_DISRUPTION_RULE,
                "recovery_posture",
                (
                    "backup_posture_state=continuous",
                    "backup_tier=Continuous30Days",
                    "backup_interval_minutes=not_applicable",
                    "backup_retention_hours=not_applicable",
                    "backup_storage_redundancy=not_applicable",
                    "successful_restore_established=false",
                ),
            ),
            (
                "azure-provider-default",
                AzureNormalizer(),
                _azure_resources(
                    [_AZURE_ITEM_DELETE],
                    account=_azure_account(),
                ),
                AZURE_DISRUPTION_RULE,
                "recovery_posture",
                (
                    "backup_posture_state=provider_default_periodic",
                    "backup_tier=not_applicable",
                    "backup_interval_minutes=240",
                    "backup_retention_hours=8",
                    "backup_storage_redundancy=Geo",
                    "successful_restore_established=false",
                ),
            ),
        )

        for (
            label,
            normalizer,
            resources,
            rule_id,
            evidence_key,
            expected_fragments,
        ) in cases:
            with self.subTest(case=label):
                _inventory, findings = _analyze(normalizer, resources)
                finding = _finding_by_rule(findings, rule_id)
                records = _evidence(finding)[evidence_key]

                self.assertTrue(any(all(fragment in record for fragment in expected_fragments) for record in records))

    def test_unknown_recovery_stays_visible_without_suppressing_authority(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    "dynamodb:DeleteItem",
                    table=_aws_table(unknown_pitr=True),
                ),
                AWS_DISRUPTION_RULE,
                "recovery_evidence",
                "dynamodb_item_deletion_path_uncertainties",
                "pitr_state=unknown",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    [_GCP_ENTITY_DELETE],
                    database=_gcp_database(unknown_pitr=True),
                ),
                GCP_DISRUPTION_RULE,
                "recovery_posture",
                None,
                "pitr_state=unknown",
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(
                    [_AZURE_ITEM_DELETE],
                    account=_azure_account(unknown_backup=True),
                ),
                AZURE_DISRUPTION_RULE,
                "recovery_posture",
                "cosmosdb_item_deletion_path_uncertainties",
                "backup_posture_state=unknown",
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            rule_id,
            recovery_key,
            uncertainty_key,
            state_fragment,
        ) in cases:
            with self.subTest(provider=provider):
                _inventory, findings = _analyze(normalizer, resources)
                finding = _finding_by_rule(findings, rule_id)
                evidence = _evidence(finding)

                matching_recovery = [
                    record
                    for record in evidence[recovery_key]
                    if state_fragment in record and "recovery_posture_unknown" in record
                ]
                self.assertTrue(matching_recovery)
                if uncertainty_key is None:
                    self.assertTrue(
                        any(
                            "uncertainties=" in record and "uncertainties=none" not in record
                            for record in matching_recovery
                        )
                    )
                else:
                    self.assertTrue(evidence[uncertainty_key])

    def test_operation_paths_and_scope_counts_deduplicate_stably(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    [
                        "dynamodb:DeleteItem",
                        "dynamodb:PartiQLDelete",
                        "dynamodb:BatchWriteItem",
                    ]
                ),
                3,
                {AWS_TAMPERING_RULE, AWS_DISRUPTION_RULE},
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources([_GCP_ENTITY_DELETE, _GCP_BULK_DELETE]),
                2,
                {GCP_DISRUPTION_RULE},
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources([_AZURE_ITEM_DELETE, _AZURE_ITEM_DELETE]),
                1,
                {AZURE_DISRUPTION_RULE},
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            expected_path_count,
            expected_rules,
        ) in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, _uncertainties = _path_state(provider, inventory)
                fingerprints = [_path_fingerprint(provider, path) for path in paths]

                self.assertEqual(len(paths), expected_path_count)
                self.assertEqual(len(fingerprints), len(set(fingerprints)))
                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    expected_rules,
                )
                if provider == "gcp":
                    self.assertEqual(
                        _evidence(findings[0])["scope_breadth"],
                        [
                            "project_applicable_grants=1; "
                            "exact_database_grants=0; "
                            "modeled_databases=1; "
                            "blast_radius_basis=project_applicable_grant"
                        ],
                    )

    def test_one_gcp_project_grant_stays_unique_across_database_fanout(
        self,
    ) -> None:
        resources = [
            *_gcp_resources([_GCP_ENTITY_DELETE, _GCP_BULK_DELETE]),
            _gcp_database(
                address="google_firestore_database.analytics",
                name="analytics",
            ),
        ]

        inventory, findings = _analyze(GcpNormalizer(), resources)
        paths, _uncertainties = _path_state("gcp", inventory)
        fingerprints = [_path_fingerprint("gcp", path) for path in paths]

        self.assertEqual(len(paths), 4)
        self.assertEqual(len(fingerprints), len(set(fingerprints)))
        self.assertEqual(
            {path["operation"] for path in paths},
            {_GCP_ENTITY_DELETE, _GCP_BULK_DELETE},
        )
        self.assertEqual(
            {path["firestore_database_address"] for path in paths},
            {
                "google_firestore_database.orders",
                "google_firestore_database.analytics",
            },
        )
        self.assertEqual(
            [finding.rule_id for finding in findings],
            [GCP_DISRUPTION_RULE],
        )

        finding = findings[0]
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)
        self.assertEqual(
            _evidence(finding)["scope_breadth"],
            [
                "project_applicable_grants=1; "
                "exact_database_grants=0; "
                "modeled_databases=2; "
                "blast_radius_basis=project_applicable_grant"
            ],
        )

    def test_reused_rule_engine_preserves_provider_isolation(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources("dynamodb:BatchWriteItem"),
                {AWS_TAMPERING_RULE, AWS_DISRUPTION_RULE},
                ("google_", "azurerm_"),
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    [
                        "datastore.entities.create",
                        _GCP_ENTITY_DELETE,
                    ]
                ),
                {GCP_TAMPERING_RULE, GCP_DISRUPTION_RULE},
                ("aws_", "azurerm_"),
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources([_AZURE_ITEM_CREATE, _AZURE_ITEM_DELETE]),
                {AZURE_TAMPERING_RULE, AZURE_DISRUPTION_RULE},
                ("aws_", "google_"),
            ),
            (
                "aws-second-pass",
                AwsNormalizer(),
                _aws_resources("dynamodb:BatchWriteItem"),
                {AWS_TAMPERING_RULE, AWS_DISRUPTION_RULE},
                ("google_", "azurerm_"),
            ),
        )
        engine = StrideRuleEngine()

        for (
            label,
            normalizer,
            resources,
            expected_rules,
            foreign_prefixes,
        ) in cases:
            with self.subTest(provider=label):
                provider = label.removesuffix("-second-pass")
                inventory, findings = _analyze(
                    normalizer,
                    resources,
                    engine=engine,
                )
                paths, _uncertainties = _path_state(
                    provider,
                    inventory,
                )
                payload = json.dumps(
                    {
                        "paths": paths,
                        "findings": _finding_payload(findings),
                    },
                    sort_keys=True,
                )

                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    expected_rules,
                )
                for path in paths:
                    self.assertFalse(
                        {
                            "item_id",
                            "document_id",
                            "partition_key_value",
                        }
                        & set(path)
                    )
                for prefix in foreign_prefixes:
                    self.assertNotIn(prefix, payload)


if __name__ == "__main__":
    unittest.main()

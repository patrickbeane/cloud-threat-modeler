from __future__ import annotations

import json
import unittest
from collections.abc import Mapping, Sequence
from typing import Any, cast

from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _ARCHIVE_BUCKET_ARN,
    _BUCKET_ARN,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _bucket as aws_bucket,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _statement as aws_statement,
)
from tests.providers.aws.test_aws_public_ecs_s3_bucket_topology_disruption_rules import (
    _runtime_resources as aws_runtime_resources,
)
from tests.providers.azure.test_azure_app_service_storage_container_topology_destruction_paths import (
    _ACCOUNT_ADDRESS as AZURE_ACCOUNT_ADDRESS,
)
from tests.providers.azure.test_azure_app_service_storage_container_topology_destruction_paths import (
    _CONTAINER_ADDRESS as AZURE_CONTAINER_ADDRESS,
)
from tests.providers.azure.test_azure_app_service_storage_container_topology_destruction_paths import (
    _DELETE_CONTAINER as AZURE_DELETE_CONTAINER,
)
from tests.providers.azure.test_azure_app_service_storage_container_topology_destruction_paths import (
    _control_assignment as azure_control_assignment,
)
from tests.providers.azure.test_azure_app_service_storage_container_topology_destruction_paths import (
    _control_role as azure_control_role,
)
from tests.providers.azure.test_azure_app_service_storage_container_topology_destruction_paths import (
    _storage_account as azure_storage_account,
)
from tests.providers.azure.test_azure_app_service_storage_container_topology_destruction_paths import (
    _storage_container as azure_storage_container,
)
from tests.providers.azure.test_azure_public_app_service_storage_container_topology_disruption_rules import (
    _public_web_app as azure_public_web_app,
)
from tests.providers.azure.test_azure_public_app_service_storage_container_topology_disruption_rules import (
    _resources as azure_topology_resources,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_object_deletion_paths import (
    _BUCKET_ADDRESS as GCP_BUCKET_ADDRESS,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_object_deletion_paths import (
    _PROJECT as GCP_PROJECT,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_object_deletion_paths import (
    _bucket as gcp_bucket,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_object_deletion_paths import (
    _bucket_member as gcp_bucket_member,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_object_deletion_paths import (
    _custom_role as gcp_custom_role,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_object_deletion_paths import (
    _project_member as gcp_project_member,
)
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_mutation_rules import (
    _cloud_run as gcp_cloud_run,
)
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_mutation_rules import (
    _public_invoker as gcp_public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, ResourceInventory, StrideCategory, TerraformResource
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

AWS_TAMPERING_RULE = "aws-public-ecs-s3-mutation-access"
AWS_OBJECT_DISRUPTION_RULE = "aws-public-ecs-s3-object-disruption"
AWS_TOPOLOGY_DISRUPTION_RULE = "aws-public-ecs-s3-bucket-topology-disruption"

GCP_TAMPERING_RULE = "gcp-public-cloud-run-gcs-mutation-access"
GCP_OBJECT_DISRUPTION_RULE = "gcp-public-cloud-run-gcs-object-disruption"
GCP_TOPOLOGY_DISRUPTION_RULE = "gcp-public-cloud-run-gcs-bucket-topology-disruption"

AZURE_TAMPERING_RULE = "azure-public-app-service-storage-mutation-access"
AZURE_OBJECT_DISRUPTION_RULE = "azure-public-app-service-storage-blob-disruption"
AZURE_TOPOLOGY_DISRUPTION_RULE = "azure-public-app-service-storage-container-topology-disruption"

_RULE_IDS = frozenset(
    {
        AWS_TAMPERING_RULE,
        AWS_OBJECT_DISRUPTION_RULE,
        AWS_TOPOLOGY_DISRUPTION_RULE,
        GCP_TAMPERING_RULE,
        GCP_OBJECT_DISRUPTION_RULE,
        GCP_TOPOLOGY_DISRUPTION_RULE,
        AZURE_TAMPERING_RULE,
        AZURE_OBJECT_DISRUPTION_RULE,
        AZURE_TOPOLOGY_DISRUPTION_RULE,
    }
)

_AWS_WORKLOAD_ADDRESS = "aws_ecs_service.orders"
_GCP_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_AZURE_WORKLOAD_ADDRESS = "azurerm_linux_web_app.orders"

_AWS_DELETE_BUCKET = "s3:DeleteBucket"
_AWS_PUT_OBJECT = "s3:PutObject"
_AWS_DELETE_OBJECT = "s3:DeleteObject"
_GCP_DELETE_BUCKET = "storage.buckets.delete"
_GCP_CREATE_OBJECT = "storage.objects.create"
_GCP_DELETE_OBJECT = "storage.objects.delete"
_AZURE_WRITE_BLOB = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"
_AZURE_DELETE_BLOB = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
_GCP_TOPOLOGY_ROLE_NAME = f"projects/{GCP_PROJECT}/roles/bucketTopology"


def _flatten(groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for group in groups for rule_id in group)


def _tf(value: object) -> TerraformResource:
    assert isinstance(value, TerraformResource)
    return value


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


def _topology_state(
    provider: str,
    inventory: ResourceInventory,
) -> tuple[list[Mapping[str, object]], list[str]]:
    if provider == "aws":
        workload = inventory.get_by_address(_AWS_WORKLOAD_ADDRESS)
        assert workload is not None
        facts = aws_facts(workload)
        return (
            [cast(Mapping[str, object], path) for path in facts.ecs_s3_bucket_topology_destruction_paths],
            list(facts.ecs_s3_bucket_topology_destruction_path_uncertainties),
        )
    if provider == "gcp":
        workload = inventory.get_by_address(_GCP_WORKLOAD_ADDRESS)
        assert workload is not None
        facts = gcp_facts(workload)
        return (
            [cast(Mapping[str, object], path) for path in facts.cloud_run_gcs_bucket_topology_destruction_paths],
            list(facts.cloud_run_gcs_bucket_topology_destruction_path_uncertainties),
        )

    workload = inventory.get_by_address(_AZURE_WORKLOAD_ADDRESS)
    assert workload is not None
    facts = azure_facts(workload)
    return (
        [cast(Mapping[str, object], path) for path in facts.app_service_storage_container_topology_destruction_paths],
        list(facts.app_service_storage_container_topology_destruction_path_uncertainties),
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
        aws_facts(workload).set_ecs_s3_bucket_topology_destruction_paths(cast(Any, records))
        return
    if provider == "gcp":
        workload = inventory.get_by_address(_GCP_WORKLOAD_ADDRESS)
        assert workload is not None
        gcp_facts(workload).set_cloud_run_gcs_bucket_topology_destruction_paths(cast(Any, records))
        return

    workload = inventory.get_by_address(_AZURE_WORKLOAD_ADDRESS)
    assert workload is not None
    azure_facts(workload).set_app_service_storage_container_topology_destruction_paths(cast(Any, records))


def _topology_fingerprint(
    provider: str,
    path: Mapping[str, object],
) -> tuple[object, ...]:
    if provider == "aws":
        identity = path.get("role_arn")
        target = path.get("bucket_address")
        sources = path.get("authorization_source_addresses")
    elif provider == "gcp":
        identity = path.get("service_account_email")
        target = path.get("bucket_address")
        sources = path.get("iam_source_addresses")
    else:
        identity = path.get("principal_id")
        target = path.get("container_address")
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


def _aws_topology_resources(*, public: bool = True) -> list[TerraformResource]:
    return aws_runtime_resources(
        _AWS_DELETE_BUCKET,
        include_load_balancer=public,
    )


def _gcp_topology_resources(
    *,
    public: bool = True,
    bucket: TerraformResource | None = None,
) -> list[TerraformResource]:
    return [
        gcp_cloud_run(public_ingress=public),
        gcp_public_invoker(),
        bucket or _tf(gcp_bucket()),
        _tf(
            gcp_custom_role(
                role_id="bucketTopology",
                permissions=[_GCP_DELETE_BUCKET],
                stage="GA",
                deleted=False,
            )
        ),
        _tf(gcp_bucket_member(role=_GCP_TOPOLOGY_ROLE_NAME)),
    ]


def _azure_topology_resources(*, public: bool = True) -> list[TerraformResource]:
    return azure_topology_resources(public=public)


def _non_topology_resources() -> tuple[
    tuple[str, ProviderNormalizer, list[TerraformResource], set[str]],
    ...,
]:
    return (
        (
            "aws",
            AwsNormalizer(),
            aws_runtime_resources(
                role_statements=[
                    aws_statement("Allow", _AWS_PUT_OBJECT, f"{_BUCKET_ARN}/*"),
                    aws_statement("Allow", _AWS_DELETE_OBJECT, f"{_BUCKET_ARN}/*"),
                ]
            ),
            {AWS_TAMPERING_RULE, AWS_OBJECT_DISRUPTION_RULE},
        ),
        (
            "gcp",
            GcpNormalizer(),
            [
                gcp_cloud_run(),
                gcp_public_invoker(),
                _tf(gcp_bucket()),
                _tf(
                    gcp_custom_role(
                        role_id="objectOps",
                        permissions=[_GCP_CREATE_OBJECT, _GCP_DELETE_OBJECT],
                        stage="GA",
                        deleted=False,
                    )
                ),
                _tf(gcp_bucket_member(role=f"projects/{GCP_PROJECT}/roles/objectOps")),
            ],
            {GCP_TAMPERING_RULE, GCP_OBJECT_DISRUPTION_RULE},
        ),
        (
            "azure",
            AzureNormalizer(),
            azure_topology_resources(
                role=azure_control_role(
                    actions=[],
                    data_actions=[_AZURE_WRITE_BLOB, _AZURE_DELETE_BLOB],
                )
            ),
            {AZURE_TAMPERING_RULE, AZURE_OBJECT_DISRUPTION_RULE},
        ),
    )


def _mixed_write_and_topology_resources() -> tuple[
    tuple[str, ProviderNormalizer, list[TerraformResource], str, str, str, str],
    ...,
]:
    return (
        (
            "aws",
            AwsNormalizer(),
            aws_runtime_resources(
                role_statements=[
                    aws_statement("Allow", _AWS_PUT_OBJECT, f"{_BUCKET_ARN}/*"),
                    aws_statement("Allow", _AWS_DELETE_BUCKET, _BUCKET_ARN),
                ]
            ),
            AWS_TAMPERING_RULE,
            AWS_TOPOLOGY_DISRUPTION_RULE,
            "s3_mutation_paths",
            _AWS_DELETE_BUCKET,
        ),
        (
            "gcp",
            GcpNormalizer(),
            [
                gcp_cloud_run(),
                gcp_public_invoker(),
                _tf(gcp_bucket()),
                _tf(
                    gcp_custom_role(
                        role_id="mixedStorage",
                        permissions=[_GCP_CREATE_OBJECT, _GCP_DELETE_BUCKET],
                        stage="GA",
                        deleted=False,
                    )
                ),
                _tf(gcp_bucket_member(role=f"projects/{GCP_PROJECT}/roles/mixedStorage")),
            ],
            GCP_TAMPERING_RULE,
            GCP_TOPOLOGY_DISRUPTION_RULE,
            "gcs_mutation_paths",
            _GCP_DELETE_BUCKET,
        ),
        (
            "azure",
            AzureNormalizer(),
            azure_topology_resources(
                role=azure_control_role(
                    actions=[AZURE_DELETE_CONTAINER],
                    data_actions=[_AZURE_WRITE_BLOB],
                )
            ),
            AZURE_TAMPERING_RULE,
            AZURE_TOPOLOGY_DISRUPTION_RULE,
            "storage_mutation_paths",
            AZURE_DELETE_CONTAINER,
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


class PublicWorkloadObjectStorageTopologyDisruptionParityTests(unittest.TestCase):
    """Pin shared topology DoS outcomes without flattening provider evidence."""

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
                _azure_topology_resources(),
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

    def test_object_write_and_delete_do_not_become_topology_disruption(self) -> None:
        topology_rules = {
            "aws": AWS_TOPOLOGY_DISRUPTION_RULE,
            "gcp": GCP_TOPOLOGY_DISRUPTION_RULE,
            "azure": AZURE_TOPOLOGY_DISRUPTION_RULE,
        }
        for provider, normalizer, resources, expected_rules in _non_topology_resources():
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

    def test_write_and_topology_delete_emit_both_without_cross_effect_evidence(self) -> None:
        for (
            provider,
            normalizer,
            resources,
            mutation_rule,
            topology_rule,
            mutation_evidence_key,
            topology_operation,
        ) in _mixed_write_and_topology_resources():
            with self.subTest(provider=provider):
                _inventory, findings = _analyze(normalizer, resources)

                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    {mutation_rule, topology_rule},
                )
                mutation = _finding_by_rule(findings, mutation_rule)
                topology = _finding_by_rule(findings, topology_rule)
                mutation_payload = json.dumps(_evidence(mutation)[mutation_evidence_key], sort_keys=True)
                topology_payload = json.dumps(_evidence(topology), sort_keys=True)
                self.assertNotIn(topology_operation, mutation_payload)
                self.assertIn(topology_operation, topology_payload)
                self.assertEqual(mutation.category, StrideCategory.TAMPERING)
                self.assertEqual(topology.category, StrideCategory.DENIAL_OF_SERVICE)

    def test_native_target_and_recovery_evidence_remain_provider_specific(self) -> None:
        aws_inventory, aws_findings = _analyze(AwsNormalizer(), _aws_topology_resources())
        aws_paths, _ = _topology_state("aws", aws_inventory)
        aws_path = aws_paths[0]
        self.assertEqual(aws_path["operation"], _AWS_DELETE_BUCKET)
        self.assertEqual(aws_path["target_scope"], "exact_s3_bucket")
        self.assertEqual(aws_path["target_model_evidence_addresses"], ["aws_s3_bucket.orders"])
        self.assertIs(aws_path["same_account"], True)
        aws_recovery = cast(Mapping[str, object], aws_path["recovery_evidence"])
        self.assertIs(aws_recovery["bucket_emptiness_required"], True)
        self.assertEqual(aws_recovery["bucket_emptiness_state"], "not_established")
        self.assertEqual(aws_recovery["attached_access_point_state"], "not_established")

        gcp_inventory, gcp_findings = _analyze(GcpNormalizer(), _gcp_topology_resources())
        gcp_paths, _ = _topology_state("gcp", gcp_inventory)
        gcp_path = gcp_paths[0]
        self.assertEqual(gcp_path["operation"], _GCP_DELETE_BUCKET)
        self.assertEqual(gcp_path["target_scope"], "exact_gcs_bucket")
        self.assertEqual(gcp_path["target_model_evidence_addresses"], [GCP_BUCKET_ADDRESS])
        self.assertEqual(gcp_path["bucket_reference"], "projects/_/buckets/tfstride-orders-data")
        gcp_recovery = cast(Mapping[str, object], gcp_path["recovery_evidence"])
        self.assertEqual(gcp_recovery["soft_delete_state"], "enabled")
        self.assertEqual(gcp_recovery["bucket_emptiness_state"], "not_established")

        azure_inventory, azure_findings = _analyze(AzureNormalizer(), _azure_topology_resources())
        azure_paths, _ = _topology_state("azure", azure_inventory)
        azure_path = azure_paths[0]
        self.assertEqual(azure_path["operation"], AZURE_DELETE_CONTAINER)
        self.assertEqual(azure_path["target_scope"], "exact_storage_container")
        self.assertEqual(
            azure_path["target_model_evidence_addresses"],
            [AZURE_ACCOUNT_ADDRESS, AZURE_CONTAINER_ADDRESS],
        )
        self.assertEqual(azure_path["authorization_evidence_kind"], "azure_rbac_action")
        azure_recovery = cast(Mapping[str, object], azure_path["recovery_evidence"])
        self.assertEqual(azure_recovery["container_soft_delete_state"], "enabled")
        azure_constraints = cast(Mapping[str, object], azure_path["deletion_constraint_evidence"])
        self.assertEqual(azure_constraints["protected_content_emptiness_state"], "not_applicable")

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
            ("azure", AzureNormalizer(), _azure_topology_resources(public=False)),
        )

        for provider, normalizer, resources in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, _uncertainties = _topology_state(provider, inventory)

                self.assertTrue(paths)
                self.assertEqual(findings, [])

    def test_conditional_or_unresolved_authority_fails_closed(self) -> None:
        cases = (
            (
                "aws-condition",
                "aws",
                AwsNormalizer(),
                aws_runtime_resources(
                    role_statements=[
                        aws_statement(
                            "Allow",
                            _AWS_DELETE_BUCKET,
                            _BUCKET_ARN,
                            condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                        )
                    ]
                ),
            ),
            (
                "gcp-condition",
                "gcp",
                GcpNormalizer(),
                [
                    gcp_cloud_run(),
                    gcp_public_invoker(),
                    _tf(gcp_bucket()),
                    _tf(
                        gcp_custom_role(
                            role_id="bucketTopology",
                            permissions=[_GCP_DELETE_BUCKET],
                            stage="GA",
                            deleted=False,
                        )
                    ),
                    _tf(
                        gcp_bucket_member(
                            role=_GCP_TOPOLOGY_ROLE_NAME,
                            condition={
                                "title": "runtime-window",
                                "expression": 'request.time < timestamp("2030-01-01T00:00:00Z")',
                            },
                        )
                    ),
                ],
            ),
            (
                "azure-condition-version",
                "azure",
                AzureNormalizer(),
                azure_topology_resources(
                    assignment=azure_control_assignment(
                        unknown_values={"condition_version": True},
                    )
                ),
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
                self.assertNotIn(topology_rules[provider], {finding.rule_id for finding in findings})

    def test_recovery_and_prerequisite_uncertainty_qualifies_but_does_not_suppress_authority(self) -> None:
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
                _gcp_topology_resources(bucket=_tf(gcp_bucket(unknown_soft_delete=True))),
                GCP_TOPOLOGY_DISRUPTION_RULE,
            ),
            (
                "azure",
                AzureNormalizer(),
                azure_topology_resources(
                    container=azure_storage_container(has_immutability_policy=True),
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
                    {"paths": paths, "finding": _finding_payload([finding])},
                    sort_keys=True,
                )
                self.assertNotIn('"successful_deletion_observed": true', payload)
                self.assertNotIn('"recovery_observed": true', payload)
                self.assertNotIn('"restoration_observed": true', payload)
                self.assertNotIn("permanent deletion", payload.casefold())

                if provider in {"aws", "gcp"}:
                    recovery = cast(Mapping[str, object], paths[0]["recovery_evidence"])
                    self.assertEqual(recovery["bucket_emptiness_state"], "not_established")
                    self.assertIs(recovery["out_of_plan_object_inventory_evaluated"], False)
                    self.assertIn(
                        "bucket_emptiness_state=not_established",
                        _evidence(finding)["bucket_deletion_recovery_evidence"][0],
                    )
                    if provider == "gcp":
                        self.assertTrue(_evidence(finding)["bucket_topology_destruction_path_uncertainties"])
                else:
                    constraints = cast(Mapping[str, object], paths[0]["deletion_constraint_evidence"])
                    self.assertEqual(
                        constraints["constraint_state"],
                        "protected_content_emptiness_not_established",
                    )
                    self.assertEqual(constraints["protected_content_emptiness_state"], "not_established")
                    self.assertIn(
                        "protected_content_emptiness_state=not_established",
                        _evidence(finding)["container_deletion_prerequisite_evidence"][0],
                    )

    def test_broad_grants_fan_out_only_to_exact_modeled_targets(self) -> None:
        aws_resources = aws_runtime_resources(
            role_statements=[
                aws_statement("Allow", _AWS_DELETE_BUCKET, _BUCKET_ARN),
                aws_statement("Allow", _AWS_DELETE_BUCKET, _ARCHIVE_BUCKET_ARN),
            ],
            extra=[aws_bucket("archive", arn=_ARCHIVE_BUCKET_ARN)],
        )
        gcp_resources = [
            gcp_cloud_run(),
            gcp_public_invoker(),
            _tf(gcp_bucket()),
            _tf(
                gcp_bucket(
                    address="google_storage_bucket.archive",
                    name="tfstride-archive-data",
                )
            ),
            _tf(
                gcp_bucket(
                    address="google_storage_bucket.foreign",
                    name="tfstride-foreign-data",
                    project="tfstride-foreign",
                )
            ),
            _tf(gcp_project_member(role="roles/storage.admin")),
        ]
        azure_resources = [
            azure_storage_account(),
            azure_storage_container(),
            azure_storage_container(name="archive"),
            azure_public_web_app(),
            azure_control_role(actions=[AZURE_DELETE_CONTAINER]),
            azure_control_assignment(scope="azurerm_storage_account.orders.id"),
        ]
        cases = (
            (
                "aws",
                AwsNormalizer(),
                aws_resources,
                AWS_TOPOLOGY_DISRUPTION_RULE,
                {"aws_s3_bucket.orders", "aws_s3_bucket.archive"},
                "s3_bucket_topology_destruction_paths",
            ),
            (
                "gcp",
                GcpNormalizer(),
                gcp_resources,
                GCP_TOPOLOGY_DISRUPTION_RULE,
                {GCP_BUCKET_ADDRESS, "google_storage_bucket.archive"},
                "gcs_bucket_topology_destruction_paths",
            ),
            (
                "azure",
                AzureNormalizer(),
                azure_resources,
                AZURE_TOPOLOGY_DISRUPTION_RULE,
                {AZURE_CONTAINER_ADDRESS, "azurerm_storage_container.archive"},
                "storage_container_topology_destruction_paths",
            ),
        )

        for provider, normalizer, resources, rule_id, targets, evidence_key in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                paths, _uncertainties = _topology_state(provider, inventory)
                finding = _finding_by_rule(findings, rule_id)
                path_targets = {str(path.get("bucket_address") or path.get("container_address")) for path in paths}

                self.assertEqual(path_targets, targets)
                self.assertEqual(len(paths), 2)
                self.assertEqual(len(_evidence(finding)[evidence_key]), 2)
                self.assertEqual(finding.severity_reasoning.blast_radius, 2)
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
                "aws_s3_bucket.orders",
                "s3_bucket_topology_destruction_paths",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_topology_resources(),
                GCP_TOPOLOGY_DISRUPTION_RULE,
                GCP_BUCKET_ADDRESS,
                "gcs_bucket_topology_destruction_paths",
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_topology_resources(),
                AZURE_TOPOLOGY_DISRUPTION_RULE,
                AZURE_CONTAINER_ADDRESS,
                "storage_container_topology_destruction_paths",
            ),
        )

        for provider, normalizer, resources, rule_id, target, evidence_key in cases:
            with self.subTest(provider=provider):
                inventory, _findings = _analyze(normalizer, resources)
                paths, _uncertainties = _topology_state(provider, inventory)
                self.assertEqual(len(paths), 1)
                _replace_topology_paths(provider, inventory, [*paths, dict(paths[0])])

                finding = _finding_by_rule(_evaluate_inventory(inventory), rule_id)
                self.assertEqual(finding.affected_resources.count(target), 1)
                self.assertEqual(len(_evidence(finding)[evidence_key]), 1)
                self.assertEqual(finding.severity_reasoning.blast_radius, 1)

    def test_stale_projected_targets_are_rejected_for_every_provider(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_topology_resources(),
                AWS_TOPOLOGY_DISRUPTION_RULE,
                "bucket_address",
                "aws_s3_bucket.stale",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_topology_resources(),
                GCP_TOPOLOGY_DISRUPTION_RULE,
                "bucket_address",
                "google_storage_bucket.stale",
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_topology_resources(),
                AZURE_TOPOLOGY_DISRUPTION_RULE,
                "container_address",
                "azurerm_storage_container.stale",
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
                _azure_topology_resources(),
                AZURE_TOPOLOGY_DISRUPTION_RULE,
            ),
        )

        for provider, normalizer, resources, rule_id in cases:
            with self.subTest(provider=provider):
                inventory, findings = _analyze(normalizer, resources)
                self.assertIsNotNone(_finding_by_rule(findings, rule_id))
                cached_paths, _uncertainties = _topology_state(provider, inventory)
                self.assertEqual(len(cached_paths), 1)

                if provider == "aws":
                    role = inventory.get_by_address("aws_iam_role.orders_task")
                    assert role is not None
                    role.policy_statements = ()
                elif provider == "gcp":
                    role = inventory.get_by_address("google_project_iam_custom_role.bucketTopology")
                    assert role is not None
                    gcp_facts(role).set(
                        GcpResourceMetadata.CUSTOM_ROLE_STAGE,
                        "DISABLED",
                    )
                else:
                    role = inventory.get_by_address("azurerm_role_definition.storage_topology")
                    assert role is not None
                    azure_facts(role).set(
                        AzureResourceMetadata.ROLE_DEFINITION_ACTIONS,
                        [],
                    )

                retained_paths, _uncertainties = _topology_state(provider, inventory)
                self.assertEqual(retained_paths, cached_paths)
                self.assertNotIn(
                    rule_id,
                    {finding.rule_id for finding in _evaluate_inventory(inventory)},
                )

    def test_reused_rule_engine_preserves_provider_isolation_and_payload_exclusion(self) -> None:
        aws_resources = _aws_topology_resources()
        aws_target = next(resource for resource in aws_resources if resource.address == "aws_s3_bucket.orders")
        aws_target.values["tags"] = {"payload": "aws-storage-topology-payload-must-not-leak"}

        gcp_resources = _gcp_topology_resources()
        gcp_target = next(resource for resource in gcp_resources if resource.address == GCP_BUCKET_ADDRESS)
        gcp_target.values["labels"] = {"payload": "gcp-storage-topology-payload-must-not-leak"}

        azure_resources = _azure_topology_resources()
        azure_target = next(resource for resource in azure_resources if resource.address == AZURE_CONTAINER_ADDRESS)
        azure_target.values["metadata"] = {"payload": "azure-storage-topology-payload-must-not-leak"}

        cases = (
            (
                "aws",
                AwsNormalizer(),
                aws_resources,
                AWS_TOPOLOGY_DISRUPTION_RULE,
                ("google_", "azurerm_", _GCP_DELETE_BUCKET, AZURE_DELETE_CONTAINER),
                "aws-storage-topology-payload-must-not-leak",
            ),
            (
                "gcp",
                GcpNormalizer(),
                gcp_resources,
                GCP_TOPOLOGY_DISRUPTION_RULE,
                ("aws_", "azurerm_", _AWS_DELETE_BUCKET, AZURE_DELETE_CONTAINER),
                "gcp-storage-topology-payload-must-not-leak",
            ),
            (
                "azure",
                AzureNormalizer(),
                azure_resources,
                AZURE_TOPOLOGY_DISRUPTION_RULE,
                ("aws_", "google_", _AWS_DELETE_BUCKET, _GCP_DELETE_BUCKET),
                "azure-storage-topology-payload-must-not-leak",
            ),
            (
                "aws-second-pass",
                AwsNormalizer(),
                aws_resources,
                AWS_TOPOLOGY_DISRUPTION_RULE,
                ("google_", "azurerm_", _GCP_DELETE_BUCKET, AZURE_DELETE_CONTAINER),
                "aws-storage-topology-payload-must-not-leak",
            ),
        )
        engine = StrideRuleEngine()

        for label, normalizer, resources, rule_id, foreign_values, sentinel in cases:
            with self.subTest(provider=label):
                provider = label.removesuffix("-second-pass")
                inventory, findings = _analyze(normalizer, resources, engine=engine)
                paths, _uncertainties = _topology_state(provider, inventory)

                self.assertTrue(paths)
                self.assertEqual([finding.rule_id for finding in findings], [rule_id])
                payload = json.dumps(
                    {"paths": paths, "findings": _finding_payload(findings)},
                    sort_keys=True,
                )
                self.assertNotIn(sentinel, payload)
                for foreign_value in foreign_values:
                    self.assertNotIn(foreign_value, payload)


if __name__ == "__main__":
    unittest.main()

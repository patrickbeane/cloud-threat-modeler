from __future__ import annotations

import unittest
from collections.abc import Sequence

from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _KEY_ARNS as AWS_KEY_ARNS,
)
from tests.providers.aws.test_aws_kms_encryption_dependencies import (
    _key as aws_dependency_key,
)
from tests.providers.aws.test_aws_kms_encryption_dependencies import (
    _resolution as aws_resolution,
)
from tests.providers.aws.test_aws_kms_encryption_dependencies import (
    _resource as aws_resource,
)
from tests.providers.aws.test_aws_kms_encryption_dependencies import (
    _unknown_queue as aws_unknown_queue,
)
from tests.providers.aws.test_aws_public_ecs_kms_management_rules import (
    _public_management_resources as aws_public_management_resources,
)
from tests.providers.azure.test_azure_app_service_key_vault_management_paths import (
    _crypto_officer_assignment as azure_crypto_officer_assignment,
)
from tests.providers.azure.test_azure_app_service_key_vault_management_paths import (
    _vault_with_recovery as azure_vault_with_recovery,
)
from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _KEY_URI as AZURE_KEY_URI,
)
from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _KEY_VERSIONLESS_URI as AZURE_KEY_VERSIONLESS_URI,
)
from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _key as azure_key,
)
from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _resource as azure_resource,
)
from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _web_app as azure_web_app,
)
from tests.providers.azure.test_azure_public_app_service_storage_mutation_rules import (
    _public as azure_public,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _RING as GCP_KEY_RING,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _key as gcp_key,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _project_member as gcp_project_member,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _version as gcp_version,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _public_cloud_run as gcp_public_cloud_run,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _public_invoker as gcp_public_invoker,
)
from tests.providers.gcp.test_gcp_public_cloud_run_kms_management_rules import (
    _topic_with_cmek as gcp_topic_with_cmek,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import (
    Finding,
    ResourceInventory,
    StrideCategory,
    TerraformReferenceResolutionState,
    TerraformResource,
)
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts

AWS_DISRUPTION_RULE = "aws-public-ecs-kms-key-disruption"
GCP_DISRUPTION_RULE = "gcp-public-cloud-run-kms-key-disruption"
AZURE_DISRUPTION_RULE = "azure-public-app-service-key-vault-key-disruption"
_RULE_IDS = frozenset(
    {
        AWS_DISRUPTION_RULE,
        GCP_DISRUPTION_RULE,
        AZURE_DISRUPTION_RULE,
    }
)


def _evaluate(inventory: ResourceInventory) -> list[Finding]:
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=_RULE_IDS),
    )


def _single_finding(inventory: ResourceInventory, expected_rule: str) -> Finding:
    findings = _evaluate(inventory)
    if [finding.rule_id for finding in findings] != [expected_rule]:
        raise AssertionError(f"expected only {expected_rule}, got {[finding.rule_id for finding in findings]}")
    return findings[0]


def _evidence(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


def _aws_queue(name: str, key_reference: str) -> TerraformResource:
    return aws_resource(
        "aws_sqs_queue",
        name,
        {
            "name": name,
            "arn": f"arn:aws:sqs:us-east-1:111122223333:{name}",
            "kms_master_key_id": key_reference,
            "sqs_managed_sse_enabled": False,
        },
    )


def _aws_inventory(*dependencies: TerraformResource) -> ResourceInventory:
    return AwsNormalizer().normalize(
        [
            *aws_public_management_resources(
                operations=("kms:DisableKey", "kms:ScheduleKeyDeletion"),
            ),
            *dependencies,
        ]
    )


def _gcp_management_resources(topic: TerraformResource) -> list[TerraformResource]:
    key = gcp_key("data", "ENCRYPT_DECRYPT")
    key.values["destroy_scheduled_duration"] = "604800s"
    version = gcp_version("data", "GOOGLE_SYMMETRIC_ENCRYPTION")
    version.values["deletion_policy"] = "ABANDON"
    return [
        gcp_public_cloud_run(),
        gcp_public_invoker(),
        key,
        version,
        topic,
        gcp_project_member("runtime_admin", "roles/cloudkms.admin"),
    ]


def _gcp_inventory(
    *,
    exact_version_dependency: bool = False,
    unknown_dependency: bool = False,
) -> ResourceInventory:
    topic = gcp_topic_with_cmek(
        "orders",
        key_name=(None if unknown_dependency else f"{GCP_KEY_RING}/cryptoKeys/data"),
        unknown_key=unknown_dependency,
    )
    inventory = GcpNormalizer().normalize(_gcp_management_resources(topic))
    if not exact_version_dependency:
        return inventory

    key = inventory.get_by_address("google_kms_crypto_key.data")
    normalized_topic = inventory.get_by_address("google_pubsub_topic.orders")
    assert key is not None
    assert normalized_topic is not None
    version_address = "google_kms_crypto_key_version.data"
    version_resource_name = f"{GCP_KEY_RING}/cryptoKeys/data/cryptoKeyVersions/1"
    dependency = gcp_facts(key).kms_encryption_dependencies[0].copy()
    dependency.update(
        {
            "candidate_targets": [
                {
                    "address": version_address,
                    "target_kind": "crypto_key_version",
                }
            ],
            "reference_provenance": "planned_value",
            "reference_kind": "crypto_key_version_resource_name",
            "configured_key_reference": version_resource_name,
            "version_reference_is_explicit": True,
            "key_version_address": version_address,
            "key_version_resource_name": version_resource_name,
        }
    )
    for resource in (key, normalized_topic):
        object.__setattr__(resource, "_decoration_state_frozen", False)
        gcp_facts(resource).set_kms_encryption_dependency_posture(
            dependencies=[dependency],
            uncertainties=[],
        )
        object.__setattr__(resource, "_decoration_state_frozen", True)
    return inventory


def _azure_storage(
    name: str,
    key_reference: str | None,
    *,
    unknown_uri: bool = False,
) -> TerraformResource:
    key_field = "key_vault_key_uri" if unknown_uri else "key_vault_key_id"
    return azure_resource(
        AzureResourceType.STORAGE_ACCOUNT,
        name,
        {
            "id": (f"/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/{name}"),
            "name": name,
            "customer_managed_key": [{key_field: key_reference}],
        },
        unknown_values=({"customer_managed_key": [{"key_vault_key_uri": True}]} if unknown_uri else None),
    )


def _azure_inventory(
    dependencies: Sequence[TerraformResource],
    *,
    purge_protection: bool,
) -> ResourceInventory:
    return AzureNormalizer().normalize(
        [
            azure_vault_with_recovery(
                rbac_enabled=True,
                purge_protection=purge_protection,
            ),
            azure_key(key_opts=("encrypt",)),
            azure_public(azure_web_app()),
            azure_crypto_officer_assignment(),
            *dependencies,
        ]
    )


class ManagedKeyDependencyBlastRadiusParityTests(unittest.TestCase):
    """Pins shared blast-radius outcomes without flattening native key semantics."""

    def test_exact_dependencies_enrich_only_local_disruption_findings_once(self) -> None:
        cases = (
            (
                "aws",
                _aws_inventory(_aws_queue("orders", AWS_KEY_ARNS["data"])),
                AWS_DISRUPTION_RULE,
                "aws_sqs_queue.orders",
                "kms_management_paths",
                "unique_dependency_count=1; unique_dependent_resource_count=1; ",
            ),
            (
                "gcp",
                _gcp_inventory(exact_version_dependency=True),
                GCP_DISRUPTION_RULE,
                "google_pubsub_topic.orders",
                "kms_management_paths",
                "unique_dependency_count=1; unique_dependent_resource_count=1; ",
            ),
            (
                "azure",
                _azure_inventory(
                    [_azure_storage("orders", AZURE_KEY_URI)],
                    purge_protection=False,
                ),
                AZURE_DISRUPTION_RULE,
                "azurerm_storage_account.orders",
                "key_vault_management_paths",
                "unique_dependency_count=1; unique_dependent_resource_count=1; ",
            ),
        )

        for provider, inventory, rule_id, dependent, path_evidence_key, summary in cases:
            with self.subTest(provider=provider):
                finding = _single_finding(inventory, rule_id)
                self.assertEqual(finding.category, StrideCategory.DENIAL_OF_SERVICE)
                self.assertTrue(finding.rule_id.startswith(f"{provider}-"))
                self.assertIn(dependent, finding.affected_resources)
                evidence = _evidence(finding)
                self.assertGreater(len(evidence[path_evidence_key]), 1)
                self.assertIn(summary, evidence["downstream_dependencies"][0])

    def test_dependency_projection_requires_provider_native_exact_targets(self) -> None:
        other_key_arn = "arn:aws:kms:us-east-1:111122223333:key/44444444-4444-4444-4444-444444444444"
        aws_inventory = _aws_inventory(
            aws_dependency_key(
                "other",
                key_id="44444444-4444-4444-4444-444444444444",
                key_arn=other_key_arn,
            ),
            _aws_queue("other", other_key_arn),
        )
        aws_finding = _single_finding(aws_inventory, AWS_DISRUPTION_RULE)
        aws_other_key = aws_inventory.get_by_address("aws_kms_key.other")
        assert aws_other_key is not None
        self.assertEqual(
            [dependency["dependent_address"] for dependency in aws_facts(aws_other_key).kms_encryption_dependencies],
            ["aws_sqs_queue.other"],
        )
        self.assertNotIn("aws_sqs_queue.other", aws_finding.affected_resources)
        self.assertIn(
            "unique_dependency_count=0; unique_dependent_resource_count=0; ",
            _evidence(aws_finding)["downstream_dependencies"][0],
        )

        gcp_inventory = _gcp_inventory()
        gcp_finding = _single_finding(gcp_inventory, GCP_DISRUPTION_RULE)
        gcp_topic = gcp_inventory.get_by_address("google_pubsub_topic.orders")
        assert gcp_topic is not None
        self.assertEqual(
            gcp_facts(gcp_topic).kms_encryption_dependencies[0]["resolution_state"],
            "resolved",
        )
        self.assertFalse(gcp_facts(gcp_topic).kms_encryption_dependencies[0]["version_reference_is_explicit"])
        self.assertNotIn("google_pubsub_topic.orders", gcp_finding.affected_resources)
        self.assertIn(
            "unique_dependency_count=0; unique_dependent_resource_count=0; unique_version_target_count=1; ",
            _evidence(gcp_finding)["downstream_dependencies"][0],
        )

        azure_inventory = _azure_inventory(
            [
                _azure_storage("versionless", AZURE_KEY_VERSIONLESS_URI),
                _azure_storage("versioned", AZURE_KEY_URI),
            ],
            purge_protection=False,
        )
        workload = azure_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None
        workload_facts = azure_facts(workload)
        workload_facts.set_app_service_key_vault_management_paths(
            [path for path in workload_facts.app_service_key_vault_management_paths if path["operation"] == "update"]
        )
        azure_finding = _single_finding(azure_inventory, AZURE_DISRUPTION_RULE)
        self.assertNotIn("azurerm_storage_account.versionless", azure_finding.affected_resources)
        self.assertIn("azurerm_storage_account.versioned", azure_finding.affected_resources)
        self.assertIn(
            "unique_dependency_count=1; unique_dependent_resource_count=1; ",
            _evidence(azure_finding)["downstream_dependencies"][0],
        )

    def test_unresolved_dependencies_remain_visible_without_blast_radius_promotion(self) -> None:
        aws_unresolved = aws_resolution(
            ("kms_master_key_id",),
            (("aws_kms_key.data", ".arn"),),
            state=TerraformReferenceResolutionState.UNRESOLVED,
        )
        aws_inventory = _aws_inventory(
            aws_unknown_queue("unresolved", aws_unresolved),
        )
        aws_queue = aws_inventory.get_by_address("aws_sqs_queue.unresolved")
        assert aws_queue is not None
        aws_dependency = aws_facts(aws_queue).kms_encryption_dependencies[0]
        self.assertEqual(aws_dependency["resolution_state"], "unresolved")
        self.assertTrue(aws_dependency["posture_uncertainties"])
        aws_finding = _single_finding(aws_inventory, AWS_DISRUPTION_RULE)
        self.assertNotIn(aws_queue.address, aws_finding.affected_resources)
        self.assertIn(
            "unique_dependency_count=0; unique_dependent_resource_count=0; ",
            _evidence(aws_finding)["downstream_dependencies"][0],
        )

        gcp_inventory = _gcp_inventory(unknown_dependency=True)
        gcp_topic = gcp_inventory.get_by_address("google_pubsub_topic.orders")
        assert gcp_topic is not None
        gcp_dependency = gcp_facts(gcp_topic).kms_encryption_dependencies[0]
        self.assertEqual(gcp_dependency["resolution_state"], "unresolved")
        self.assertTrue(gcp_dependency["posture_uncertainties"])
        gcp_finding = _single_finding(gcp_inventory, GCP_DISRUPTION_RULE)
        self.assertNotIn(gcp_topic.address, gcp_finding.affected_resources)
        self.assertIn(
            "unique_dependency_count=0; unique_dependent_resource_count=0; ",
            _evidence(gcp_finding)["downstream_dependencies"][0],
        )

        azure_inventory = _azure_inventory(
            [_azure_storage("unresolved", None, unknown_uri=True)],
            purge_protection=False,
        )
        azure_storage = azure_inventory.get_by_address("azurerm_storage_account.unresolved")
        assert azure_storage is not None
        azure_dependency = azure_facts(azure_storage).key_vault_encryption_dependencies[0]
        self.assertEqual(azure_dependency["resolution_state"], "unresolved")
        self.assertTrue(azure_dependency["posture_uncertainties"])
        azure_finding = _single_finding(azure_inventory, AZURE_DISRUPTION_RULE)
        self.assertNotIn(azure_storage.address, azure_finding.affected_resources)
        self.assertIn(
            "unique_dependency_count=0; unique_dependent_resource_count=0; ",
            _evidence(azure_finding)["downstream_dependencies"][0],
        )

    def test_recovery_semantics_remain_provider_native(self) -> None:
        aws_finding = _single_finding(
            _aws_inventory(_aws_queue("orders", AWS_KEY_ARNS["data"])),
            AWS_DISRUPTION_RULE,
        )
        aws_recovery = _evidence(aws_finding)["recovery_window"]
        self.assertTrue(
            any(
                "operation=kms:ScheduleKeyDeletion" in value
                and "deletion_window_in_days=30" in value
                and "recovery_window_state=cancelable_scheduled_deletion" in value
                for value in aws_recovery
            )
        )
        self.assertTrue(
            any(
                "operation=kms:DisableKey" in value and "recovery_window_state=not_governed_by_deletion_window" in value
                for value in aws_recovery
            )
        )

        gcp_inventory = _gcp_inventory(exact_version_dependency=True)
        gcp_workload = gcp_inventory.get_by_address("google_cloud_run_v2_service.orders")
        assert gcp_workload is not None
        destroy_path = next(
            path
            for path in gcp_facts(gcp_workload).cloud_run_kms_management_paths
            if path["operation"] == "cloudkms.cryptoKeyVersions.destroy"
        )
        version_evidence = destroy_path["key_version"]
        assert version_evidence is not None
        self.assertEqual(version_evidence["destroy_scheduled_duration"], "604800s")
        self.assertEqual(version_evidence["deletion_policy_state"], "abandon")
        self.assertFalse(destroy_path["iam_scope_is_key_version"])

        protected_inventory = _azure_inventory(
            [_azure_storage("orders", AZURE_KEY_URI)],
            purge_protection=True,
        )
        protected_finding = _single_finding(
            protected_inventory,
            AZURE_DISRUPTION_RULE,
        )
        protected_recovery = _evidence(protected_finding)["recovery_posture"]
        self.assertTrue(
            any(
                "operation=delete" in value and "recovery_state=recoverable_soft_delete" in value
                for value in protected_recovery
            )
        )
        self.assertFalse(any("recovery_state=permanent_delete_sequence" in value for value in protected_recovery))

        unprotected_finding = _single_finding(
            _azure_inventory(
                [_azure_storage("orders", AZURE_KEY_URI)],
                purge_protection=False,
            ),
            AZURE_DISRUPTION_RULE,
        )
        self.assertTrue(
            any(
                "operation=delete_plus_purge" in value and "recovery_state=permanent_delete_sequence" in value
                for value in _evidence(unprotected_finding)["recovery_posture"]
            )
        )


if __name__ == "__main__":
    unittest.main()

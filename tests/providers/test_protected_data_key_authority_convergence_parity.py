from __future__ import annotations

import json
import unittest
from typing import Any

from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _project_member as gcp_project_member,
)
from tests.providers.test_protected_data_key_authority_convergence import (
    _AWS_BUCKET_ARN,
    _AZURE_KEY_URI,
    _AZURE_KEY_VERSIONLESS_URI,
    _AZURE_RUNTIME_PRINCIPAL_ID,
    _GCP_KEY_PATH,
    AWS_TASK_ROLE_ARN,
    GCP_BUCKET_ADDRESS,
    GCP_SERVICE_ACCOUNT_MEMBER,
    _aws_exact_key_mismatch_resources,
    _aws_resources,
    _azure_dual_identity_resources,
    _azure_exact_key_mismatch_resources,
    _azure_resources,
    _gcp_exact_key_mismatch_resources,
    _gcp_resources,
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
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts

AWS_DECRYPT_RULE = "aws-public-ecs-kms-decrypt-access"
GCP_DECRYPT_RULE = "gcp-public-cloud-run-kms-decrypt-access"
AZURE_DECRYPT_RULE = "azure-public-app-service-key-vault-decrypt-access"
_RULE_IDS = frozenset(
    {
        AWS_DECRYPT_RULE,
        GCP_DECRYPT_RULE,
        AZURE_DECRYPT_RULE,
    }
)

_AWS_WORKLOAD = "aws_ecs_service.orders"
_AWS_DEPENDENT = "aws_s3_bucket.orders"
_GCP_WORKLOAD = "google_cloud_run_v2_service.orders"
_GCP_DEPENDENT = GCP_BUCKET_ADDRESS
_AZURE_WORKLOAD = "azurerm_linux_web_app.orders"
_AZURE_DEPENDENT = "azurerm_storage_container.orders"
_RESOLVED_SUMMARY = (
    "unique_dependency_count=1; unique_dependent_resource_count=1; downstream_dependency_state=resolved_dependents"
)
_UNRESOLVED_SUMMARY = (
    "unique_dependency_count=0; unique_dependent_resource_count=0; downstream_dependency_state=no_resolved_dependents"
)


def _normalize(
    normalizer: ProviderNormalizer,
    resources: list[TerraformResource],
) -> ResourceInventory:
    return normalizer.normalize(resources)


def _evaluate(
    inventory: ResourceInventory,
    *,
    engine: StrideRuleEngine | None = None,
) -> list[Finding]:
    rule_engine = engine or StrideRuleEngine()
    return rule_engine.evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=_RULE_IDS),
    )


def _single_local_finding(
    inventory: ResourceInventory,
    expected_rule: str,
) -> Finding:
    findings = _evaluate(inventory)
    if [finding.rule_id for finding in findings] != [expected_rule]:
        raise AssertionError(f"expected only {expected_rule}, got {[finding.rule_id for finding in findings]}")
    return findings[0]


def _resource(inventory: ResourceInventory, address: str):
    resource = inventory.get_by_address(address)
    assert resource is not None
    return resource


def _evidence(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


def _finding_convergence_uncertainties(
    provider: str,
    finding: Finding,
) -> list[str]:
    evidence = _evidence(finding)
    if provider == "aws":
        return evidence["protected_data_uncertainties"]
    return evidence["downstream_dependency_uncertainties"]


def _finding_payload(finding: Finding) -> str:
    return json.dumps(
        {
            "rule_id": finding.rule_id,
            "affected_resources": finding.affected_resources,
            "rationale": finding.rationale,
            "evidence": _evidence(finding),
        },
        sort_keys=True,
    )


def _convergence_evidence(
    provider: str,
    inventory: ResourceInventory,
) -> tuple[list[Any], list[str]]:
    if provider == "aws":
        facts = aws_facts(_resource(inventory, _AWS_WORKLOAD))
        return (
            list(facts.ecs_s3_protected_data_convergences),
            facts.ecs_s3_protected_data_convergence_uncertainties,
        )
    if provider == "gcp":
        facts = gcp_facts(_resource(inventory, _GCP_WORKLOAD))
        return (
            list(facts.cloud_run_gcs_protected_data_convergences),
            facts.cloud_run_gcs_protected_data_convergence_uncertainties,
        )
    if provider == "azure":
        facts = azure_facts(_resource(inventory, _AZURE_WORKLOAD))
        return (
            [
                *facts.app_service_storage_protected_data_convergences,
                *facts.app_service_service_bus_protected_data_convergences,
            ],
            [
                *facts.app_service_storage_protected_data_convergence_uncertainties,
                *facts.app_service_service_bus_protected_data_convergence_uncertainties,
            ],
        )
    raise AssertionError(f"unsupported parity provider: {provider}")


class ProtectedDataKeyAuthorityConvergenceParityTests(unittest.TestCase):
    """Pins shared outcomes while retaining each provider's native evidence."""

    def test_exact_convergence_enriches_only_the_local_plaintext_recovery_finding(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(),
                AWS_DECRYPT_RULE,
                _AWS_DEPENDENT,
                1,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(),
                GCP_DECRYPT_RULE,
                _GCP_DEPENDENT,
                1,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(),
                AZURE_DECRYPT_RULE,
                _AZURE_DEPENDENT,
                2,
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            expected_rule,
            dependent_address,
            expected_convergence_count,
        ) in cases:
            with self.subTest(provider=provider):
                inventory = _normalize(normalizer, resources)
                finding = _single_local_finding(inventory, expected_rule)
                convergences, uncertainties = _convergence_evidence(
                    provider,
                    inventory,
                )

                self.assertEqual(
                    finding.category,
                    StrideCategory.INFORMATION_DISCLOSURE,
                )
                self.assertTrue(finding.rule_id.startswith(f"{provider}-"))
                self.assertIn(dependent_address, finding.affected_resources)
                self.assertEqual(
                    _evidence(finding)["downstream_dependencies"][0],
                    _RESOLVED_SUMMARY,
                )
                self.assertEqual(
                    len(convergences),
                    expected_convergence_count,
                )
                self.assertEqual(uncertainties, [])
                self.assertTrue(
                    all(
                        convergence["convergence_state"] == "resolved"
                        and convergence["runtime_identity_match"] is True
                        and convergence["protected_resource_match"] is True
                        and convergence["key_identity_match"] is True
                        for convergence in convergences
                    )
                )

    def test_native_identity_and_target_granularity_remain_provider_specific(
        self,
    ) -> None:
        aws_inventory = _normalize(AwsNormalizer(), _aws_resources())
        aws_convergence = aws_facts(_resource(aws_inventory, _AWS_WORKLOAD)).ecs_s3_protected_data_convergences[0]
        self.assertEqual(
            aws_convergence["access_path"]["role_arn"],
            AWS_TASK_ROLE_ARN,
        )
        self.assertEqual(
            aws_convergence["key_operation_path"]["role_arn"],
            AWS_TASK_ROLE_ARN,
        )
        self.assertEqual(
            aws_convergence["access_path"]["bucket_arn"],
            _AWS_BUCKET_ARN,
        )
        self.assertEqual(
            aws_convergence["access_path"]["bucket_address"],
            aws_convergence["encryption_dependency"]["dependent_address"],
        )
        self.assertEqual(
            aws_convergence["key_operation_path"]["key_address"],
            aws_convergence["encryption_dependency"]["key_address"],
        )
        self.assertEqual(
            aws_convergence["encryption_dependency"]["reference_kind"],
            "alias_arn",
        )
        self.assertEqual(
            aws_convergence["encryption_dependency"]["alias_address"],
            "aws_kms_alias.data",
        )

        gcp_inventory = _normalize(GcpNormalizer(), _gcp_resources())
        gcp_convergence = gcp_facts(_resource(gcp_inventory, _GCP_WORKLOAD)).cloud_run_gcs_protected_data_convergences[
            0
        ]
        self.assertEqual(
            gcp_convergence["access_path"]["service_account_member"],
            GCP_SERVICE_ACCOUNT_MEMBER,
        )
        self.assertEqual(
            gcp_convergence["key_operation_path"]["service_account_member"],
            GCP_SERVICE_ACCOUNT_MEMBER,
        )
        self.assertEqual(
            gcp_convergence["access_path"]["bucket_address"],
            gcp_convergence["encryption_dependency"]["dependent_address"],
        )
        self.assertEqual(
            gcp_convergence["key_operation_path"]["key_address"],
            gcp_convergence["encryption_dependency"]["key_address"],
        )
        self.assertEqual(
            gcp_convergence["key_resource_name"],
            _GCP_KEY_PATH,
        )
        self.assertEqual(
            gcp_convergence["key_operation_path"]["scope_type"],
            "crypto_key",
        )
        self.assertIs(
            gcp_convergence["key_operation_path"]["iam_scope_is_key_version"],
            False,
        )

        azure_inventory = _normalize(AzureNormalizer(), _azure_resources())
        azure_convergences = azure_facts(
            _resource(azure_inventory, _AZURE_WORKLOAD)
        ).app_service_storage_protected_data_convergences
        self.assertEqual(
            {convergence["operation"] for convergence in azure_convergences},
            {"decrypt", "unwrap"},
        )
        for convergence in azure_convergences:
            self.assertEqual(
                convergence["access_path"]["principal_id"],
                _AZURE_RUNTIME_PRINCIPAL_ID,
            )
            self.assertEqual(
                convergence["key_operation_path"]["principal_id"],
                _AZURE_RUNTIME_PRINCIPAL_ID,
            )
            self.assertEqual(
                convergence["storage_resource_address"],
                _AZURE_DEPENDENT,
            )
            self.assertEqual(
                convergence["storage_account_address"],
                "azurerm_storage_account.orders",
            )
            self.assertEqual(
                convergence["encryption_dependency"]["dependent_address"],
                "azurerm_storage_account.orders",
            )
            self.assertEqual(
                convergence["encryption_dependency"]["target_kind"],
                "key_version",
            )
            self.assertEqual(convergence["key_uri"], _AZURE_KEY_URI)
            self.assertEqual(
                convergence["key_versionless_uri"],
                _AZURE_KEY_VERSIONLESS_URI,
            )

    def test_exact_key_or_runtime_identity_mismatch_never_enriches_a_finding(
        self,
    ) -> None:
        cases = (
            (
                "aws-key",
                "aws",
                AwsNormalizer(),
                _aws_exact_key_mismatch_resources(),
                AWS_DECRYPT_RULE,
                _AWS_DEPENDENT,
            ),
            (
                "gcp-key",
                "gcp",
                GcpNormalizer(),
                _gcp_exact_key_mismatch_resources(),
                GCP_DECRYPT_RULE,
                _GCP_DEPENDENT,
            ),
            (
                "azure-key",
                "azure",
                AzureNormalizer(),
                _azure_exact_key_mismatch_resources(),
                AZURE_DECRYPT_RULE,
                _AZURE_DEPENDENT,
            ),
            (
                "azure-runtime-identity",
                "azure",
                AzureNormalizer(),
                _azure_dual_identity_resources(),
                AZURE_DECRYPT_RULE,
                _AZURE_DEPENDENT,
            ),
        )

        for (
            name,
            provider,
            normalizer,
            resources,
            expected_rule,
            dependent_address,
        ) in cases:
            with self.subTest(case=name):
                inventory = _normalize(normalizer, resources)
                convergence, _uncertainties = _convergence_evidence(
                    provider,
                    inventory,
                )
                finding = _single_local_finding(inventory, expected_rule)

                self.assertEqual(convergence, [])
                self.assertNotIn(
                    dependent_address,
                    finding.affected_resources,
                )
                self.assertEqual(
                    _evidence(finding)["downstream_dependencies"][0],
                    _UNRESOLVED_SUMMARY,
                )

    def test_conditional_or_ambiguous_evidence_remains_visible_without_convergence(
        self,
    ) -> None:
        conditional_cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(s3_condition={"StringEquals": {"s3:ExistingObjectTag/classification": "protected"}}),
                AWS_DECRYPT_RULE,
                _AWS_DEPENDENT,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    bucket_condition={
                        "title": "runtime-window",
                        "expression": ("request.time < timestamp('2030-01-01T00:00:00Z')"),
                    }
                ),
                GCP_DECRYPT_RULE,
                _GCP_DEPENDENT,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(
                    storage_condition=("@Resource[Microsoft.Storage/storageAccounts:name] StringEquals 'orders'")
                ),
                AZURE_DECRYPT_RULE,
                _AZURE_DEPENDENT,
            ),
        )
        ambiguous_cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(ambiguous_dependency=True),
                AWS_DECRYPT_RULE,
                _AWS_DEPENDENT,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(ambiguous_dependency=True),
                GCP_DECRYPT_RULE,
                _GCP_DEPENDENT,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(ambiguous_dependency=True),
                AZURE_DECRYPT_RULE,
                _AZURE_DEPENDENT,
            ),
        )

        for evidence_kind, cases in (
            ("conditional_access", conditional_cases),
            ("ambiguous_dependency", ambiguous_cases),
        ):
            for (
                provider,
                normalizer,
                resources,
                expected_rule,
                dependent_address,
            ) in cases:
                with self.subTest(
                    evidence_kind=evidence_kind,
                    provider=provider,
                ):
                    inventory = _normalize(normalizer, resources)
                    convergences, uncertainties = _convergence_evidence(
                        provider,
                        inventory,
                    )
                    finding = _single_local_finding(
                        inventory,
                        expected_rule,
                    )

                    self.assertEqual(convergences, [])
                    self.assertTrue(uncertainties)
                    finding_uncertainties = _finding_convergence_uncertainties(
                        provider,
                        finding,
                    )
                    self.assertTrue(finding_uncertainties)
                    self.assertEqual(
                        set(finding_uncertainties),
                        set(uncertainties),
                    )
                    self.assertNotIn(
                        dependent_address,
                        finding.affected_resources,
                    )
                    self.assertEqual(
                        _evidence(finding)["downstream_dependencies"][0],
                        _UNRESOLVED_SUMMARY,
                    )

    def test_native_proof_multiplicity_deduplicates_logical_dependency_counts(
        self,
    ) -> None:
        gcp_resources = _gcp_resources()
        gcp_resources.append(
            gcp_project_member(
                "additional_project_decrypter",
                "roles/cloudkms.cryptoKeyDecrypter",
            )
        )
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(),
                AWS_DECRYPT_RULE,
                _AWS_DEPENDENT,
            ),
            (
                "gcp",
                GcpNormalizer(),
                gcp_resources,
                GCP_DECRYPT_RULE,
                _GCP_DEPENDENT,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(),
                AZURE_DECRYPT_RULE,
                _AZURE_DEPENDENT,
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            expected_rule,
            dependent_address,
        ) in cases:
            with self.subTest(provider=provider):
                inventory = _normalize(normalizer, resources)
                finding = _single_local_finding(inventory, expected_rule)
                convergences, _uncertainties = _convergence_evidence(
                    provider,
                    inventory,
                )
                downstream = _evidence(finding)["downstream_dependencies"]

                self.assertIn(dependent_address, finding.affected_resources)
                self.assertEqual(downstream[0], _RESOLVED_SUMMARY)
                if provider == "aws":
                    self.assertEqual(len(convergences), 1)
                    self.assertEqual(
                        convergences[0]["encryption_dependency"]["reference_kind"],
                        "alias_arn",
                    )
                elif provider == "gcp":
                    self.assertEqual(len(convergences), 2)
                    self.assertEqual(
                        {convergence["key_operation_path"]["scope_type"] for convergence in convergences},
                        {"project", "crypto_key"},
                    )
                    self.assertTrue(any("authorization_proof_count=2" in value for value in downstream))
                else:
                    self.assertEqual(len(convergences), 2)
                    self.assertEqual(
                        {convergence["operation"] for convergence in convergences},
                        {"decrypt", "unwrap"},
                    )
                    self.assertTrue(
                        any(
                            "operations=decrypt,unwrap" in value and "authorization_proof_count=1" in value
                            for value in downstream
                        )
                    )

    def test_convergence_and_findings_do_not_leak_across_providers(self) -> None:
        engine = StrideRuleEngine()
        cases = (
            (
                "aws-initial",
                "aws",
                AwsNormalizer(),
                _aws_resources(),
                AWS_DECRYPT_RULE,
                ("google_", "azurerm_"),
            ),
            (
                "gcp-after-aws",
                "gcp",
                GcpNormalizer(),
                _gcp_resources(),
                GCP_DECRYPT_RULE,
                ("aws_", "azurerm_"),
            ),
            (
                "azure-after-gcp",
                "azure",
                AzureNormalizer(),
                _azure_resources(),
                AZURE_DECRYPT_RULE,
                ("aws_", "google_"),
            ),
            (
                "aws-after-provider-switches",
                "aws",
                AwsNormalizer(),
                _aws_resources(),
                AWS_DECRYPT_RULE,
                ("google_", "azurerm_"),
            ),
        )

        for (
            sequence,
            provider,
            normalizer,
            resources,
            expected_rule,
            foreign_prefixes,
        ) in cases:
            with self.subTest(sequence=sequence):
                inventory = _normalize(normalizer, resources)
                convergences, _uncertainties = _convergence_evidence(
                    provider,
                    inventory,
                )
                findings = _evaluate(inventory, engine=engine)
                convergence_payload = json.dumps(
                    convergences,
                    sort_keys=True,
                )

                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [expected_rule],
                )
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))
                finding_payload = _finding_payload(findings[0])
                for foreign_prefix in foreign_prefixes:
                    self.assertNotIn(
                        foreign_prefix,
                        convergence_payload,
                    )
                    self.assertNotIn(foreign_prefix, finding_payload)

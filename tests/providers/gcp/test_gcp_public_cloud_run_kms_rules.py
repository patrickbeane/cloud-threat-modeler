from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _PROJECT,
    _RING,
    _key,
    _key_member,
    _project_member,
    _ring_member,
    _version,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _PUBLIC_INVOKER_ADDRESS,
    _as_resource,
    _evidence,
    _public_cloud_run,
    _public_invoker,
)
from tests.providers.test_protected_data_key_authority_convergence import (
    _GCP_KEY_PATH,
    GCP_BUCKET_ADDRESS,
    GCP_SERVICE_ACCOUNT_MEMBER,
    _gcp_resources,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_DECRYPT_RULE = "gcp-public-cloud-run-kms-decrypt-access"
_SIGN_RULE = "gcp-public-cloud-run-kms-signing-access"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_DECRYPT_KEY_ADDRESS = "google_kms_crypto_key.data"
_SIGN_KEY_ADDRESS = "google_kms_crypto_key.signing"
_DECRYPT_IAM_ADDRESS = "google_project_iam_member.runtime_decrypter"


def _with_second_cmek_bucket(
    resources: list[TerraformResource],
) -> list[TerraformResource]:
    resources.extend(
        [
            _terraform_resource(
                "google_storage_bucket.archive",
                GcpResourceType.STORAGE_BUCKET,
                {
                    "id": "tfstride-archive-data",
                    "name": "tfstride-archive-data",
                    "project": "tfstride-demo",
                    "location": "US",
                    "encryption": [{"default_kms_key_name": _GCP_KEY_PATH}],
                },
            ),
            _terraform_resource(
                "google_storage_bucket_iam_member.archive_access",
                GcpResourceType.STORAGE_BUCKET_IAM_MEMBER,
                {
                    "bucket": "google_storage_bucket.archive.name",
                    "role": "roles/storage.objectViewer",
                    "member": GCP_SERVICE_ACCOUNT_MEMBER,
                },
            ),
        ]
    )
    return resources


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    return StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


class GcpPublicCloudRunKmsOperationRuleTests(unittest.TestCase):
    def test_rules_are_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_DECRYPT_RULE, registered)
        self.assertIn(_SIGN_RULE, registered)

    def test_public_project_decrypt_is_reported_with_broader_blast_radius(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_key("data", "ENCRYPT_DECRYPT")),
                _as_resource(_key("secondary", "ENCRYPT_DECRYPT")),
                _as_resource(_version("data", "GOOGLE_SYMMETRIC_ENCRYPTION")),
                _as_resource(_project_member("runtime_decrypter", "roles/cloudkms.cryptoKeyDecrypter")),
            ],
            _DECRYPT_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DECRYPT_RULE])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.INFORMATION_DISCLOSURE)
        self.assertEqual(
            finding.affected_resources,
            [
                _WORKLOAD_ADDRESS,
                _PUBLIC_INVOKER_ADDRESS,
                _DECRYPT_KEY_ADDRESS,
                "google_kms_crypto_key.secondary",
                _DECRYPT_IAM_ADDRESS,
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            f"internet-to-service:internet->{_WORKLOAD_ADDRESS}",
        )
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)
        self.assertEqual(finding.severity_reasoning.data_sensitivity, 2)
        self.assertIn("deterministic Cloud KMS decrypt authority", finding.rationale)
        self.assertIn("information-disclosure potential", finding.rationale)
        self.assertIn("project-applicable", finding.rationale)

        evidence = _evidence(finding)
        self.assertEqual(
            evidence["public_invoker_bindings"],
            [f"source={_PUBLIC_INVOKER_ADDRESS}; role=roles/run.invoker; member=allUsers; condition=none"],
        )
        self.assertIn("operation_class=decrypt", evidence["kms_operation_paths"][0])
        self.assertIn("scope_type=project", evidence["kms_operation_paths"][0])
        self.assertIn(f"scope={_PROJECT}", evidence["kms_operation_paths"][0])
        self.assertEqual(
            evidence["scope_breadth"],
            [
                "project_grants=1; key_ring_grants=0; exact_key_grants=0; "
                "modeled_keys=2; blast_radius_basis=project_applicable_grant"
            ],
        )
        self.assertIn("iam_scope_is_key_version=false", evidence["authorization_scope"][1])

    def test_public_decrypt_enriches_blast_radius_with_cmek_bucket(self) -> None:
        findings = _evaluate(_gcp_resources(), _DECRYPT_RULE)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertIn(GCP_BUCKET_ADDRESS, finding.affected_resources)
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.blast_radius, 1)

        evidence = _evidence(finding)
        self.assertEqual(
            evidence["downstream_dependencies"][0],
            "unique_dependency_count=1; unique_dependent_resource_count=1; "
            "downstream_dependency_state=resolved_dependents",
        )
        self.assertIn(
            f"bucket_address={GCP_BUCKET_ADDRESS}",
            evidence["downstream_dependencies"][1],
        )
        self.assertIn(
            "key_address=google_kms_crypto_key.data",
            evidence["downstream_dependencies"][1],
        )
        self.assertIn(
            "authorization_proof_count=1",
            evidence["downstream_dependencies"][1],
        )
        self.assertIn(
            "unique KMS-protected GCS bucket(s) across 1 unique encryption dependency relationship(s)",
            finding.rationale,
        )

    def test_duplicate_iam_proofs_collapse_to_one_logical_dependency(self) -> None:
        resources = _gcp_resources()
        resources.append(
            _project_member(
                "additional_project_decrypter",
                "roles/cloudkms.cryptoKeyDecrypter",
            )
        )

        findings = _evaluate(resources, _DECRYPT_RULE)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)

        evidence = _evidence(finding)
        self.assertEqual(
            evidence["downstream_dependencies"][0],
            "unique_dependency_count=1; unique_dependent_resource_count=1; "
            "downstream_dependency_state=resolved_dependents",
        )
        self.assertIn(
            "authorization_proof_count=2",
            evidence["downstream_dependencies"][1],
        )
        self.assertIn(
            "crypto_key:",
            evidence["downstream_dependencies"][1],
        )
        self.assertIn(
            "project:tfstride-demo",
            evidence["downstream_dependencies"][1],
        )
        self.assertIn(
            "unique KMS-protected GCS bucket(s) across 1 unique encryption dependency relationship(s)",
            finding.rationale,
        )

    def test_multiple_cmek_buckets_raise_downstream_blast_radius(self) -> None:
        findings = _evaluate(
            _with_second_cmek_bucket(_gcp_resources()),
            _DECRYPT_RULE,
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertIn(
            "google_storage_bucket.orders",
            finding.affected_resources,
        )
        self.assertIn(
            "google_storage_bucket.archive",
            finding.affected_resources,
        )
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)

        evidence = _evidence(finding)
        self.assertEqual(
            evidence["downstream_dependencies"][0],
            "unique_dependency_count=2; unique_dependent_resource_count=2; "
            "downstream_dependency_state=resolved_dependents",
        )

    def test_public_exact_key_signing_is_reported_with_narrower_blast_radius(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_key("signing", "ASYMMETRIC_SIGN")),
                _as_resource(_version("signing", "EC_SIGN_P256_SHA256")),
                _as_resource(_key_member("runtime_signer", "signing", "roles/cloudkms.signer")),
            ],
            _SIGN_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_SIGN_RULE])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.SPOOFING)
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.blast_radius, 1)
        self.assertEqual(finding.severity_reasoning.data_sensitivity, 1)
        self.assertIn("deterministic Cloud KMS sign authority", finding.rationale)
        self.assertIn("spoofing potential", finding.rationale)

        evidence = _evidence(finding)
        self.assertIn("operation_class=sign", evidence["kms_operation_paths"][0])
        self.assertIn("scope_type=crypto_key", evidence["kms_operation_paths"][0])
        self.assertIn(f"scope={_RING}/cryptoKeys/signing", evidence["kms_operation_paths"][0])
        self.assertEqual(
            evidence["scope_breadth"],
            [
                "project_grants=0; key_ring_grants=0; exact_key_grants=1; modeled_keys=1; blast_radius_basis=key_ring_or_exact_key_grant"
            ],
        )

    def test_public_key_ring_decrypt_is_narrower_than_project_grant(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_key("data", "ENCRYPT_DECRYPT")),
                _as_resource(_key("secondary", "ENCRYPT_DECRYPT")),
                _as_resource(_ring_member("ring_decrypter", "roles/cloudkms.cryptoKeyDecrypter")),
            ],
            _DECRYPT_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DECRYPT_RULE])
        finding = findings[0]
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.blast_radius, 1)
        evidence = _evidence(finding)
        self.assertIn("scope_type=key_ring", evidence["kms_operation_paths"][0])
        self.assertIn(f"scope={_RING}", evidence["kms_operation_paths"][0])
        self.assertEqual(
            evidence["scope_breadth"],
            [
                "project_grants=0; key_ring_grants=1; exact_key_grants=0; "
                "modeled_keys=2; blast_radius_basis=key_ring_or_exact_key_grant"
            ],
        )

    def test_private_cloud_run_does_not_emit_public_kms_finding(self) -> None:
        self.assertEqual(
            _evaluate(
                [
                    _public_cloud_run(public_ingress=False),
                    _public_invoker(),
                    _as_resource(_key("data", "ENCRYPT_DECRYPT")),
                    _as_resource(_project_member("runtime_decrypter", "roles/cloudkms.cryptoKeyDecrypter")),
                ],
                _DECRYPT_RULE,
            ),
            [],
        )

    def test_conditional_kms_grant_does_not_emit_public_finding(self) -> None:
        self.assertEqual(
            _evaluate(
                [
                    _public_cloud_run(),
                    _public_invoker(),
                    _as_resource(_key("data", "ENCRYPT_DECRYPT")),
                    _as_resource(
                        _key_member(
                            "runtime_decrypter",
                            "data",
                            "roles/cloudkms.cryptoKeyDecrypter",
                            condition={
                                "title": "business-hours",
                                "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
                            },
                        )
                    ),
                ],
                _DECRYPT_RULE,
            ),
            [],
        )

    def test_mac_generation_emits_spoofing_finding(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_key("mac", "MAC")),
                _as_resource(_key_member("runtime_mac_signer", "mac", "roles/cloudkms.signer")),
            ],
            _SIGN_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_SIGN_RULE])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.SPOOFING)
        self.assertIn("deterministic Cloud KMS MAC-generation authority", finding.rationale)
        self.assertIn("message authentication codes", finding.rationale)
        evidence = _evidence(finding)
        self.assertIn("key_purpose=MAC", evidence["kms_operation_paths"][0])
        self.assertIn("operation_class=mac_generation", evidence["kms_operation_paths"][0])

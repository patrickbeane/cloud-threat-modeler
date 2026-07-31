from __future__ import annotations

import unittest
from collections.abc import Iterable
from typing import Any

from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _KEY_ARNS as AWS_KEY_ARNS,
)
from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _TASK_ROLE_ARN as AWS_TASK_ROLE_ARN,
)
from tests.providers.aws.test_aws_ecs_kms_operation_paths import _key as aws_key
from tests.providers.aws.test_aws_ecs_kms_operation_paths import _policy as aws_policy
from tests.providers.aws.test_aws_ecs_kms_operation_paths import _role as aws_role
from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _statement as aws_statement,
)
from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _task_definition as aws_task_definition,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _public_edge as aws_public_edge,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _service as aws_service,
)
from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _SERVICE_ENCRYPTION_USER_ID as AZURE_SERVICE_ENCRYPTION_USER_ID,
)
from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _SYSTEM_PRINCIPAL_ID as AZURE_SYSTEM_PRINCIPAL_ID,
)
from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _access_policy as azure_access_policy,
)
from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _key as azure_key,
)
from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _role_assignment as azure_role_assignment,
)
from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _vault as azure_vault,
)
from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _web_app as azure_web_app,
)
from tests.providers.azure.test_azure_public_app_service_storage_mutation_rules import (
    _public as azure_public,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _cloud_run as gcp_cloud_run,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import _key as gcp_key
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _key_binding as gcp_key_binding,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _key_member as gcp_key_member,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _project_member as gcp_project_member,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _public_invoker as gcp_public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, StrideCategory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_DECRYPT_RULE = "aws-public-ecs-kms-decrypt-access"
AWS_SIGNING_RULE = "aws-public-ecs-kms-signing-access"
GCP_DECRYPT_RULE = "gcp-public-cloud-run-kms-decrypt-access"
GCP_SIGNING_RULE = "gcp-public-cloud-run-kms-signing-access"
AZURE_DECRYPT_RULE = "azure-public-app-service-key-vault-decrypt-access"
AZURE_SIGNING_RULE = "azure-public-app-service-key-vault-signing-access"
_RULE_IDS = frozenset(
    {
        AWS_DECRYPT_RULE,
        AWS_SIGNING_RULE,
        GCP_DECRYPT_RULE,
        GCP_SIGNING_RULE,
        AZURE_DECRYPT_RULE,
        AZURE_SIGNING_RULE,
    }
)


def _flatten(groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for group in groups for rule_id in group)


def _evaluate(
    normalizer: ProviderNormalizer,
    resources: list[TerraformResource],
) -> list[Finding]:
    inventory = normalizer.normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=_RULE_IDS),
    )


def _evidence(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


def _assert_evidence_fragments(
    test: unittest.TestCase,
    finding: Finding,
    key: str,
    fragments: Iterable[str],
) -> None:
    values = _evidence(finding)[key]
    for fragment in fragments:
        test.assertTrue(
            any(fragment in value for value in values),
            f"{fragment!r} missing from {key}: {values!r}",
        )


def _aws_resources(
    operations: tuple[tuple[str, str, str], ...],
    *,
    public: bool = True,
    condition: bool = False,
    deny: bool = False,
    incomplete_policy: bool = False,
    runtime_identity: bool = True,
) -> list[TerraformResource]:
    keys: list[TerraformResource] = []
    role_statements: list[dict[str, Any]] = []
    for name, usage, operation in operations:
        allow = aws_statement(
            "Allow",
            operation,
            "*",
            principal=AWS_TASK_ROLE_ARN,
        )
        if condition:
            allow["Condition"] = {"StringEquals": {"kms:EncryptionContext:service": "orders"}}
        policy_statements = [allow]
        if deny:
            policy_statements.append(
                aws_statement(
                    "Deny",
                    operation,
                    "*",
                    principal=AWS_TASK_ROLE_ARN,
                )
            )
        key = aws_key(name, usage, aws_policy(*policy_statements))
        if incomplete_policy:
            key.unknown_values["policy"] = True
        keys.append(key)
        role_statements.append(
            aws_statement(
                "Allow",
                operation,
                AWS_KEY_ARNS[name],
                principal=AWS_TASK_ROLE_ARN,
            )
        )

    task_definition = aws_task_definition()
    if not runtime_identity:
        task_definition.values["task_role_arn"] = None
        task_definition.unknown_values["task_role_arn"] = True
    return [
        *aws_public_edge(internal=not public),
        *keys,
        aws_role("orders_task", AWS_TASK_ROLE_ARN, role_statements),
        task_definition,
        aws_service(),
    ]


def _gcp_workload(*, public: bool, runtime_identity: bool) -> TerraformResource:
    workload = gcp_cloud_run(public=public)
    if not runtime_identity:
        workload.values["template"] = [{"service_account": None}]
        workload.unknown_values["template"] = [{"service_account": True}]
    return workload


def _gcp_key_resources(
    name: str,
    purpose: str,
    role: str,
    *,
    public: bool = True,
    condition: bool = False,
    ambiguous: bool = False,
    runtime_identity: bool = True,
) -> list[TerraformResource]:
    condition_value = None
    if condition:
        condition_value = {
            "title": "runtime-window",
            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
        }
    resources = [
        _gcp_workload(public=public, runtime_identity=runtime_identity),
        gcp_public_invoker(),
        gcp_key(name, purpose),
        gcp_key_member(
            f"runtime_{name}",
            name,
            role,
            condition=condition_value,
        ),
    ]
    if ambiguous:
        resources.append(
            gcp_key_binding(
                f"runtime_{name}_binding",
                name,
                role,
            )
        )
    return resources


def _gcp_broad_resources(*, public: bool = True) -> list[TerraformResource]:
    return [
        _gcp_workload(public=public, runtime_identity=True),
        gcp_public_invoker(),
        gcp_key("data", "ENCRYPT_DECRYPT"),
        gcp_key("signing", "ASYMMETRIC_SIGN"),
        gcp_key("mac", "MAC"),
        gcp_project_member("runtime_crypto", "roles/cloudkms.cryptoOperator"),
    ]


def _azure_resources(
    key_opts: tuple[str, ...],
    *,
    public: bool = True,
    role_id: str | None = None,
    role_name: str = "Key Vault Crypto User",
    condition: bool = False,
    ambiguous: bool = False,
    runtime_identity: bool = True,
) -> list[TerraformResource]:
    app = azure_web_app()
    if public:
        azure_public(app)
    if not runtime_identity:
        app.values["identity"] = [
            {
                "type": "SystemAssigned",
                "principal_id": None,
                "tenant_id": "tenant-id",
                "identity_ids": [],
            }
        ]
        app.unknown_values["identity"] = [{"principal_id": True}]

    if ambiguous:
        vault = azure_vault(rbac_enabled=False)
        vault.values["access_policy"] = [
            {
                "tenant_id": "tenant-id",
                "object_id": AZURE_SYSTEM_PRINCIPAL_ID,
                "key_permissions": ["Decrypt"],
            }
        ]
        return [
            vault,
            azure_key(key_opts=key_opts),
            app,
            azure_access_policy(
                principal_id=AZURE_SYSTEM_PRINCIPAL_ID,
                key_permissions=("Decrypt",),
            ),
        ]

    assignment_args: dict[str, Any] = {
        "role_name": role_name,
    }
    if role_id is not None:
        assignment_args["role_id"] = role_id
    if condition:
        assignment_args["condition"] = "@Resource[Microsoft.KeyVault/vaults].name StringEquals 'orders'"
    return [
        azure_vault(rbac_enabled=True),
        azure_key(key_opts=key_opts),
        app,
        azure_role_assignment(**assignment_args),
    ]


class PublicWorkloadCryptographicOperationPathParityTests(unittest.TestCase):
    """Pins equivalent threats while retaining provider-native authorization evidence."""

    def test_provider_local_rule_families_are_registered(self) -> None:
        self.assertTrue({AWS_DECRYPT_RULE, AWS_SIGNING_RULE} <= _flatten(AWS_RULE_GROUP_IDS))
        self.assertTrue({GCP_DECRYPT_RULE, GCP_SIGNING_RULE} <= _flatten(GCP_RULE_GROUP_IDS))
        self.assertTrue({AZURE_DECRYPT_RULE, AZURE_SIGNING_RULE} <= _flatten(AZURE_RULE_GROUP_IDS))

    def test_public_plaintext_recovery_authority_emits_information_disclosure(self) -> None:
        cases = (
            (
                "aws-decrypt",
                "aws",
                AwsNormalizer(),
                _aws_resources((("data", "ENCRYPT_DECRYPT", "kms:Decrypt"),)),
                AWS_DECRYPT_RULE,
                "aws_kms_key.data",
                "kms_operation_paths",
                (
                    "operation=kms:Decrypt",
                    "key_arn=arn:aws:kms:",
                    "authorization_bases=key_policy_direct",
                ),
            ),
            (
                "gcp-decrypt",
                "gcp",
                GcpNormalizer(),
                [
                    _gcp_workload(public=True, runtime_identity=True),
                    gcp_public_invoker(),
                    gcp_key("data", "ENCRYPT_DECRYPT"),
                    gcp_project_member(
                        "runtime_decrypter",
                        "roles/cloudkms.cryptoKeyDecrypter",
                    ),
                ],
                GCP_DECRYPT_RULE,
                "google_kms_crypto_key.data",
                "kms_operation_paths",
                (
                    "operation_class=decrypt",
                    "scope_type=project",
                    "grant_basis=project_iam",
                ),
            ),
            (
                "azure-unwrap",
                "azure",
                AzureNormalizer(),
                _azure_resources(
                    ("unwrapKey",),
                    role_id=AZURE_SERVICE_ENCRYPTION_USER_ID,
                    role_name="Key Vault Crypto Service Encryption User",
                ),
                AZURE_DECRYPT_RULE,
                "azurerm_key_vault_key.signing",
                "key_vault_operation_paths",
                (
                    "operation=unwrap",
                    "authorization_model=azure_rbac",
                    "key_versionless_uri=https://orders.vault.azure.net/keys/signing",
                ),
            ),
        )

        for case, provider, normalizer, resources, rule_id, target, evidence_key, fragments in cases:
            with self.subTest(case=case):
                findings = _evaluate(normalizer, resources)
                self.assertEqual([finding.rule_id for finding in findings], [rule_id])
                finding = findings[0]
                self.assertEqual(finding.category, StrideCategory.INFORMATION_DISCLOSURE)
                self.assertIn(target, finding.affected_resources)
                self.assertTrue(finding.rule_id.startswith(f"{provider}-"))
                _assert_evidence_fragments(self, finding, evidence_key, fragments)

    def test_public_authenticator_generation_authority_emits_spoofing(self) -> None:
        cases = (
            (
                "aws-mac",
                "aws",
                AwsNormalizer(),
                _aws_resources((("mac", "GENERATE_VERIFY_MAC", "kms:GenerateMac"),)),
                AWS_SIGNING_RULE,
                "aws_kms_key.mac",
                "kms_operation_paths",
                ("operation=kms:GenerateMac", "key_usage=GENERATE_VERIFY_MAC"),
            ),
            (
                "gcp-mac",
                "gcp",
                GcpNormalizer(),
                _gcp_key_resources(
                    "mac",
                    "MAC",
                    "roles/cloudkms.signer",
                ),
                GCP_SIGNING_RULE,
                "google_kms_crypto_key.mac",
                "kms_operation_paths",
                ("operation_class=mac_generation", "key_purpose=MAC"),
            ),
            (
                "azure-sign",
                "azure",
                AzureNormalizer(),
                _azure_resources(("sign",)),
                AZURE_SIGNING_RULE,
                "azurerm_key_vault_key.signing",
                "key_vault_operation_paths",
                ("operation=sign", "matched_key_operation=sign"),
            ),
        )

        for case, provider, normalizer, resources, rule_id, target, evidence_key, fragments in cases:
            with self.subTest(case=case):
                findings = _evaluate(normalizer, resources)
                self.assertEqual([finding.rule_id for finding in findings], [rule_id])
                finding = findings[0]
                self.assertEqual(finding.category, StrideCategory.SPOOFING)
                self.assertIn(target, finding.affected_resources)
                self.assertTrue(finding.rule_id.startswith(f"{provider}-"))
                _assert_evidence_fragments(self, finding, evidence_key, fragments)

    def test_private_workloads_stay_quiet(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    (
                        ("data", "ENCRYPT_DECRYPT", "kms:Decrypt"),
                        ("signing", "SIGN_VERIFY", "kms:Sign"),
                    ),
                    public=False,
                ),
            ),
            ("gcp", GcpNormalizer(), _gcp_broad_resources(public=False)),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(("decrypt", "unwrapKey", "sign"), public=False),
            ),
        )

        for provider, normalizer, resources in cases:
            with self.subTest(provider=provider):
                self.assertEqual(_evaluate(normalizer, resources), [])

    def test_encrypt_wrap_verify_and_public_key_retrieval_stay_quiet(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    (
                        ("data", "ENCRYPT_DECRYPT", "kms:Encrypt"),
                        ("signing", "SIGN_VERIFY", "kms:Verify"),
                        ("mac", "GENERATE_VERIFY_MAC", "kms:VerifyMac"),
                    )
                ),
            ),
            (
                "gcp",
                GcpNormalizer(),
                [
                    _gcp_workload(public=True, runtime_identity=True),
                    gcp_public_invoker(),
                    gcp_key("data", "ENCRYPT_DECRYPT"),
                    gcp_key("signing", "ASYMMETRIC_SIGN"),
                    gcp_key_member(
                        "runtime_encrypter",
                        "data",
                        "roles/cloudkms.cryptoKeyEncrypter",
                    ),
                    gcp_key_member(
                        "runtime_verifier",
                        "signing",
                        "roles/cloudkms.verifier",
                    ),
                    gcp_key_member(
                        "runtime_public_key_viewer",
                        "signing",
                        "roles/cloudkms.publicKeyViewer",
                    ),
                ],
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(("encrypt", "wrapKey", "verify")),
            ),
        )

        for provider, normalizer, resources in cases:
            with self.subTest(provider=provider):
                self.assertEqual(_evaluate(normalizer, resources), [])

    def test_non_deterministic_or_incompatible_authority_stays_quiet(self) -> None:
        cases = (
            (
                "aws-conditional",
                AwsNormalizer(),
                _aws_resources(
                    (("data", "ENCRYPT_DECRYPT", "kms:Decrypt"),),
                    condition=True,
                ),
            ),
            (
                "aws-denied",
                AwsNormalizer(),
                _aws_resources(
                    (("data", "ENCRYPT_DECRYPT", "kms:Decrypt"),),
                    deny=True,
                ),
            ),
            (
                "aws-incomplete-policy",
                AwsNormalizer(),
                _aws_resources(
                    (("data", "ENCRYPT_DECRYPT", "kms:Decrypt"),),
                    incomplete_policy=True,
                ),
            ),
            (
                "aws-unresolved-identity",
                AwsNormalizer(),
                _aws_resources(
                    (("data", "ENCRYPT_DECRYPT", "kms:Decrypt"),),
                    runtime_identity=False,
                ),
            ),
            (
                "aws-incompatible-key-usage",
                AwsNormalizer(),
                _aws_resources((("data", "ENCRYPT_DECRYPT", "kms:Sign"),)),
            ),
            (
                "gcp-conditional",
                GcpNormalizer(),
                _gcp_key_resources(
                    "data",
                    "ENCRYPT_DECRYPT",
                    "roles/cloudkms.cryptoKeyDecrypter",
                    condition=True,
                ),
            ),
            (
                "gcp-ambiguous-managers",
                GcpNormalizer(),
                _gcp_key_resources(
                    "data",
                    "ENCRYPT_DECRYPT",
                    "roles/cloudkms.cryptoKeyDecrypter",
                    ambiguous=True,
                ),
            ),
            (
                "gcp-unresolved-identity",
                GcpNormalizer(),
                _gcp_key_resources(
                    "data",
                    "ENCRYPT_DECRYPT",
                    "roles/cloudkms.cryptoKeyDecrypter",
                    runtime_identity=False,
                ),
            ),
            (
                "gcp-incompatible-purpose",
                GcpNormalizer(),
                _gcp_key_resources(
                    "data",
                    "ENCRYPT_DECRYPT",
                    "roles/cloudkms.signer",
                ),
            ),
            (
                "azure-conditional",
                AzureNormalizer(),
                _azure_resources(("decrypt",), condition=True),
            ),
            (
                "azure-ambiguous-managers",
                AzureNormalizer(),
                _azure_resources(("decrypt",), ambiguous=True),
            ),
            (
                "azure-unresolved-identity",
                AzureNormalizer(),
                _azure_resources(("decrypt",), runtime_identity=False),
            ),
            (
                "azure-incompatible-key-options",
                AzureNormalizer(),
                _azure_resources(("encrypt",)),
            ),
        )

        for case, normalizer, resources in cases:
            with self.subTest(case=case):
                self.assertEqual(_evaluate(normalizer, resources), [])

    def test_broad_crypto_operators_can_emit_both_threat_categories(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    (
                        ("data", "ENCRYPT_DECRYPT", "kms:Decrypt"),
                        ("signing", "SIGN_VERIFY", "kms:Sign"),
                        ("mac", "GENERATE_VERIFY_MAC", "kms:GenerateMac"),
                    )
                ),
                {AWS_DECRYPT_RULE, AWS_SIGNING_RULE},
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_broad_resources(),
                {GCP_DECRYPT_RULE, GCP_SIGNING_RULE},
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(("decrypt", "unwrapKey", "sign")),
                {AZURE_DECRYPT_RULE, AZURE_SIGNING_RULE},
            ),
        )

        for provider, normalizer, resources, expected_rules in cases:
            with self.subTest(provider=provider):
                findings = _evaluate(normalizer, resources)
                self.assertEqual({finding.rule_id for finding in findings}, expected_rules)
                self.assertEqual(
                    {finding.category for finding in findings},
                    {
                        StrideCategory.INFORMATION_DISCLOSURE,
                        StrideCategory.SPOOFING,
                    },
                )
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))


if __name__ == "__main__":
    unittest.main()

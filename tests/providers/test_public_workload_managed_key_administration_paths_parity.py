from __future__ import annotations

import unittest
from collections.abc import Iterable

from tests.providers.aws.test_aws_ecs_kms_management_paths import (
    _unresolved_attachment as aws_unresolved_attachment,
)
from tests.providers.aws.test_aws_ecs_kms_management_paths import (
    _with_lifecycle as aws_with_lifecycle,
)
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
from tests.providers.azure.test_azure_app_service_key_vault_management_paths import (
    _CRYPTO_OFFICER_ID as AZURE_CRYPTO_OFFICER_ID,
)
from tests.providers.azure.test_azure_app_service_key_vault_management_paths import (
    _control_assignment as azure_control_assignment,
)
from tests.providers.azure.test_azure_app_service_key_vault_management_paths import (
    _control_role as azure_control_role,
)
from tests.providers.azure.test_azure_app_service_key_vault_management_paths import (
    _crypto_officer_assignment as azure_crypto_officer_assignment,
)
from tests.providers.azure.test_azure_app_service_key_vault_management_paths import (
    _vault_with_recovery as azure_vault_with_recovery,
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
    _web_app as azure_web_app,
)
from tests.providers.azure.test_azure_public_app_service_storage_mutation_rules import (
    _public as azure_public,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _PROJECT as GCP_PROJECT,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _cloud_run as gcp_cloud_run,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _custom_role as gcp_custom_role,
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
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _version as gcp_version,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _public_invoker as gcp_public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, ResourceInventory, StrideCategory, TerraformResource
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

AWS_DISRUPTION_RULE = "aws-public-ecs-kms-key-disruption"
AWS_DELEGATION_RULE = "aws-public-ecs-kms-authorization-delegation"
GCP_DISRUPTION_RULE = "gcp-public-cloud-run-kms-key-disruption"
GCP_DELEGATION_RULE = "gcp-public-cloud-run-kms-authorization-delegation"
AZURE_DISRUPTION_RULE = "azure-public-app-service-key-vault-key-disruption"
AZURE_DELEGATION_RULE = "azure-public-app-service-key-vault-authorization-delegation"
_RULE_IDS = frozenset(
    {
        AWS_DISRUPTION_RULE,
        AWS_DELEGATION_RULE,
        GCP_DISRUPTION_RULE,
        GCP_DELEGATION_RULE,
        AZURE_DISRUPTION_RULE,
        AZURE_DELEGATION_RULE,
    }
)
_AZURE_ROLE_ASSIGNMENTS_WRITE = "Microsoft.Authorization/roleAssignments/write"


def _flatten(groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for group in groups for rule_id in group)


def _analyze(
    normalizer: ProviderNormalizer,
    resources: list[TerraformResource],
) -> tuple[ResourceInventory, list[Finding]]:
    inventory = normalizer.normalize(resources)
    findings = StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=_RULE_IDS),
    )
    return inventory, findings


def _evaluate(
    normalizer: ProviderNormalizer,
    resources: list[TerraformResource],
) -> list[Finding]:
    return _analyze(normalizer, resources)[1]


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
    operations: tuple[str, ...],
    *,
    public: bool = True,
    condition: bool = False,
    deny: bool = False,
    incomplete_policy: bool = False,
    unresolved_policy: bool = False,
    runtime_identity: bool = True,
    origin: str = "AWS_KMS",
) -> list[TerraformResource]:
    allow = aws_statement(
        "Allow",
        list(operations),
        "*",
        principal=AWS_TASK_ROLE_ARN,
    )
    if condition:
        allow["Condition"] = {
            "StringEquals": {
                "aws:PrincipalTag/environment": "production",
            }
        }
    key_statements = [allow]
    if deny:
        key_statements.append(
            aws_statement(
                "Deny",
                list(operations),
                "*",
                principal=AWS_TASK_ROLE_ARN,
            )
        )
    key = aws_with_lifecycle(
        aws_key(
            "data",
            "ENCRYPT_DECRYPT",
            aws_policy(*key_statements),
        ),
        origin=origin,
    )
    if incomplete_policy:
        key.unknown_values["policy"] = True

    task_definition = aws_task_definition()
    if not runtime_identity:
        task_definition.values["task_role_arn"] = None
        task_definition.unknown_values["task_role_arn"] = True

    resources = [
        *aws_public_edge(internal=not public),
        key,
        aws_role(
            "orders_task",
            AWS_TASK_ROLE_ARN,
            [
                aws_statement(
                    "Allow",
                    list(operations),
                    AWS_KEY_ARNS["data"],
                    principal=AWS_TASK_ROLE_ARN,
                )
            ],
        ),
        task_definition,
        aws_service(),
    ]
    if unresolved_policy:
        resources.append(aws_unresolved_attachment())
    return resources


def _gcp_role_name(name: str) -> str:
    return f"projects/{GCP_PROJECT}/roles/{name}Crypto"


def _gcp_resources(
    permissions: tuple[str, ...],
    *,
    public: bool = True,
    scope_type: str = "crypto_key",
    condition: bool = False,
    ambiguous: bool = False,
    incomplete_role: bool = False,
    runtime_identity: bool = True,
    version_state: str = "ENABLED",
    unresolved_version: bool = False,
) -> list[TerraformResource]:
    workload = gcp_cloud_run(public=public)
    if not runtime_identity:
        workload.values["template"] = [{"service_account": None}]
        workload.unknown_values["template"] = [{"service_account": True}]

    key = gcp_key("data", "ENCRYPT_DECRYPT")
    key.values["destroy_scheduled_duration"] = "604800s"
    version = gcp_version(
        "data",
        "GOOGLE_SYMMETRIC_ENCRYPTION",
        state=version_state,
    )
    version.values["deletion_policy"] = "ABANDON"
    if unresolved_version:
        for field in ("crypto_key", "id", "name"):
            version.values[field] = None
            version.unknown_values[field] = True

    role_name = "runtime_admin"
    role = gcp_custom_role(role_name, list(permissions))
    if incomplete_role:
        role.unknown_values["permissions"] = True
    condition_value = None
    if condition:
        condition_value = {
            "title": "maintenance-window",
            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
        }

    if scope_type == "project":
        grant = gcp_project_member(
            "runtime_admin",
            _gcp_role_name(role_name),
            condition=condition_value,
        )
    else:
        grant = gcp_key_member(
            "runtime_admin",
            "data",
            _gcp_role_name(role_name),
            condition=condition_value,
        )

    resources = [
        workload,
        gcp_public_invoker(),
        key,
        version,
        role,
        grant,
    ]
    if ambiguous:
        resources.append(
            gcp_key_binding(
                "runtime_admin_binding",
                "data",
                _gcp_role_name(role_name),
            )
        )
    return resources


def _gcp_broad_resources(*, public: bool = True) -> list[TerraformResource]:
    key = gcp_key("data", "ENCRYPT_DECRYPT")
    key.values["destroy_scheduled_duration"] = "604800s"
    version = gcp_version(
        "data",
        "GOOGLE_SYMMETRIC_ENCRYPTION",
        state="ENABLED",
    )
    version.values["deletion_policy"] = "ABANDON"
    return [
        gcp_cloud_run(public=public),
        gcp_public_invoker(),
        key,
        version,
        gcp_project_member("runtime_admin", "roles/cloudkms.admin"),
    ]


def _azure_workload(*, public: bool, runtime_identity: bool) -> TerraformResource:
    workload = azure_web_app()
    if public:
        azure_public(workload)
    if not runtime_identity:
        workload.values["identity"] = [
            {
                "type": "SystemAssigned",
                "principal_id": None,
                "tenant_id": "tenant-id",
                "identity_ids": [],
            }
        ]
        workload.unknown_values["identity"] = [{"principal_id": True}]
    return workload


def _azure_disruption_resources(
    *,
    public: bool = True,
    condition: bool = False,
    ambiguous: bool = False,
    runtime_identity: bool = True,
    purge_protection: bool = False,
) -> list[TerraformResource]:
    workload = _azure_workload(
        public=public,
        runtime_identity=runtime_identity,
    )
    if ambiguous:
        vault = azure_vault_with_recovery(
            rbac_enabled=False,
            purge_protection=purge_protection,
        )
        permissions = ["Delete"]
        vault.values["access_policy"] = [
            {
                "tenant_id": "tenant-id",
                "object_id": AZURE_SYSTEM_PRINCIPAL_ID,
                "key_permissions": permissions,
            }
        ]
        return [
            vault,
            azure_key(key_opts=("encrypt",)),
            workload,
            azure_access_policy(
                principal_id=AZURE_SYSTEM_PRINCIPAL_ID,
                key_permissions=tuple(permissions),
            ),
        ]

    assignment = (
        azure_role_assignment(
            principal_id=AZURE_SYSTEM_PRINCIPAL_ID,
            scope="azurerm_key_vault.orders.id",
            role_id=AZURE_CRYPTO_OFFICER_ID,
            role_name="Key Vault Crypto Officer",
            condition=("@Resource[Microsoft.KeyVault/vaults].name StringEquals 'orders'" if condition else None),
        )
        if condition
        else azure_crypto_officer_assignment(scope="/subscriptions/sub-0001")
    )
    return [
        azure_vault_with_recovery(
            rbac_enabled=True,
            purge_protection=purge_protection,
        ),
        azure_key(key_opts=("encrypt",)),
        workload,
        assignment,
    ]


def _azure_delegation_resources(
    *,
    public: bool = True,
    condition: bool = False,
    denied: bool = False,
    incomplete_role: bool = False,
    runtime_identity: bool = True,
) -> list[TerraformResource]:
    return [
        azure_vault_with_recovery(
            rbac_enabled=True,
            purge_protection=False,
        ),
        _azure_workload(
            public=public,
            runtime_identity=runtime_identity,
        ),
        azure_control_role(
            actions=(_AZURE_ROLE_ASSIGNMENTS_WRITE,),
            not_actions=(_AZURE_ROLE_ASSIGNMENTS_WRITE,) if denied else (),
            unknown_permissions=incomplete_role,
        ),
        azure_control_assignment(
            condition=(
                "@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] StringEquals 'allowed-role'"
                if condition
                else None
            )
        ),
    ]


def _azure_broad_resources(*, public: bool = True) -> list[TerraformResource]:
    return [
        azure_vault_with_recovery(
            rbac_enabled=True,
            purge_protection=False,
        ),
        azure_key(key_opts=("encrypt",)),
        _azure_workload(public=public, runtime_identity=True),
        azure_crypto_officer_assignment(scope="/subscriptions/sub-0001"),
        azure_control_role(actions=(_AZURE_ROLE_ASSIGNMENTS_WRITE,)),
        azure_control_assignment(),
    ]


class PublicWorkloadManagedKeyAdministrationPathParityTests(unittest.TestCase):
    """Pins equivalent threats while retaining provider-native management models."""

    def test_provider_local_rule_families_are_registered(self) -> None:
        self.assertTrue({AWS_DISRUPTION_RULE, AWS_DELEGATION_RULE} <= _flatten(AWS_RULE_GROUP_IDS))
        self.assertTrue({GCP_DISRUPTION_RULE, GCP_DELEGATION_RULE} <= _flatten(GCP_RULE_GROUP_IDS))
        self.assertTrue({AZURE_DISRUPTION_RULE, AZURE_DELEGATION_RULE} <= _flatten(AZURE_RULE_GROUP_IDS))

    def test_public_deterministic_disruption_authority_emits_denial_of_service(
        self,
    ) -> None:
        cases = (
            (
                "aws-scheduled-deletion",
                "aws",
                AwsNormalizer(),
                _aws_resources(("kms:ScheduleKeyDeletion",)),
                AWS_DISRUPTION_RULE,
                "aws_kms_key.data",
                "kms_management_paths",
                ("operation=kms:ScheduleKeyDeletion", "key_arn=arn:aws:kms:"),
            ),
            (
                "gcp-version-destroy",
                "gcp",
                GcpNormalizer(),
                _gcp_resources(("cloudkms.cryptoKeyVersions.destroy",)),
                GCP_DISRUPTION_RULE,
                "google_kms_crypto_key_version.data",
                "kms_management_paths",
                (
                    "operation=cloudkms.cryptoKeyVersions.destroy",
                    "target_type=crypto_key_version",
                ),
            ),
            (
                "azure-delete",
                "azure",
                AzureNormalizer(),
                _azure_disruption_resources(),
                AZURE_DISRUPTION_RULE,
                "azurerm_key_vault_key.signing",
                "key_vault_management_paths",
                (
                    "operation=delete",
                    "authorization_basis=key_vault_data_plane_grant",
                ),
            ),
        )

        for (
            case,
            provider,
            normalizer,
            resources,
            rule_id,
            target,
            evidence_key,
            fragments,
        ) in cases:
            with self.subTest(case=case):
                findings = _evaluate(normalizer, resources)
                self.assertEqual([finding.rule_id for finding in findings], [rule_id])
                finding = findings[0]
                self.assertEqual(finding.category, StrideCategory.DENIAL_OF_SERVICE)
                self.assertIn(target, finding.affected_resources)
                self.assertTrue(finding.rule_id.startswith(f"{provider}-"))
                _assert_evidence_fragments(
                    self,
                    finding,
                    evidence_key,
                    fragments,
                )

    def test_public_deterministic_delegation_authority_emits_elevation_of_privilege(
        self,
    ) -> None:
        cases = (
            (
                "aws-create-grant",
                "aws",
                AwsNormalizer(),
                _aws_resources(("kms:CreateGrant",)),
                AWS_DELEGATION_RULE,
                "aws_kms_key.data",
                "kms_management_paths",
                ("operation=kms:CreateGrant", "management_effect=delegation"),
            ),
            (
                "gcp-set-key-policy",
                "gcp",
                GcpNormalizer(),
                _gcp_resources(("cloudkms.cryptoKeys.setIamPolicy",)),
                GCP_DELEGATION_RULE,
                "google_kms_crypto_key.data",
                "kms_management_paths",
                (
                    "operation=cloudkms.cryptoKeys.setIamPolicy",
                    "target_type=crypto_key",
                ),
            ),
            (
                "azure-role-assignment-management",
                "azure",
                AzureNormalizer(),
                _azure_delegation_resources(),
                AZURE_DELEGATION_RULE,
                "azurerm_key_vault.orders",
                "key_vault_management_paths",
                (
                    "operation=rbac_role_assignment_management",
                    "authorization_basis=azure_control_plane_role_assignment",
                ),
            ),
        )

        for (
            case,
            provider,
            normalizer,
            resources,
            rule_id,
            target,
            evidence_key,
            fragments,
        ) in cases:
            with self.subTest(case=case):
                findings = _evaluate(normalizer, resources)
                self.assertEqual([finding.rule_id for finding in findings], [rule_id])
                finding = findings[0]
                self.assertEqual(
                    finding.category,
                    StrideCategory.ELEVATION_OF_PRIVILEGE,
                )
                self.assertIn(target, finding.affected_resources)
                self.assertTrue(finding.rule_id.startswith(f"{provider}-"))
                _assert_evidence_fragments(
                    self,
                    finding,
                    evidence_key,
                    fragments,
                )

    def test_private_workloads_stay_quiet(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    ("kms:ScheduleKeyDeletion", "kms:CreateGrant"),
                    public=False,
                ),
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_broad_resources(public=False),
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_broad_resources(public=False),
            ),
        )

        for provider, normalizer, resources in cases:
            with self.subTest(provider=provider):
                self.assertEqual(_evaluate(normalizer, resources), [])

    def test_non_deterministic_or_incompatible_paths_stay_quiet(self) -> None:
        cases = (
            (
                "aws-conditional",
                AwsNormalizer(),
                _aws_resources(("kms:DisableKey",), condition=True),
            ),
            (
                "aws-denied",
                AwsNormalizer(),
                _aws_resources(("kms:DisableKey",), deny=True),
            ),
            (
                "aws-incomplete-policy",
                AwsNormalizer(),
                _aws_resources(
                    ("kms:DisableKey",),
                    incomplete_policy=True,
                ),
            ),
            (
                "aws-unresolved-policy",
                AwsNormalizer(),
                _aws_resources(
                    ("kms:DisableKey",),
                    unresolved_policy=True,
                ),
            ),
            (
                "aws-unresolved-runtime-identity",
                AwsNormalizer(),
                _aws_resources(
                    ("kms:DisableKey",),
                    runtime_identity=False,
                ),
            ),
            (
                "aws-incompatible-origin",
                AwsNormalizer(),
                _aws_resources(
                    ("kms:DeleteImportedKeyMaterial",),
                    origin="AWS_KMS",
                ),
            ),
            (
                "gcp-conditional",
                GcpNormalizer(),
                _gcp_resources(
                    ("cloudkms.cryptoKeyVersions.destroy",),
                    condition=True,
                ),
            ),
            (
                "gcp-ambiguous-managers",
                GcpNormalizer(),
                _gcp_resources(
                    ("cloudkms.cryptoKeyVersions.destroy",),
                    ambiguous=True,
                ),
            ),
            (
                "gcp-incomplete-role",
                GcpNormalizer(),
                _gcp_resources(
                    ("cloudkms.cryptoKeyVersions.destroy",),
                    incomplete_role=True,
                ),
            ),
            (
                "gcp-unresolved-runtime-identity",
                GcpNormalizer(),
                _gcp_resources(
                    ("cloudkms.cryptoKeyVersions.destroy",),
                    runtime_identity=False,
                ),
            ),
            (
                "gcp-unresolved-version",
                GcpNormalizer(),
                _gcp_resources(
                    ("cloudkms.cryptoKeyVersions.destroy",),
                    unresolved_version=True,
                ),
            ),
            (
                "gcp-incompatible-version-lifecycle",
                GcpNormalizer(),
                _gcp_resources(
                    ("cloudkms.cryptoKeyVersions.destroy",),
                    version_state="DESTROY_SCHEDULED",
                ),
            ),
            (
                "azure-conditional",
                AzureNormalizer(),
                _azure_delegation_resources(condition=True),
            ),
            (
                "azure-denied",
                AzureNormalizer(),
                _azure_delegation_resources(denied=True),
            ),
            (
                "azure-incomplete-role",
                AzureNormalizer(),
                _azure_delegation_resources(incomplete_role=True),
            ),
            (
                "azure-ambiguous-managers",
                AzureNormalizer(),
                _azure_disruption_resources(ambiguous=True),
            ),
            (
                "azure-unresolved-runtime-identity",
                AzureNormalizer(),
                _azure_delegation_resources(runtime_identity=False),
            ),
        )

        for case, normalizer, resources in cases:
            with self.subTest(case=case):
                self.assertEqual(_evaluate(normalizer, resources), [])

    def test_recoverability_and_native_scope_remain_provider_specific(
        self,
    ) -> None:
        aws_inventory, aws_findings = _analyze(
            AwsNormalizer(),
            _aws_resources(("kms:ScheduleKeyDeletion",)),
        )
        aws_service_resource = aws_inventory.get_by_address("aws_ecs_service.orders")
        assert aws_service_resource is not None
        aws_path = aws_facts(aws_service_resource).ecs_kms_management_paths[0]
        self.assertEqual(aws_path["key_arn"], AWS_KEY_ARNS["data"])
        self.assertEqual(aws_path["deletion_window_in_days"], 30)
        self.assertEqual(aws_path["key_origin"], "AWS_KMS")
        _assert_evidence_fragments(
            self,
            aws_findings[0],
            "kms_management_paths",
            ("key_arn=arn:aws:kms:", "key_origin=AWS_KMS"),
        )

        gcp_inventory, gcp_findings = _analyze(
            GcpNormalizer(),
            _gcp_resources(
                ("cloudkms.cryptoKeyVersions.destroy",),
                scope_type="project",
            ),
        )
        gcp_workload = gcp_inventory.get_by_address("google_cloud_run_v2_service.orders")
        assert gcp_workload is not None
        gcp_path = gcp_facts(gcp_workload).cloud_run_kms_management_paths[0]
        self.assertEqual(gcp_path["scope_type"], "project")
        self.assertFalse(gcp_path["iam_scope_is_key_version"])
        self.assertEqual(
            gcp_path["key_version"]["destroy_scheduled_duration"],
            "604800s",
        )
        self.assertEqual(
            gcp_path["key_version"]["deletion_policy_state"],
            "abandon",
        )
        _assert_evidence_fragments(
            self,
            gcp_findings[0],
            "scope_breadth",
            ("project_grants=1", "blast_radius_basis=project_applicable_grant"),
        )

        azure_inventory, azure_findings = _analyze(
            AzureNormalizer(),
            _azure_disruption_resources(purge_protection=True),
        )
        azure_workload = azure_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert azure_workload is not None
        azure_paths = azure_facts(azure_workload).app_service_key_vault_management_paths
        azure_operations = {path["operation"] for path in azure_paths}
        delete_path = next(path for path in azure_paths if path["operation"] == "delete")
        self.assertTrue(delete_path["purge_protection_enabled"])
        self.assertIn("delete", azure_operations)
        self.assertNotIn("delete_plus_purge", azure_operations)
        self.assertEqual(
            {finding.rule_id for finding in azure_findings},
            {AZURE_DISRUPTION_RULE},
        )
        _assert_evidence_fragments(
            self,
            azure_findings[0],
            "key_vault_management_paths",
            (
                "deletion_impact=recoverable_soft_delete",
                "scope_types=subscription",
            ),
        )
        self.assertFalse(
            any(
                "permanent_delete_sequence" in value
                for value in _evidence(azure_findings[0])["key_vault_management_paths"]
            )
        )

    def test_broad_runtime_authority_emits_both_threats_without_provider_leakage(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    (
                        "kms:DisableKey",
                        "kms:ScheduleKeyDeletion",
                        "kms:CreateGrant",
                        "kms:PutKeyPolicy",
                    )
                ),
                {AWS_DISRUPTION_RULE, AWS_DELEGATION_RULE},
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_broad_resources(),
                {GCP_DISRUPTION_RULE, GCP_DELEGATION_RULE},
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_broad_resources(),
                {AZURE_DISRUPTION_RULE, AZURE_DELEGATION_RULE},
            ),
        )

        for provider, normalizer, resources, expected_rules in cases:
            with self.subTest(provider=provider):
                findings = _evaluate(normalizer, resources)
                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    expected_rules,
                )
                self.assertEqual(
                    {finding.category for finding in findings},
                    {
                        StrideCategory.DENIAL_OF_SERVICE,
                        StrideCategory.ELEVATION_OF_PRIVILEGE,
                    },
                )
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import unittest
from collections.abc import Iterable, Mapping
from typing import cast

from tests.providers.aws.test_aws_public_ecs_secret_management_rules import (
    _public_resources as aws_public_resources,
)
from tests.providers.aws.test_aws_secrets_manager_operation_authorization import (
    _ROLE_ARN as AWS_ROLE_ARN,
)
from tests.providers.aws.test_aws_secrets_manager_operation_authorization import (
    _SECRET_ARN as AWS_SECRET_ARN,
)
from tests.providers.aws.test_aws_secrets_manager_operation_authorization import (
    _statement as aws_statement,
)
from tests.providers.aws.test_aws_secrets_manager_operation_authorization import (
    _unresolved_attachment as aws_unresolved_attachment,
)
from tests.providers.azure.test_azure_app_service_key_vault_secret_management_paths import (
    _access_policy as azure_access_policy,
)
from tests.providers.azure.test_azure_app_service_key_vault_secret_management_paths import (
    _system_secret_assignment as azure_system_secret_assignment,
)
from tests.providers.gcp.test_gcp_cloud_run_secret_management_paths import (
    _PAYLOAD_SENTINEL as GCP_PAYLOAD_SENTINEL,
)
from tests.providers.gcp.test_gcp_cloud_run_secret_management_paths import (
    _SERVICE_ACCOUNT_EMAIL as GCP_SERVICE_ACCOUNT_EMAIL,
)
from tests.providers.gcp.test_gcp_cloud_run_secret_management_paths import (
    _SERVICE_ACCOUNT_MEMBER as GCP_SERVICE_ACCOUNT_MEMBER,
)
from tests.providers.gcp.test_gcp_cloud_run_secret_management_paths import (
    _cloud_run as gcp_cloud_run,
)
from tests.providers.gcp.test_gcp_cloud_run_secret_management_paths import (
    _custom_role as gcp_custom_role,
)
from tests.providers.gcp.test_gcp_cloud_run_secret_management_paths import (
    _project_member as gcp_project_member,
)
from tests.providers.gcp.test_gcp_cloud_run_secret_management_paths import (
    _secret as gcp_secret,
)
from tests.providers.gcp.test_gcp_cloud_run_secret_management_paths import (
    _secret_binding as gcp_secret_binding,
)
from tests.providers.gcp.test_gcp_cloud_run_secret_management_paths import (
    _secret_member as gcp_secret_member,
)
from tests.providers.gcp.test_gcp_cloud_run_secret_management_paths import (
    _version as gcp_version,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _public_invoker as gcp_public_invoker,
)
from tests.providers.test_public_workload_secret_integrity_boundaries import (
    _AZURE_SECRET_RESOURCE_ID as AZURE_SECRET_RESOURCE_ID,
)
from tests.providers.test_public_workload_secret_integrity_boundaries import (
    _AZURE_SYSTEM_PRINCIPAL_ID as AZURE_SYSTEM_PRINCIPAL_ID,
)
from tests.providers.test_public_workload_secret_integrity_boundaries import (
    _SECRET_PAYLOAD_SENTINEL as AZURE_PAYLOAD_SENTINEL,
)
from tests.providers.test_public_workload_secret_integrity_boundaries import (
    _azure_secret as azure_secret,
)
from tests.providers.test_public_workload_secret_integrity_boundaries import (
    _azure_secret_admin_role as azure_secret_admin_role,
)
from tests.providers.test_public_workload_secret_integrity_boundaries import (
    _azure_vault as azure_vault,
)
from tests.providers.test_public_workload_secret_integrity_boundaries import (
    _azure_web_app as azure_web_app,
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

AWS_TAMPERING_RULE = "aws-public-ecs-secret-tampering"
AWS_DISRUPTION_RULE = "aws-public-ecs-secret-disruption"
GCP_TAMPERING_RULE = "gcp-public-cloud-run-secret-tampering"
GCP_DISRUPTION_RULE = "gcp-public-cloud-run-secret-disruption"
AZURE_TAMPERING_RULE = "azure-public-app-service-secret-tampering"
AZURE_DISRUPTION_RULE = "azure-public-app-service-secret-disruption"
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
_AWS_TAMPERING_OPERATIONS = (
    "secretsmanager:PutSecretValue",
    "secretsmanager:UpdateSecret",
    "secretsmanager:UpdateSecretVersionStage",
)
_AZURE_SET = "Microsoft.KeyVault/vaults/secrets/setSecret/action"
_AZURE_DELETE = "Microsoft.KeyVault/vaults/secrets/delete"
_AZURE_PURGE = "Microsoft.KeyVault/vaults/secrets/purge/action"
_AWS_SERVICE_ADDRESS = "aws_ecs_service.orders"
_GCP_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
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


def _path_state(
    provider: str,
    inventory: ResourceInventory,
) -> tuple[list[Mapping[str, object]], list[str]]:
    if provider == "aws":
        workload = inventory.get_by_address(_AWS_SERVICE_ADDRESS)
        assert workload is not None
        facts = aws_facts(workload)
        return (
            [cast(Mapping[str, object], path) for path in facts.ecs_secret_management_paths],
            list(facts.ecs_secret_management_path_uncertainties),
        )
    if provider == "gcp":
        workload = inventory.get_by_address(_GCP_WORKLOAD_ADDRESS)
        assert workload is not None
        facts = gcp_facts(workload)
        return (
            [cast(Mapping[str, object], path) for path in facts.cloud_run_secret_management_paths],
            list(facts.cloud_run_secret_management_path_uncertainties),
        )
    workload = inventory.get_by_address(_AZURE_WORKLOAD_ADDRESS)
    assert workload is not None
    facts = azure_facts(workload)
    return (
        [cast(Mapping[str, object], path) for path in facts.app_service_key_vault_secret_management_paths],
        list(facts.app_service_key_vault_secret_management_path_uncertainties),
    )


def _gcp_workload(*, public: bool = True, service_account: str = GCP_SERVICE_ACCOUNT_EMAIL) -> TerraformResource:
    workload = gcp_cloud_run(service_account=service_account)
    workload.values["ingress"] = "INGRESS_TRAFFIC_ALL" if public else "INGRESS_TRAFFIC_INTERNAL_ONLY"
    return workload


def _gcp_resources(
    *iam_resources: TerraformResource,
    public: bool = True,
    include_version: bool = True,
    service_account: str = GCP_SERVICE_ACCOUNT_EMAIL,
) -> list[TerraformResource]:
    return [
        _gcp_workload(public=public, service_account=service_account),
        gcp_public_invoker(),
        gcp_secret(),
        *([gcp_version()] if include_version else []),
        *iam_resources,
    ]


def _azure_resources(
    data_actions: tuple[str, ...],
    *,
    public: bool = True,
    purge_protection: bool | None = False,
    condition: str | None = None,
    not_data_actions: tuple[str, ...] = (),
    permissions_unknown: bool = False,
) -> list[TerraformResource]:
    role = azure_secret_admin_role(permissions_unknown=permissions_unknown)
    permissions = role.values.get("permissions")
    assert isinstance(permissions, list)
    assert permissions
    permission = permissions[0]
    assert isinstance(permission, dict)
    permission["data_actions"] = list(data_actions)
    permission["not_data_actions"] = list(not_data_actions)
    return [
        azure_vault(purge_protection_enabled=purge_protection),
        azure_secret(),
        azure_web_app(public=public),
        role,
        azure_system_secret_assignment(
            scope="azurerm_key_vault_secret.orders.resource_versionless_id",
            condition=condition,
        ),
    ]


def _azure_ambiguous_resources() -> list[TerraformResource]:
    vault = azure_vault(rbac_enabled=False)
    vault.values["access_policy"] = [
        {
            "tenant_id": "tenant-id",
            "object_id": AZURE_SYSTEM_PRINCIPAL_ID,
            "secret_permissions": ["Set"],
        }
    ]
    return [
        vault,
        azure_secret(),
        azure_web_app(),
        azure_access_policy(
            "external_system_set",
            principal_id=AZURE_SYSTEM_PRINCIPAL_ID,
            secret_permissions=("Set",),
        ),
    ]


def _aws_unresolved_identity_resources() -> list[TerraformResource]:
    resources = aws_public_resources([aws_statement("Allow", "secretsmanager:PutSecretValue")])
    role = next(resource for resource in resources if resource.resource_type == "aws_iam_role")
    role.values["arn"] = None
    role.unknown_values["arn"] = True
    task_definition = next(resource for resource in resources if resource.resource_type == "aws_ecs_task_definition")
    task_definition.values["task_role_arn"] = "aws_iam_role.orders_task"
    return resources


def _azure_unresolved_identity_resources() -> list[TerraformResource]:
    resources = _azure_resources((_AZURE_SET,))
    workload = next(resource for resource in resources if resource.address == _AZURE_WORKLOAD_ADDRESS)
    identities = workload.values.get("identity")
    assert isinstance(identities, list)
    assert identities
    identity = identities[0]
    assert isinstance(identity, dict)
    identity["principal_id"] = None
    workload.unknown_values["identity"] = [{"principal_id": True}]
    return resources


def _finding_payload(findings: list[Finding]) -> str:
    return json.dumps(
        [
            {
                "rule_id": finding.rule_id,
                "category": finding.category.value,
                "affected_resources": finding.affected_resources,
                "rationale": finding.rationale,
                "evidence": {item.key: item.values for item in finding.evidence},
            }
            for finding in findings
        ],
        sort_keys=True,
    )


class PublicWorkloadSecretIntegrityAndAvailabilityPathParityTests(unittest.TestCase):
    """Pins shared threat outcomes while retaining native secret lifecycle models."""

    def test_provider_local_rule_families_are_registered(self) -> None:
        self.assertTrue({AWS_TAMPERING_RULE, AWS_DISRUPTION_RULE} <= _flatten(AWS_RULE_GROUP_IDS))
        self.assertTrue({GCP_TAMPERING_RULE, GCP_DISRUPTION_RULE} <= _flatten(GCP_RULE_GROUP_IDS))
        self.assertTrue({AZURE_TAMPERING_RULE, AZURE_DISRUPTION_RULE} <= _flatten(AZURE_RULE_GROUP_IDS))

    def test_public_deterministic_secret_mutation_emits_tampering(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                aws_public_resources([aws_statement("Allow", "secretsmanager:PutSecretValue")]),
                AWS_TAMPERING_RULE,
                "aws_secretsmanager_secret.orders",
                "secretsmanager:PutSecretValue",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    gcp_project_member(role="roles/secretmanager.secretVersionAdder"),
                    include_version=False,
                ),
                GCP_TAMPERING_RULE,
                "google_secret_manager_secret.orders",
                "secretmanager.versions.add",
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources((_AZURE_SET,)),
                AZURE_TAMPERING_RULE,
                "azurerm_key_vault_secret.orders",
                "operation=set",
            ),
        )

        for provider, normalizer, resources, rule_id, target, operation in cases:
            with self.subTest(provider=provider):
                _inventory, findings = _analyze(normalizer, resources)

                self.assertEqual([finding.rule_id for finding in findings], [rule_id])
                finding = findings[0]
                self.assertEqual(finding.category, StrideCategory.TAMPERING)
                self.assertIn(target, finding.affected_resources)
                self.assertTrue(finding.rule_id.startswith(f"{provider}-"))
                _assert_evidence_fragments(
                    self,
                    finding,
                    "secret_management_paths",
                    (operation, "management_effect=tampering"),
                )

    def test_public_deterministic_secret_removal_emits_native_disruption(
        self,
    ) -> None:
        aws_inventory, aws_findings = _analyze(
            AwsNormalizer(),
            aws_public_resources(
                [aws_statement("Allow", "secretsmanager:DeleteSecret")],
                recovery_window_in_days=30,
            ),
        )
        self.assertEqual(
            [finding.rule_id for finding in aws_findings],
            [AWS_DISRUPTION_RULE],
        )
        self.assertEqual(
            aws_findings[0].category,
            StrideCategory.DENIAL_OF_SERVICE,
        )
        aws_paths, _aws_uncertainties = _path_state("aws", aws_inventory)
        self.assertEqual(
            [path["operation"] for path in aws_paths],
            ["secretsmanager:DeleteSecret"],
        )
        self.assertEqual(aws_paths[0]["role_arn"], AWS_ROLE_ARN)
        self.assertEqual(aws_paths[0]["secret_arn"], AWS_SECRET_ARN)
        _assert_evidence_fragments(
            self,
            aws_findings[0],
            "recovery_window",
            (
                "terraform_recovery_window_in_days=30",
                "terraform_recovery_window_is_not_runtime_recovery=true",
            ),
        )

        gcp_role, gcp_role_resource = gcp_custom_role(["secretmanager.versions.destroy"])
        gcp_inventory, gcp_findings = _analyze(
            GcpNormalizer(),
            _gcp_resources(
                gcp_role_resource,
                gcp_secret_member(role=gcp_role),
            ),
        )
        self.assertEqual(
            [finding.rule_id for finding in gcp_findings],
            [GCP_DISRUPTION_RULE],
        )
        self.assertEqual(
            gcp_findings[0].category,
            StrideCategory.DENIAL_OF_SERVICE,
        )
        gcp_paths, _gcp_uncertainties = _path_state("gcp", gcp_inventory)
        self.assertEqual(
            [path["operation"] for path in gcp_paths],
            ["secretmanager.versions.destroy"],
        )
        self.assertEqual(
            gcp_paths[0]["service_account_member"],
            GCP_SERVICE_ACCOUNT_MEMBER,
        )
        self.assertEqual(gcp_paths[0]["target_type"], "secret_version")
        _assert_evidence_fragments(
            self,
            gcp_findings[0],
            "recovery_evidence",
            (
                "version_destroy_ttl=604800s",
                "recovery_state=version_destroy_delay",
            ),
        )

        azure_inventory, azure_findings = _analyze(
            AzureNormalizer(),
            _azure_resources((_AZURE_DELETE, _AZURE_PURGE)),
        )
        self.assertEqual(
            [finding.rule_id for finding in azure_findings],
            [AZURE_DISRUPTION_RULE],
        )
        self.assertEqual(
            azure_findings[0].category,
            StrideCategory.DENIAL_OF_SERVICE,
        )
        azure_paths, _azure_uncertainties = _path_state(
            "azure",
            azure_inventory,
        )
        self.assertEqual(
            {path["operation"] for path in azure_paths},
            {"delete", "delete_plus_purge"},
        )
        purge_path = next(path for path in azure_paths if path["operation"] == "delete_plus_purge")
        self.assertEqual(purge_path["step_operations"], ["delete", "purge"])
        self.assertEqual(purge_path["principal_id"], AZURE_SYSTEM_PRINCIPAL_ID)
        self.assertEqual(
            purge_path["target_resource_id"],
            AZURE_SECRET_RESOURCE_ID,
        )
        _assert_evidence_fragments(
            self,
            azure_findings[0],
            "recovery_posture",
            (
                "recovery_state=recoverable_soft_delete",
                "recovery_state=permanent_delete_sequence",
            ),
        )

    def test_private_workloads_remain_quiet_while_authority_paths_survive(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                aws_public_resources(
                    [
                        aws_statement(
                            "Allow",
                            [
                                "secretsmanager:PutSecretValue",
                                "secretsmanager:DeleteSecret",
                            ],
                        )
                    ],
                    internal=True,
                ),
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    gcp_project_member(),
                    public=False,
                ),
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(
                    (_AZURE_SET, _AZURE_DELETE, _AZURE_PURGE),
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

    def test_nondeterministic_denied_incomplete_and_ambiguous_paths_stay_quiet(
        self,
    ) -> None:
        gcp_unknown_role, gcp_unknown_role_resource = gcp_custom_role(
            ["secretmanager.versions.add"],
            permissions_unknown=True,
        )
        cases = (
            (
                "aws-conditional",
                "aws",
                AwsNormalizer(),
                aws_public_resources(
                    [
                        aws_statement(
                            "Allow",
                            "secretsmanager:PutSecretValue",
                            condition={"StringEquals": {"aws:PrincipalTag/environment": "production"}},
                        )
                    ]
                ),
                True,
            ),
            (
                "aws-denied",
                "aws",
                AwsNormalizer(),
                aws_public_resources(
                    [
                        aws_statement(
                            "Deny",
                            "secretsmanager:PutSecretValue",
                        )
                    ]
                ),
                False,
            ),
            (
                "aws-incomplete",
                "aws",
                AwsNormalizer(),
                [
                    *aws_public_resources([]),
                    aws_unresolved_attachment(),
                ],
                True,
            ),
            (
                "aws-unresolved-identity",
                "aws",
                AwsNormalizer(),
                _aws_unresolved_identity_resources(),
                True,
            ),
            (
                "gcp-conditional",
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    gcp_secret_member(
                        role="roles/secretmanager.secretVersionAdder",
                        condition={
                            "title": "deployment-window",
                            "expression": ("request.time < timestamp('2027-01-01T00:00:00Z')"),
                        },
                    )
                ),
                True,
            ),
            (
                "gcp-ambiguous",
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    gcp_secret_member(role="roles/secretmanager.admin"),
                    gcp_secret_binding(role="roles/secretmanager.admin"),
                ),
                True,
            ),
            (
                "gcp-incomplete",
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    gcp_unknown_role_resource,
                    gcp_secret_member(role=gcp_unknown_role),
                ),
                True,
            ),
            (
                "gcp-unresolved-identity",
                "gcp",
                GcpNormalizer(),
                _gcp_resources(
                    gcp_project_member(),
                    service_account="${google_service_account.runtime.email}",
                ),
                True,
            ),
            (
                "azure-conditional",
                "azure",
                AzureNormalizer(),
                _azure_resources(
                    (_AZURE_SET,),
                    condition=("@Resource[Microsoft.KeyVault/vaults/secrets:Name] StringEqualsIgnoreCase 'orders'"),
                ),
                True,
            ),
            (
                "azure-denied",
                "azure",
                AzureNormalizer(),
                _azure_resources(
                    (_AZURE_SET,),
                    not_data_actions=(_AZURE_SET,),
                ),
                False,
            ),
            (
                "azure-incomplete",
                "azure",
                AzureNormalizer(),
                _azure_resources(
                    (_AZURE_SET,),
                    permissions_unknown=True,
                ),
                True,
            ),
            (
                "azure-ambiguous",
                "azure",
                AzureNormalizer(),
                _azure_ambiguous_resources(),
                True,
            ),
            (
                "azure-unresolved-identity",
                "azure",
                AzureNormalizer(),
                _azure_unresolved_identity_resources(),
                True,
            ),
        )

        for case, provider, normalizer, resources, uncertainty_expected in cases:
            with self.subTest(case=case):
                inventory, findings = _analyze(normalizer, resources)
                paths, uncertainties = _path_state(provider, inventory)

                self.assertEqual(paths, [])
                self.assertEqual(findings, [])
                if uncertainty_expected:
                    self.assertTrue(uncertainties)

    def test_broad_runtime_authority_emits_both_threats_without_cross_effects(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                aws_public_resources(
                    [
                        aws_statement(
                            "Allow",
                            [
                                *_AWS_TAMPERING_OPERATIONS,
                                "secretsmanager:DeleteSecret",
                            ],
                        )
                    ]
                ),
                {AWS_TAMPERING_RULE, AWS_DISRUPTION_RULE},
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(gcp_project_member()),
                {GCP_TAMPERING_RULE, GCP_DISRUPTION_RULE},
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources((_AZURE_SET, _AZURE_DELETE, _AZURE_PURGE)),
                {AZURE_TAMPERING_RULE, AZURE_DISRUPTION_RULE},
            ),
        )

        for provider, normalizer, resources, expected_rules in cases:
            with self.subTest(provider=provider):
                _inventory, findings = _analyze(normalizer, resources)

                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    expected_rules,
                )
                self.assertEqual(
                    {finding.category for finding in findings},
                    {
                        StrideCategory.TAMPERING,
                        StrideCategory.DENIAL_OF_SERVICE,
                    },
                )
                findings_by_category = {finding.category: finding for finding in findings}
                self.assertTrue(
                    all(
                        "management_effect=tampering" in value
                        for value in _evidence(findings_by_category[StrideCategory.TAMPERING])[
                            "secret_management_paths"
                        ]
                    )
                )
                self.assertTrue(
                    all(
                        "management_effect=disruption" in value
                        for value in _evidence(findings_by_category[StrideCategory.DENIAL_OF_SERVICE])[
                            "secret_management_paths"
                        ]
                    )
                )

    def test_paths_and_findings_do_not_leak_across_provider_evaluations(
        self,
    ) -> None:
        engine = StrideRuleEngine()
        cases = (
            (
                "aws-initial",
                "aws",
                AwsNormalizer(),
                aws_public_resources(
                    [
                        aws_statement(
                            "Allow",
                            [
                                "secretsmanager:PutSecretValue",
                                "secretsmanager:DeleteSecret",
                            ],
                        )
                    ]
                ),
                {AWS_TAMPERING_RULE, AWS_DISRUPTION_RULE},
                ("google_", "azurerm_"),
                (),
            ),
            (
                "gcp-after-aws",
                "gcp",
                GcpNormalizer(),
                _gcp_resources(gcp_project_member()),
                {GCP_TAMPERING_RULE, GCP_DISRUPTION_RULE},
                ("aws_", "azurerm_"),
                (GCP_PAYLOAD_SENTINEL,),
            ),
            (
                "azure-after-gcp",
                "azure",
                AzureNormalizer(),
                _azure_resources((_AZURE_SET, _AZURE_DELETE, _AZURE_PURGE)),
                {AZURE_TAMPERING_RULE, AZURE_DISRUPTION_RULE},
                ("aws_", "google_"),
                (AZURE_PAYLOAD_SENTINEL,),
            ),
            (
                "aws-after-provider-switches",
                "aws",
                AwsNormalizer(),
                aws_public_resources(
                    [
                        aws_statement(
                            "Allow",
                            [
                                "secretsmanager:PutSecretValue",
                                "secretsmanager:DeleteSecret",
                            ],
                        )
                    ]
                ),
                {AWS_TAMPERING_RULE, AWS_DISRUPTION_RULE},
                ("google_", "azurerm_"),
                (),
            ),
        )

        for (
            sequence,
            provider,
            normalizer,
            resources,
            expected_rules,
            foreign_prefixes,
            payload_sentinels,
        ) in cases:
            with self.subTest(sequence=sequence):
                inventory, findings = _analyze(
                    normalizer,
                    resources,
                    engine=engine,
                )
                paths, _uncertainties = _path_state(provider, inventory)
                path_payload = json.dumps(paths, sort_keys=True, default=str)
                finding_payload = _finding_payload(findings)

                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    expected_rules,
                )
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))
                for foreign_prefix in foreign_prefixes:
                    self.assertNotIn(foreign_prefix, path_payload)
                    self.assertNotIn(foreign_prefix, finding_payload)
                for payload_sentinel in payload_sentinels:
                    self.assertNotIn(payload_sentinel, path_payload)
                    self.assertNotIn(payload_sentinel, finding_payload)


if __name__ == "__main__":
    unittest.main()

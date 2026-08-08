from __future__ import annotations

import json
import unittest
from typing import Any

from tests.providers.test_public_workload_managed_key_operation_boundaries import (
    _AWS_ACCOUNT_ID,
    _AWS_EXECUTION_ROLE_ARN,
    _AWS_TASK_ROLE_ARN,
    _AZURE_SUBSCRIPTION_ID,
    _AZURE_VAULT_ID,
    _AZURE_VAULT_URI,
    _GCP_PROJECT,
    _GCP_SERVICE_ACCOUNT_EMAIL,
    _GCP_SERVICE_ACCOUNT_MEMBER,
    _aws_ecs_service,
    _aws_execution_role,
    _aws_public_edge,
    _aws_task_definition,
    _gcp_cloud_run,
    _gcp_public_invoker,
    _resource,
)
from tfstride.models import TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_AWS_SECRET_ARN = f"arn:aws:secretsmanager:us-east-1:{_AWS_ACCOUNT_ID}:secret:orders-AbCdEf"
_AWS_EXTERNAL_POLICY_ARN = f"arn:aws:iam::{_AWS_ACCOUNT_ID}:policy/external-secret-administration"
_AWS_INTEGRITY_ACTIONS = (
    "secretsmanager:PutSecretValue",
    "secretsmanager:UpdateSecret",
    "secretsmanager:UpdateSecretVersionStage",
)
_AWS_DISRUPTION_ACTIONS = ("secretsmanager:DeleteSecret",)
_AWS_QUIET_ACTIONS = (
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret",
    "secretsmanager:ListSecretVersionIds",
    "secretsmanager:RestoreSecret",
    "secretsmanager:RotateSecret",
)

_GCP_SECRET_NAME = f"projects/{_GCP_PROJECT}/secrets/orders"
_GCP_CUSTOM_ROLE_NAME = f"projects/{_GCP_PROJECT}/roles/runtimeSecretIntegrity"
_GCP_INTEGRITY_PERMISSIONS = ("secretmanager.versions.add",)
_GCP_DISRUPTION_PERMISSIONS = (
    "secretmanager.versions.disable",
    "secretmanager.versions.destroy",
    "secretmanager.secrets.delete",
)
_GCP_QUIET_PERMISSIONS = (
    "secretmanager.versions.access",
    "secretmanager.versions.enable",
    "secretmanager.versions.get",
    "secretmanager.secrets.get",
)

_AZURE_SYSTEM_PRINCIPAL_ID = "orders-system-principal"
_AZURE_RUNTIME_IDENTITY_ID = (
    f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}/resourceGroups/app/providers/"
    "Microsoft.ManagedIdentity/userAssignedIdentities/orders-runtime"
)
_AZURE_RUNTIME_PRINCIPAL_ID = "orders-user-runtime-principal"
_AZURE_REFERENCE_IDENTITY_ID = (
    f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}/resourceGroups/app/providers/"
    "Microsoft.ManagedIdentity/userAssignedIdentities/orders-reference-reader"
)
_AZURE_REFERENCE_PRINCIPAL_ID = "orders-reference-reader-principal"
_AZURE_SECRET_VERSION = "version-0001"
_AZURE_SECRET_VERSIONLESS_URI = f"{_AZURE_VAULT_URI}/secrets/orders"
_AZURE_SECRET_URI = f"{_AZURE_SECRET_VERSIONLESS_URI}/{_AZURE_SECRET_VERSION}"
_AZURE_SECRET_RESOURCE_ID = f"{_AZURE_VAULT_ID}/secrets/orders"
_AZURE_SECRET_ADMIN_ROLE_ID = (
    f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/orders-secret-integrity"
)
_AZURE_SECRET_READER_ROLE_ID = "/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6"
_AZURE_INTEGRITY_ACTIONS = ("Microsoft.KeyVault/vaults/secrets/setSecret/action",)
_AZURE_DISRUPTION_ACTIONS = (
    "Microsoft.KeyVault/vaults/secrets/delete",
    "Microsoft.KeyVault/vaults/secrets/purge/action",
)
_AZURE_QUIET_ACTIONS = (
    "Microsoft.KeyVault/vaults/secrets/getSecret/action",
    "Microsoft.KeyVault/vaults/secrets/readMetadata/action",
    "Microsoft.KeyVault/vaults/secrets/recover/action",
    "Microsoft.KeyVault/vaults/secrets/backup/action",
    "Microsoft.KeyVault/vaults/secrets/restore/action",
)
_SECRET_PAYLOAD_SENTINEL = "fixture-secret-payload-must-not-survive-normalization"


def _aws_policy_statement(
    effect: str,
    actions: str | list[str],
    resources: str | list[str],
    *,
    principal: str | None = None,
    condition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "Effect": effect,
        "Action": actions,
        "Resource": resources,
    }
    if principal is not None:
        statement["Principal"] = {"AWS": principal}
    if condition is not None:
        statement["Condition"] = condition
    return statement


def _aws_runtime_role() -> TerraformResource:
    statements = [
        _aws_policy_statement(
            "Allow",
            [*_AWS_INTEGRITY_ACTIONS, *_AWS_DISRUPTION_ACTIONS],
            _AWS_SECRET_ARN,
        ),
        _aws_policy_statement(
            "Allow",
            "secretsmanager:PutSecretValue",
            _AWS_SECRET_ARN,
            condition={
                "StringEquals": {
                    "aws:PrincipalTag/environment": "production",
                }
            },
        ),
        _aws_policy_statement(
            "Deny",
            "secretsmanager:DeleteSecret",
            _AWS_SECRET_ARN,
        ),
        _aws_policy_statement(
            "Allow",
            list(_AWS_QUIET_ACTIONS),
            _AWS_SECRET_ARN,
        ),
    ]
    return _resource(
        "aws",
        "aws_iam_role",
        "orders_task",
        {
            "name": "orders-task",
            "arn": _AWS_TASK_ROLE_ARN,
            "inline_policy": [
                {
                    "name": "secret-integrity",
                    "policy": json.dumps(
                        {
                            "Version": "2012-10-17",
                            "Statement": statements,
                        }
                    ),
                }
            ],
        },
    )


def _aws_execution_role_with_secret_admin() -> TerraformResource:
    role = _aws_execution_role()
    role.values["inline_policy"] = [
        {
            "name": "must-not-be-runtime-authority",
            "policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        _aws_policy_statement(
                            "Allow",
                            [*_AWS_INTEGRITY_ACTIONS, *_AWS_DISRUPTION_ACTIONS],
                            _AWS_SECRET_ARN,
                        )
                    ],
                }
            ),
        }
    ]
    return role


def _aws_secret() -> TerraformResource:
    return _resource(
        "aws",
        "aws_secretsmanager_secret",
        "orders",
        {
            "id": _AWS_SECRET_ARN,
            "arn": _AWS_SECRET_ARN,
            "name": "orders",
            "description": "Orders runtime credentials",
            "recovery_window_in_days": 21,
        },
    )


def _aws_secret_policy() -> TerraformResource:
    statements = [
        _aws_policy_statement(
            "Allow",
            list(_AWS_INTEGRITY_ACTIONS),
            _AWS_SECRET_ARN,
            principal=_AWS_TASK_ROLE_ARN,
        ),
        _aws_policy_statement(
            "Deny",
            "secretsmanager:DeleteSecret",
            _AWS_SECRET_ARN,
            principal=_AWS_TASK_ROLE_ARN,
            condition={
                "StringNotEquals": {
                    "aws:PrincipalTag/break-glass": "approved",
                }
            },
        ),
    ]
    return _resource(
        "aws",
        "aws_secretsmanager_secret_policy",
        "orders",
        {
            "secret_arn": _AWS_SECRET_ARN,
            "policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": statements,
                }
            ),
        },
    )


def _aws_unresolved_policy_attachment() -> TerraformResource:
    return _resource(
        "aws",
        "aws_iam_role_policy_attachment",
        "external_secret_admin",
        {
            "role": _AWS_TASK_ROLE_ARN,
            "policy_arn": _AWS_EXTERNAL_POLICY_ARN,
        },
    )


def _gcp_secret() -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.SECRET_MANAGER_SECRET,
        "orders",
        {
            "id": _GCP_SECRET_NAME,
            "name": _GCP_SECRET_NAME,
            "project": _GCP_PROJECT,
            "secret_id": "orders",
            "replication": [{"auto": [{}]}],
            "ttl": "2592000s",
            "version_destroy_ttl": "604800s",
        },
    )


def _gcp_secret_integrity_role(
    *,
    permissions_unknown: bool = False,
) -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        "secret_integrity",
        {
            "id": _GCP_CUSTOM_ROLE_NAME,
            "name": _GCP_CUSTOM_ROLE_NAME,
            "project": _GCP_PROJECT,
            "role_id": "runtimeSecretIntegrity",
            "title": "Runtime Secret Integrity",
            "permissions": [
                *_GCP_INTEGRITY_PERMISSIONS,
                *_GCP_DISRUPTION_PERMISSIONS,
                *_GCP_QUIET_PERMISSIONS,
            ],
        },
        unknown_values={"permissions": True} if permissions_unknown else None,
    )


def _gcp_secret_member(
    name: str,
    *,
    role: str = _GCP_CUSTOM_ROLE_NAME,
    member: str = _GCP_SERVICE_ACCOUNT_MEMBER,
    condition: dict[str, str] | None = None,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "project": _GCP_PROJECT,
        "secret_id": _GCP_SECRET_NAME,
        "role": role,
        "member": member,
    }
    if condition is not None:
        values["condition"] = [condition]
    return _resource(
        "google",
        GcpResourceType.SECRET_MANAGER_SECRET_IAM_MEMBER,
        name,
        values,
        unknown_values=unknown_values,
    )


def _gcp_project_admin_member() -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.PROJECT_IAM_MEMBER,
        "secret_admin",
        {
            "project": _GCP_PROJECT,
            "role": "roles/secretmanager.admin",
            "member": _GCP_SERVICE_ACCOUNT_MEMBER,
        },
    )


def _gcp_secret_binding() -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.SECRET_MANAGER_SECRET_IAM_BINDING,
        "integrity_managers",
        {
            "project": _GCP_PROJECT,
            "secret_id": _GCP_SECRET_NAME,
            "role": _GCP_CUSTOM_ROLE_NAME,
            "members": [
                _GCP_SERVICE_ACCOUNT_MEMBER,
                "group:operators@example.com",
            ],
        },
    )


def _gcp_secret_policy() -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.SECRET_MANAGER_SECRET_IAM_POLICY,
        "authoritative",
        {
            "project": _GCP_PROJECT,
            "secret_id": _GCP_SECRET_NAME,
            "policy_data": json.dumps(
                {
                    "bindings": [
                        {
                            "role": _GCP_CUSTOM_ROLE_NAME,
                            "members": [f"serviceAccount:policy-admin@{_GCP_PROJECT}.iam.gserviceaccount.com"],
                        }
                    ]
                }
            ),
        },
    )


def _gcp_unknown_project_policy() -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.PROJECT_IAM_POLICY,
        "unknown_secret_policy",
        {
            "project": _GCP_PROJECT,
            "policy_data": None,
        },
        unknown_values={"policy_data": True},
    )


def _azure_vault(
    *,
    rbac_enabled: bool = True,
    purge_protection_enabled: bool | None = False,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": _AZURE_VAULT_ID,
        "name": "orders",
        "vault_uri": _AZURE_VAULT_URI,
        "enable_rbac_authorization": rbac_enabled,
        "public_network_access_enabled": True,
    }
    unknown_values: dict[str, Any] = {}
    if purge_protection_enabled is None:
        values["purge_protection_enabled"] = None
        unknown_values["purge_protection_enabled"] = True
    else:
        values["purge_protection_enabled"] = purge_protection_enabled
    return _resource(
        "azurerm",
        AzureResourceType.KEY_VAULT,
        "orders",
        values,
        unknown_values=unknown_values,
    )


def _azure_secret() -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.KEY_VAULT_SECRET,
        "orders",
        {
            "id": _AZURE_SECRET_URI,
            "versionless_id": _AZURE_SECRET_VERSIONLESS_URI,
            "resource_id": _AZURE_SECRET_RESOURCE_ID,
            "name": "orders",
            "version": _AZURE_SECRET_VERSION,
            "key_vault_id": "azurerm_key_vault.orders.id",
            "expiration_date": "2027-07-28T00:00:00Z",
            "not_before_date": "2026-07-28T00:00:00Z",
            "value": _SECRET_PAYLOAD_SENTINEL,
        },
    )


def _azure_identity(
    name: str,
    *,
    identity_id: str,
    principal_id: str,
) -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.USER_ASSIGNED_IDENTITY,
        name,
        {
            "id": identity_id,
            "name": name,
            "principal_id": principal_id,
            "client_id": f"{name}-client-id",
            "tenant_id": "tenant-id",
        },
    )


def _azure_web_app(*, public: bool = True) -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.LINUX_WEB_APP,
        "orders",
        {
            "id": (f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}/resourceGroups/app/providers/Microsoft.Web/sites/orders"),
            "name": "orders",
            "public_network_access_enabled": public,
            "key_vault_reference_identity_id": ("azurerm_user_assigned_identity.reference_reader.id"),
            "app_settings": {
                "ORDERS_SECRET": (f"@Microsoft.KeyVault(SecretUri={_AZURE_SECRET_URI})"),
            },
            "identity": [
                {
                    "type": "SystemAssigned, UserAssigned",
                    "principal_id": _AZURE_SYSTEM_PRINCIPAL_ID,
                    "tenant_id": "tenant-id",
                    "identity_ids": [
                        _AZURE_RUNTIME_IDENTITY_ID,
                        _AZURE_REFERENCE_IDENTITY_ID,
                    ],
                }
            ],
        },
    )


def _azure_secret_admin_role(
    *,
    permissions_unknown: bool = False,
) -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.ROLE_DEFINITION,
        "secret_integrity",
        {
            "id": _AZURE_SECRET_ADMIN_ROLE_ID,
            "role_definition_id": _AZURE_SECRET_ADMIN_ROLE_ID,
            "name": "Orders Secret Integrity",
            "scope": f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}",
            "assignable_scopes": [
                f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}",
            ],
            "permissions": [
                {
                    "actions": [],
                    "not_actions": [],
                    "data_actions": [
                        *_AZURE_INTEGRITY_ACTIONS,
                        *_AZURE_DISRUPTION_ACTIONS,
                        *_AZURE_QUIET_ACTIONS,
                    ],
                    "not_data_actions": [
                        "Microsoft.KeyVault/vaults/secrets/backup/action",
                    ],
                }
            ],
        },
        unknown_values={"permissions": True} if permissions_unknown else None,
    )


def _azure_role_assignment(
    name: str,
    *,
    principal_id: str,
    role_definition_id: str,
    role_definition_name: str,
    condition: str | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "scope": "azurerm_key_vault.orders.id",
        "role_definition_id": role_definition_id,
        "role_definition_name": role_definition_name,
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if condition is not None:
        values["condition"] = condition
        values["condition_version"] = "2.0"
    return _resource(
        "azurerm",
        AzureResourceType.ROLE_ASSIGNMENT,
        name,
        values,
    )


def _azure_reference_reader_assignment() -> TerraformResource:
    return _azure_role_assignment(
        "reference_reader",
        principal_id=_AZURE_REFERENCE_PRINCIPAL_ID,
        role_definition_id=_AZURE_SECRET_READER_ROLE_ID,
        role_definition_name="Key Vault Secrets User",
    )


def _azure_access_policy(
    *,
    object_id: str = _AZURE_RUNTIME_PRINCIPAL_ID,
) -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.KEY_VAULT_ACCESS_POLICY,
        "runtime",
        {
            "key_vault_id": "azurerm_key_vault.orders.id",
            "tenant_id": "tenant-id",
            "object_id": object_id,
            "secret_permissions": [
                "backup",
                "delete",
                "get",
                "list",
                "purge",
                "recover",
                "restore",
                "set",
            ],
        },
    )


class PublicWorkloadSecretIntegrityBoundaryTests(unittest.TestCase):
    """Pin secret-integrity prerequisites without constructing authority paths."""

    def test_aws_public_ecs_preserves_runtime_secret_authority_and_policy_boundaries(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            [
                *_aws_public_edge(),
                _aws_runtime_role(),
                _aws_execution_role_with_secret_admin(),
                _aws_task_definition(),
                _aws_ecs_service(),
                _aws_secret(),
                _aws_secret_policy(),
            ]
        )
        workload = inventory.get_by_address("aws_ecs_service.orders")
        task_role = inventory.get_by_address("aws_iam_role.orders_task")
        execution_role = inventory.get_by_address("aws_iam_role.orders_execution")
        secret = inventory.get_by_address("aws_secretsmanager_secret.orders")
        load_balancer = inventory.get_by_address("aws_lb.public")
        assert workload is not None
        assert task_role is not None
        assert execution_role is not None
        assert secret is not None
        assert load_balancer is not None

        workload_facts = aws_facts(workload)
        self.assertTrue(load_balancer.public_exposure)
        self.assertTrue(workload.get_metadata_field(AwsResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER))
        self.assertEqual(
            workload_facts.internet_facing_load_balancer_addresses,
            ["aws_lb.public"],
        )
        self.assertEqual(workload_facts.task_role_arn, _AWS_TASK_ROLE_ARN)
        self.assertEqual(
            workload_facts.execution_role_arn,
            _AWS_EXECUTION_ROLE_ARN,
        )
        self.assertEqual(workload.attached_role_arns, (_AWS_TASK_ROLE_ARN,))
        self.assertNotIn(_AWS_EXECUTION_ROLE_ARN, workload.attached_role_arns)

        self.assertEqual(
            aws_facts(task_role).iam_policy_completeness_state,
            "complete",
        )
        self.assertEqual(len(task_role.policy_statements), 4)
        unconditional, conditional, deny, quiet = task_role.policy_statements
        self.assertEqual(unconditional.effect, "Allow")
        self.assertEqual(
            unconditional.actions,
            [*_AWS_INTEGRITY_ACTIONS, *_AWS_DISRUPTION_ACTIONS],
        )
        self.assertEqual(unconditional.resources, [_AWS_SECRET_ARN])
        self.assertEqual(conditional.actions, ["secretsmanager:PutSecretValue"])
        self.assertEqual(
            [(item.operator, item.key, item.values) for item in conditional.conditions],
            [
                (
                    "StringEquals",
                    "aws:PrincipalTag/environment",
                    ["production"],
                )
            ],
        )
        self.assertEqual(deny.effect, "Deny")
        self.assertEqual(deny.actions, ["secretsmanager:DeleteSecret"])
        self.assertEqual(quiet.actions, list(_AWS_QUIET_ACTIONS))

        self.assertEqual(len(execution_role.policy_statements), 1)
        self.assertEqual(
            execution_role.policy_statements[0].actions,
            [*_AWS_INTEGRITY_ACTIONS, *_AWS_DISRUPTION_ACTIONS],
        )

        secret_facts = aws_facts(secret)
        self.assertEqual(secret.arn, _AWS_SECRET_ARN)
        self.assertEqual(secret_facts.secrets_manager_recovery_window_in_days, 21)
        self.assertEqual(
            secret_facts.resource_policy_source_addresses,
            ["aws_secretsmanager_secret_policy.orders"],
        )
        self.assertEqual(len(secret.policy_statements), 2)
        resource_allow, resource_deny = secret.policy_statements
        self.assertEqual(resource_allow.principals, [_AWS_TASK_ROLE_ARN])
        self.assertEqual(
            resource_allow.actions,
            list(_AWS_INTEGRITY_ACTIONS),
        )
        self.assertEqual(resource_deny.effect, "Deny")
        self.assertEqual(
            resource_deny.actions,
            ["secretsmanager:DeleteSecret"],
        )
        self.assertTrue(resource_deny.conditions)

        # Delivery-time retrieval uses the execution role only when a secret is
        # injected. It must not become the runtime integrity authority.
        self.assertEqual(workload_facts.ecs_secret_access_paths, [])

    def test_aws_incomplete_identity_policy_remains_visible_separately_from_recovery(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _aws_runtime_role(),
                _aws_unresolved_policy_attachment(),
                _aws_secret(),
            ]
        )
        role = inventory.get_by_address("aws_iam_role.orders_task")
        secret = inventory.get_by_address("aws_secretsmanager_secret.orders")
        assert role is not None
        assert secret is not None

        role_facts = aws_facts(role)
        self.assertEqual(role_facts.iam_policy_completeness_state, "unknown")
        self.assertEqual(
            role_facts.unresolved_attached_policy_arns,
            [_AWS_EXTERNAL_POLICY_ARN],
        )
        self.assertTrue(role_facts.iam_policy_posture_uncertainties)
        self.assertEqual(
            aws_facts(secret).secrets_manager_recovery_window_in_days,
            21,
        )
        self.assertEqual(
            aws_facts(secret).secrets_manager_posture_uncertainties,
            [],
        )

    def test_gcp_public_cloud_run_preserves_secret_scopes_lifecycle_and_permissions(
        self,
    ) -> None:
        condition = {
            "title": "deployment-window",
            "description": "temporary version mutation",
            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
        }
        inventory = GcpNormalizer().normalize(
            [
                _gcp_cloud_run(),
                _gcp_public_invoker(),
                _gcp_secret(),
                _gcp_secret_integrity_role(),
                _gcp_secret_member(
                    "conditional_integrity",
                    condition=condition,
                ),
                _gcp_project_admin_member(),
                _gcp_unknown_project_policy(),
            ]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
        secret = inventory.get_by_address("google_secret_manager_secret.orders")
        custom_role = inventory.get_by_address("google_project_iam_custom_role.secret_integrity")
        secret_member = inventory.get_by_address("google_secret_manager_secret_iam_member.conditional_integrity")
        project_member = inventory.get_by_address("google_project_iam_member.secret_admin")
        unknown_policy = inventory.get_by_address("google_project_iam_policy.unknown_secret_policy")
        assert workload is not None
        assert secret is not None
        assert custom_role is not None
        assert secret_member is not None
        assert project_member is not None
        assert unknown_policy is not None

        workload_facts = gcp_facts(workload)
        self.assertTrue(workload.public_access_configured)
        self.assertTrue(workload.public_exposure)
        self.assertEqual(
            workload_facts.service_account_email,
            _GCP_SERVICE_ACCOUNT_EMAIL,
        )
        self.assertEqual(
            workload_facts.service_account_member,
            _GCP_SERVICE_ACCOUNT_MEMBER,
        )

        secret_facts = gcp_facts(secret)
        self.assertEqual(secret.identifier, _GCP_SECRET_NAME)
        self.assertEqual(secret_facts.project, _GCP_PROJECT)
        self.assertEqual(secret_facts.secret_id, "orders")
        self.assertEqual(
            secret_facts.secret_manager_replication_mode,
            "automatic",
        )
        self.assertEqual(secret_facts.secret_manager_ttl, "2592000s")
        self.assertEqual(
            secret_facts.secret_manager_version_destroy_ttl,
            "604800s",
        )
        self.assertEqual(
            secret_facts.resource_policy_source_addresses,
            ["google_secret_manager_secret_iam_member.conditional_integrity"],
        )
        self.assertEqual(len(secret_facts.bindings), 1)
        binding = secret_facts.bindings[0]
        self.assertEqual(binding["role"], _GCP_CUSTOM_ROLE_NAME)
        self.assertEqual(
            binding["members"],
            [_GCP_SERVICE_ACCOUNT_MEMBER],
        )
        self.assertEqual(binding["condition"], condition)

        custom_role_facts = gcp_facts(custom_role)
        self.assertEqual(
            custom_role_facts.custom_role_permissions,
            [
                *_GCP_INTEGRITY_PERMISSIONS,
                *_GCP_DISRUPTION_PERMISSIONS,
                *_GCP_QUIET_PERMISSIONS,
            ],
        )
        self.assertEqual(
            custom_role_facts.custom_role_permissions_state,
            "configured",
        )

        member_facts = gcp_facts(secret_member)
        self.assertEqual(member_facts.target_reference, _GCP_SECRET_NAME)
        self.assertEqual(member_facts.iam_scope_reference_state, "configured")
        self.assertEqual(member_facts.role, _GCP_CUSTOM_ROLE_NAME)
        self.assertEqual(member_facts.member, _GCP_SERVICE_ACCOUNT_MEMBER)
        self.assertEqual(member_facts.bindings[0]["condition"], condition)

        project_member_facts = gcp_facts(project_member)
        self.assertEqual(project_member_facts.project, _GCP_PROJECT)
        self.assertEqual(
            project_member_facts.role,
            "roles/secretmanager.admin",
        )
        self.assertEqual(
            project_member_facts.member,
            _GCP_SERVICE_ACCOUNT_MEMBER,
        )
        self.assertEqual(
            gcp_facts(unknown_policy).iam_policy_data_state,
            "unknown",
        )

        # These permissions are normalized as separate evidence. Read,
        # recovery, and metadata operations do not imply an integrity path.
        self.assertEqual(workload_facts.cloud_run_secret_access_paths, [])

    def test_gcp_overlapping_authoritative_iam_sources_remain_separate(
        self,
    ) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gcp_cloud_run(),
                _gcp_public_invoker(),
                _gcp_secret(),
                _gcp_secret_integrity_role(),
                _gcp_secret_binding(),
                _gcp_secret_policy(),
            ]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
        secret = inventory.get_by_address("google_secret_manager_secret.orders")
        binding = inventory.get_by_address("google_secret_manager_secret_iam_binding.integrity_managers")
        policy = inventory.get_by_address("google_secret_manager_secret_iam_policy.authoritative")
        assert workload is not None
        assert secret is not None
        assert binding is not None
        assert policy is not None

        self.assertTrue(workload.public_exposure)
        secret_facts = gcp_facts(secret)
        self.assertEqual(
            set(secret_facts.resource_policy_source_addresses),
            {
                "google_secret_manager_secret_iam_binding.integrity_managers",
                "google_secret_manager_secret_iam_policy.authoritative",
            },
        )
        bindings_by_source = {item["source"]: item for item in secret_facts.bindings}
        self.assertEqual(
            bindings_by_source["google_secret_manager_secret_iam_binding.integrity_managers"]["members"],
            [
                _GCP_SERVICE_ACCOUNT_MEMBER,
                "group:operators@example.com",
            ],
        )
        self.assertEqual(
            bindings_by_source["google_secret_manager_secret_iam_policy.authoritative"]["members"],
            [f"serviceAccount:policy-admin@{_GCP_PROJECT}.iam.gserviceaccount.com"],
        )
        self.assertEqual(
            gcp_facts(binding).iam_scope_reference_state,
            "configured",
        )
        self.assertEqual(
            gcp_facts(policy).iam_policy_data_state,
            "configured",
        )
        self.assertEqual(
            gcp_facts(workload).cloud_run_secret_access_paths,
            [],
        )

    def test_gcp_unresolved_member_and_custom_permissions_remain_non_authoritative(
        self,
    ) -> None:
        unresolved_member = "serviceAccount:${google_service_account.runtime.email}"
        inventory = GcpNormalizer().normalize(
            [
                _gcp_cloud_run(),
                _gcp_public_invoker(),
                _gcp_secret(),
                _gcp_secret_integrity_role(permissions_unknown=True),
                _gcp_secret_member(
                    "unknown_integrity",
                    member=unresolved_member,
                    unknown_values={"member": True},
                ),
            ]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
        secret = inventory.get_by_address("google_secret_manager_secret.orders")
        custom_role = inventory.get_by_address("google_project_iam_custom_role.secret_integrity")
        iam_member = inventory.get_by_address("google_secret_manager_secret_iam_member.unknown_integrity")
        assert workload is not None
        assert secret is not None
        assert custom_role is not None
        assert iam_member is not None

        self.assertTrue(workload.public_exposure)
        self.assertEqual(
            gcp_facts(custom_role).custom_role_permissions,
            [],
        )
        self.assertEqual(
            gcp_facts(custom_role).custom_role_permissions_state,
            "unknown",
        )
        self.assertEqual(gcp_facts(iam_member).member, unresolved_member)
        self.assertEqual(
            gcp_facts(iam_member).bindings[0]["members_state"],
            "unknown",
        )
        self.assertEqual(gcp_facts(secret).bindings, [])
        self.assertEqual(
            gcp_facts(workload).cloud_run_secret_access_paths,
            [],
        )

    def test_azure_public_app_preserves_runtime_and_reference_identity_boundaries(
        self,
    ) -> None:
        condition = "@Resource[Microsoft.KeyVault/vaults/secrets:Name] StringEqualsIgnoreCase 'orders'"
        inventory = AzureNormalizer().normalize(
            [
                _azure_vault(),
                _azure_secret(),
                _azure_identity(
                    "runtime",
                    identity_id=_AZURE_RUNTIME_IDENTITY_ID,
                    principal_id=_AZURE_RUNTIME_PRINCIPAL_ID,
                ),
                _azure_identity(
                    "reference_reader",
                    identity_id=_AZURE_REFERENCE_IDENTITY_ID,
                    principal_id=_AZURE_REFERENCE_PRINCIPAL_ID,
                ),
                _azure_web_app(),
                _azure_secret_admin_role(),
                _azure_role_assignment(
                    "system_secret_integrity",
                    principal_id=_AZURE_SYSTEM_PRINCIPAL_ID,
                    role_definition_id=("azurerm_role_definition.secret_integrity.role_definition_resource_id"),
                    role_definition_name="Orders Secret Integrity",
                ),
                _azure_role_assignment(
                    "user_secret_integrity",
                    principal_id=_AZURE_RUNTIME_PRINCIPAL_ID,
                    role_definition_id=("azurerm_role_definition.secret_integrity.role_definition_resource_id"),
                    role_definition_name="Orders Secret Integrity",
                    condition=condition,
                ),
                _azure_reference_reader_assignment(),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        runtime_identity = inventory.get_by_address("azurerm_user_assigned_identity.runtime")
        reference_identity = inventory.get_by_address("azurerm_user_assigned_identity.reference_reader")
        vault = inventory.get_by_address("azurerm_key_vault.orders")
        secret = inventory.get_by_address("azurerm_key_vault_secret.orders")
        role = inventory.get_by_address("azurerm_role_definition.secret_integrity")
        conditioned_assignment = inventory.get_by_address("azurerm_role_assignment.user_secret_integrity")
        assert workload is not None
        assert runtime_identity is not None
        assert reference_identity is not None
        assert vault is not None
        assert secret is not None
        assert role is not None
        assert conditioned_assignment is not None

        workload_facts = azure_facts(workload)
        self.assertTrue(workload.public_access_configured)
        self.assertTrue(workload_facts.public_network_access_enabled)
        self.assertTrue(workload_facts.has_system_assigned_identity)
        self.assertTrue(workload_facts.has_user_assigned_identity)
        self.assertEqual(
            workload_facts.principal_id,
            _AZURE_SYSTEM_PRINCIPAL_ID,
        )
        self.assertEqual(
            workload_facts.attached_identity_references,
            [
                _AZURE_RUNTIME_IDENTITY_ID,
                _AZURE_REFERENCE_IDENTITY_ID,
            ],
        )
        self.assertEqual(
            workload_facts.app_service_key_vault_reference_identity_id,
            "azurerm_user_assigned_identity.reference_reader.id",
        )
        self.assertEqual(runtime_identity.identifier, _AZURE_RUNTIME_IDENTITY_ID)
        self.assertEqual(
            reference_identity.identifier,
            _AZURE_REFERENCE_IDENTITY_ID,
        )

        secret_facts = azure_facts(secret)
        self.assertEqual(secret_facts.resolved_key_vault_address, vault.address)
        self.assertEqual(
            secret_facts.key_vault_secret_versionless_uri,
            _AZURE_SECRET_VERSIONLESS_URI,
        )
        self.assertEqual(
            secret_facts.key_vault_secret_uri,
            _AZURE_SECRET_URI,
        )
        self.assertEqual(
            secret_facts.key_vault_secret_resource_id,
            _AZURE_SECRET_RESOURCE_ID,
        )
        self.assertEqual(
            secret_facts.key_vault_secret_version,
            _AZURE_SECRET_VERSION,
        )
        self.assertEqual(
            secret_facts.key_vault_expiration_date,
            "2027-07-28T00:00:00Z",
        )
        self.assertEqual(
            secret_facts.key_vault_not_before_date,
            "2026-07-28T00:00:00Z",
        )

        vault_facts = azure_facts(vault)
        self.assertTrue(vault_facts.rbac_authorization_enabled)
        self.assertFalse(vault_facts.purge_protection_enabled)
        self.assertEqual(vault_facts.key_vault_recovery_uncertainties, [])

        role_facts = azure_facts(role)
        self.assertEqual(
            role_facts.role_definition_data_actions,
            [
                *_AZURE_INTEGRITY_ACTIONS,
                *_AZURE_DISRUPTION_ACTIONS,
                *_AZURE_QUIET_ACTIONS,
            ],
        )
        self.assertEqual(
            role_facts.role_definition_not_data_actions,
            ["Microsoft.KeyVault/vaults/secrets/backup/action"],
        )
        self.assertEqual(role_facts.role_definition_uncertainties, [])

        system_assignments = {item["source"] for item in workload_facts.managed_identity_role_assignments}
        runtime_assignments = {
            item["source"] for item in azure_facts(runtime_identity).managed_identity_role_assignments
        }
        reference_assignments = {
            item["source"] for item in azure_facts(reference_identity).managed_identity_role_assignments
        }
        self.assertEqual(
            system_assignments,
            {"azurerm_role_assignment.system_secret_integrity"},
        )
        self.assertEqual(
            runtime_assignments,
            {"azurerm_role_assignment.user_secret_integrity"},
        )
        self.assertEqual(
            reference_assignments,
            {"azurerm_role_assignment.reference_reader"},
        )

        conditioned_facts = azure_facts(conditioned_assignment)
        self.assertEqual(conditioned_facts.role_assignment_condition, condition)
        self.assertEqual(
            conditioned_facts.role_assignment_condition_version,
            "2.0",
        )
        self.assertEqual(
            conditioned_facts.resolved_role_definition_address,
            role.address,
        )

        # Existing App Service secret delivery deliberately follows the
        # reference identity. Runtime secret-integrity analysis must not reuse
        # that selection as arbitrary application-code authority.
        self.assertEqual(
            len(workload_facts.app_service_key_vault_access_paths),
            1,
        )
        read_path = workload_facts.app_service_key_vault_access_paths[0]
        self.assertEqual(
            read_path["identity_address"],
            reference_identity.address,
        )
        self.assertEqual(
            read_path["principal_id"],
            _AZURE_REFERENCE_PRINCIPAL_ID,
        )
        self.assertEqual(
            read_path["identity_resolution_basis"],
            "key_vault_reference_identity_id",
        )
        self.assertNotEqual(
            read_path["principal_id"],
            _AZURE_SYSTEM_PRINCIPAL_ID,
        )
        self.assertNotEqual(
            read_path["principal_id"],
            _AZURE_RUNTIME_PRINCIPAL_ID,
        )

        self.assertNotIn(
            _SECRET_PAYLOAD_SENTINEL,
            json.dumps(secret.metadata, sort_keys=True, default=str),
        )

    def test_azure_legacy_policy_and_unknown_rbac_recovery_remain_distinct(
        self,
    ) -> None:
        legacy_inventory = AzureNormalizer().normalize(
            [
                _azure_vault(rbac_enabled=False),
                _azure_secret(),
                _azure_identity(
                    "runtime",
                    identity_id=_AZURE_RUNTIME_IDENTITY_ID,
                    principal_id=_AZURE_RUNTIME_PRINCIPAL_ID,
                ),
                _azure_web_app(public=False),
                _azure_access_policy(),
            ]
        )
        workload = legacy_inventory.get_by_address("azurerm_linux_web_app.orders")
        vault = legacy_inventory.get_by_address("azurerm_key_vault.orders")
        assert workload is not None
        assert vault is not None

        self.assertFalse(workload.public_access_configured)
        vault_facts = azure_facts(vault)
        self.assertFalse(vault_facts.rbac_authorization_enabled)
        self.assertEqual(len(vault_facts.key_vault_access_policies), 1)
        policy = vault_facts.key_vault_access_policies[0]
        self.assertEqual(policy["object_id"], _AZURE_RUNTIME_PRINCIPAL_ID)
        self.assertEqual(
            policy["secret_permissions"],
            [
                "backup",
                "delete",
                "get",
                "list",
                "purge",
                "recover",
                "restore",
                "set",
            ],
        )

        unknown_inventory = AzureNormalizer().normalize(
            [
                _azure_vault(purge_protection_enabled=None),
                _azure_secret_admin_role(permissions_unknown=True),
                _azure_role_assignment(
                    "unknown_secret_integrity",
                    principal_id=_AZURE_SYSTEM_PRINCIPAL_ID,
                    role_definition_id=("azurerm_role_definition.secret_integrity.role_definition_resource_id"),
                    role_definition_name="Orders Secret Integrity",
                ),
            ]
        )
        unknown_vault = unknown_inventory.get_by_address("azurerm_key_vault.orders")
        unknown_role = unknown_inventory.get_by_address("azurerm_role_definition.secret_integrity")
        assert unknown_vault is not None
        assert unknown_role is not None

        unknown_vault_facts = azure_facts(unknown_vault)
        unknown_role_facts = azure_facts(unknown_role)
        self.assertIsNone(unknown_vault_facts.purge_protection_enabled)
        self.assertTrue(unknown_vault_facts.key_vault_recovery_uncertainties)
        self.assertEqual(unknown_role_facts.role_definition_data_actions, [])
        self.assertTrue(unknown_role_facts.role_definition_uncertainties)

    def test_private_workloads_retain_authority_without_public_exposure(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize(
            [
                *_aws_public_edge(internal=True),
                _aws_runtime_role(),
                _aws_execution_role_with_secret_admin(),
                _aws_task_definition(),
                _aws_ecs_service(),
                _aws_secret(),
            ]
        )
        aws_workload = aws_inventory.get_by_address("aws_ecs_service.orders")
        aws_load_balancer = aws_inventory.get_by_address("aws_lb.public")
        aws_role = aws_inventory.get_by_address("aws_iam_role.orders_task")
        assert aws_workload is not None
        assert aws_load_balancer is not None
        assert aws_role is not None
        self.assertFalse(aws_load_balancer.public_exposure)
        self.assertFalse(aws_workload.get_metadata_field(AwsResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER))
        self.assertEqual(
            aws_facts(aws_workload).task_role_arn,
            _AWS_TASK_ROLE_ARN,
        )
        self.assertEqual(len(aws_role.policy_statements), 4)

        gcp_inventory = GcpNormalizer().normalize(
            [
                _gcp_cloud_run(public_ingress=False),
                _gcp_secret(),
                _gcp_secret_integrity_role(),
                _gcp_secret_member("private_integrity"),
            ]
        )
        gcp_workload = gcp_inventory.get_by_address("google_cloud_run_v2_service.orders")
        gcp_role = gcp_inventory.get_by_address("google_project_iam_custom_role.secret_integrity")
        assert gcp_workload is not None
        assert gcp_role is not None
        self.assertFalse(gcp_workload.public_exposure)
        self.assertEqual(
            gcp_facts(gcp_workload).service_account_member,
            _GCP_SERVICE_ACCOUNT_MEMBER,
        )
        self.assertEqual(
            gcp_facts(gcp_role).custom_role_permissions_state,
            "configured",
        )

        azure_inventory = AzureNormalizer().normalize(
            [
                _azure_vault(),
                _azure_secret(),
                _azure_web_app(public=False),
                _azure_secret_admin_role(),
                _azure_role_assignment(
                    "private_secret_integrity",
                    principal_id=_AZURE_SYSTEM_PRINCIPAL_ID,
                    role_definition_id=("azurerm_role_definition.secret_integrity.role_definition_resource_id"),
                    role_definition_name="Orders Secret Integrity",
                ),
            ]
        )
        azure_workload = azure_inventory.get_by_address("azurerm_linux_web_app.orders")
        azure_role = azure_inventory.get_by_address("azurerm_role_definition.secret_integrity")
        assert azure_workload is not None
        assert azure_role is not None
        self.assertFalse(azure_workload.public_access_configured)
        self.assertEqual(
            azure_facts(azure_workload).principal_id,
            _AZURE_SYSTEM_PRINCIPAL_ID,
        )
        self.assertEqual(
            azure_facts(azure_role).role_definition_data_actions,
            [
                *_AZURE_INTEGRITY_ACTIONS,
                *_AZURE_DISRUPTION_ACTIONS,
                *_AZURE_QUIET_ACTIONS,
            ],
        )

    def test_provider_local_evidence_does_not_cross_secret_boundaries(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize([_aws_runtime_role(), _aws_secret(), _aws_secret_policy()])
        gcp_inventory = GcpNormalizer().normalize(
            [
                _gcp_secret(),
                _gcp_secret_integrity_role(),
                _gcp_secret_member("integrity"),
            ]
        )
        azure_inventory = AzureNormalizer().normalize([_azure_vault(), _azure_secret(), _azure_access_policy()])

        payloads = {
            "aws": json.dumps(
                [
                    {
                        "address": resource.address,
                        "metadata": resource.metadata,
                        "policy_statements": [
                            {
                                "actions": statement.actions,
                                "resources": statement.resources,
                                "principals": statement.principals,
                            }
                            for statement in resource.policy_statements
                        ],
                    }
                    for resource in aws_inventory.resources
                ],
                sort_keys=True,
                default=str,
            ),
            "gcp": json.dumps(
                [
                    {
                        "address": resource.address,
                        "metadata": resource.metadata,
                    }
                    for resource in gcp_inventory.resources
                ],
                sort_keys=True,
                default=str,
            ),
            "azure": json.dumps(
                [
                    {
                        "address": resource.address,
                        "metadata": resource.metadata,
                    }
                    for resource in azure_inventory.resources
                ],
                sort_keys=True,
                default=str,
            ),
        }

        foreign_prefixes = {
            "aws": ("google_", "azurerm_"),
            "gcp": ("aws_", "azurerm_"),
            "azure": ("aws_", "google_"),
        }
        for provider, payload in payloads.items():
            with self.subTest(provider=provider):
                self.assertNotIn(
                    _SECRET_PAYLOAD_SENTINEL,
                    payload,
                )
                for prefix in foreign_prefixes[provider]:
                    self.assertNotIn(prefix, payload)


if __name__ == "__main__":
    unittest.main()

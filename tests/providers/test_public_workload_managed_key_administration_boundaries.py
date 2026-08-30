from __future__ import annotations

import json
import unittest
from typing import Any

from tests.providers.test_public_workload_managed_key_operation_boundaries import (
    _AWS_ACCOUNT_ID,
    _AWS_EXTERNAL_POLICY_ARN,
    _AWS_KEY_ARNS,
    _AWS_KEY_IDS,
    _AWS_TASK_ROLE_ARN,
    _AZURE_RUNTIME_PRINCIPAL_ID,
    _AZURE_SUBSCRIPTION_ID,
    _AZURE_VAULT_ID,
    _GCP_KEY_RING,
    _GCP_PROJECT,
    _GCP_SERVICE_ACCOUNT_MEMBER,
    _aws_ecs_service,
    _aws_execution_role,
    _aws_public_edge,
    _aws_task_definition,
    _azure_key,
    _azure_role_assignment,
    _azure_vault,
    _azure_web_app,
    _gcp_cloud_run,
    _gcp_key,
    _gcp_key_member,
    _gcp_project_member,
    _gcp_public_invoker,
    _gcp_version,
    _resource,
)
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_AWS_IMPORTED_KEY_ID = "44444444-4444-4444-4444-444444444444"
_AWS_IMPORTED_KEY_ARN = f"arn:aws:kms:us-east-1:{_AWS_ACCOUNT_ID}:key/{_AWS_IMPORTED_KEY_ID}"
_AWS_DISRUPTIVE_ACTIONS = (
    "kms:DisableKey",
    "kms:ScheduleKeyDeletion",
)
_AWS_DELEGATION_ACTIONS = (
    "kms:CreateGrant",
    "kms:PutKeyPolicy",
)
_AWS_QUIET_ADMIN_ACTIONS = (
    "kms:CancelKeyDeletion",
    "kms:EnableKey",
    "kms:GetKeyPolicy",
    "kms:RotateKeyOnDemand",
)

_AZURE_CRYPTO_OFFICER_ROLE_ID = (
    "/providers/Microsoft.Authorization/roleDefinitions/14b46e9e-c2b7-41b4-b07b-48a6ebf60603"
)
_AZURE_CUSTOM_ADMIN_ROLE_ID = (
    f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/orders-key-admin"
)
_AZURE_CONTROL_PLANE_ROLE_ID = (
    f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}/providers/"
    "Microsoft.Authorization/roleDefinitions/orders-key-authorization-admin"
)


def _aws_key_policy(actions: list[str]) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowRuntimeAdministration",
                    "Effect": "Allow",
                    "Principal": {"AWS": _AWS_TASK_ROLE_ARN},
                    "Action": actions,
                    "Resource": "*",
                }
            ],
        }
    )


def _aws_admin_key(
    name: str,
    *,
    key_id: str,
    key_arn: str,
    origin: str,
    policy_actions: list[str],
) -> TerraformResource:
    return _resource(
        "aws",
        "aws_kms_key",
        name,
        {
            "id": key_id,
            "key_id": key_id,
            "arn": key_arn,
            "key_usage": "ENCRYPT_DECRYPT",
            "key_spec": "SYMMETRIC_DEFAULT",
            "origin": origin,
            "multi_region": False,
            "deletion_window_in_days": 30,
            "policy": _aws_key_policy(policy_actions),
        },
    )


def _aws_admin_role() -> TerraformResource:
    statements = [
        {
            "Effect": "Allow",
            "Action": list(_AWS_DISRUPTIVE_ACTIONS),
            "Resource": _AWS_KEY_ARNS["data"],
        },
        {
            "Effect": "Allow",
            "Action": list(_AWS_DELEGATION_ACTIONS),
            "Resource": _AWS_KEY_ARNS["data"],
        },
        {
            "Effect": "Allow",
            "Action": "kms:DeleteImportedKeyMaterial",
            "Resource": _AWS_IMPORTED_KEY_ARN,
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalTag/environment": "production",
                }
            },
        },
        {
            "Effect": "Deny",
            "Action": "kms:ScheduleKeyDeletion",
            "Resource": _AWS_KEY_ARNS["data"],
        },
        {
            "Effect": "Allow",
            "Action": list(_AWS_QUIET_ADMIN_ACTIONS),
            "Resource": _AWS_KEY_ARNS["data"],
        },
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
                    "name": "kms-administration",
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


def _aws_admin_grant() -> TerraformResource:
    return _resource(
        "aws",
        "aws_kms_grant",
        "runtime_delegation",
        {
            "id": "grant-runtime-delegation",
            "grant_id": "grant-runtime-delegation",
            "name": "runtime-delegation",
            "key_id": "aws_kms_key.data.key_id",
            "grantee_principal": _AWS_TASK_ROLE_ARN,
            "operations": ["CreateGrant"],
            "constraints": [
                {
                    "encryption_context_equals": {
                        "service": "orders",
                    }
                }
            ],
        },
    )


def _gcp_ring_member(
    name: str,
    *,
    condition: dict[str, str] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "key_ring_id": _GCP_KEY_RING,
        "role": "roles/cloudkms.admin",
        "member": _GCP_SERVICE_ACCOUNT_MEMBER,
    }
    if condition is not None:
        values["condition"] = [condition]
    return _resource(
        "google",
        GcpResourceType.KMS_KEY_RING_IAM_MEMBER,
        name,
        values,
    )


def _azure_custom_admin_role(
    *,
    unknown_permissions: bool = False,
) -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.ROLE_DEFINITION,
        "key_admin",
        {
            "id": _AZURE_CUSTOM_ADMIN_ROLE_ID,
            "role_definition_id": _AZURE_CUSTOM_ADMIN_ROLE_ID,
            "name": "Orders Key Administrator",
            "scope": f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}",
            "assignable_scopes": [f"{_AZURE_VAULT_ID}/keys/data"],
            "permissions": [
                {
                    "actions": [],
                    "not_actions": [],
                    "data_actions": ["Microsoft.KeyVault/vaults/keys/*"],
                    "not_data_actions": [
                        "Microsoft.KeyVault/vaults/keys/delete",
                        "Microsoft.KeyVault/vaults/keys/purge/action",
                    ],
                }
            ],
        },
        unknown_values=(
            {"permissions": [{"data_actions": True, "not_data_actions": True}]} if unknown_permissions else None
        ),
    )


def _azure_control_plane_admin_role() -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.ROLE_DEFINITION,
        "key_authorization_admin",
        {
            "id": _AZURE_CONTROL_PLANE_ROLE_ID,
            "role_definition_id": _AZURE_CONTROL_PLANE_ROLE_ID,
            "name": "Orders Key Authorization Administrator",
            "scope": f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}",
            "assignable_scopes": [_AZURE_VAULT_ID],
            "permissions": [
                {
                    "actions": [
                        "Microsoft.Authorization/roleAssignments/write",
                        "Microsoft.KeyVault/vaults/accessPolicies/write",
                    ],
                    "not_actions": [],
                    "data_actions": [],
                    "not_data_actions": [],
                }
            ],
        },
    )


class PublicWorkloadManagedKeyAdministrationBoundaryTests(unittest.TestCase):
    """Pin administration prerequisites without constructing workload paths."""

    def test_aws_public_ecs_preserves_admin_authority_and_key_lifecycle_boundaries(
        self,
    ) -> None:
        all_data_actions = [
            *_AWS_DISRUPTIVE_ACTIONS,
            *_AWS_DELEGATION_ACTIONS,
            *_AWS_QUIET_ADMIN_ACTIONS,
        ]
        inventory = AwsNormalizer().normalize(
            [
                *_aws_public_edge(),
                _aws_admin_role(),
                _aws_execution_role(),
                _aws_task_definition(),
                _aws_ecs_service(),
                _aws_admin_key(
                    "data",
                    key_id=_AWS_KEY_IDS["data"],
                    key_arn=_AWS_KEY_ARNS["data"],
                    origin="AWS_KMS",
                    policy_actions=all_data_actions,
                ),
                _aws_admin_key(
                    "imported",
                    key_id=_AWS_IMPORTED_KEY_ID,
                    key_arn=_AWS_IMPORTED_KEY_ARN,
                    origin="EXTERNAL",
                    policy_actions=["kms:DeleteImportedKeyMaterial"],
                ),
                _aws_admin_grant(),
            ]
        )
        workload = inventory.get_by_address("aws_ecs_service.orders")
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        role = inventory.get_by_address("aws_iam_role.orders_task")
        data_key = inventory.get_by_address("aws_kms_key.data")
        imported_key = inventory.get_by_address("aws_kms_key.imported")
        grant = inventory.get_by_address("aws_kms_grant.runtime_delegation")
        assert workload is not None
        assert task_definition is not None
        assert role is not None
        assert data_key is not None
        assert imported_key is not None
        assert grant is not None

        workload_facts = aws_facts(workload)
        role_facts = aws_facts(role)
        self.assertEqual(
            workload_facts.internet_facing_load_balancer_addresses,
            ["aws_lb.public"],
        )
        self.assertEqual(workload_facts.task_role_arn, _AWS_TASK_ROLE_ARN)
        self.assertEqual(role_facts.iam_policy_completeness_state, "complete")
        self.assertEqual(len(role.policy_statements), 5)

        disruptive, delegation, imported, deny, quiet = role.policy_statements
        self.assertEqual(disruptive.actions, list(_AWS_DISRUPTIVE_ACTIONS))
        self.assertEqual(disruptive.resources, [_AWS_KEY_ARNS["data"]])
        self.assertEqual(delegation.actions, list(_AWS_DELEGATION_ACTIONS))
        self.assertEqual(delegation.resources, [_AWS_KEY_ARNS["data"]])
        self.assertEqual(imported.actions, ["kms:DeleteImportedKeyMaterial"])
        self.assertEqual(imported.resources, [_AWS_IMPORTED_KEY_ARN])
        self.assertEqual(
            [(condition.operator, condition.key, condition.values) for condition in imported.conditions],
            [
                (
                    "StringEquals",
                    "aws:PrincipalTag/environment",
                    ["production"],
                )
            ],
        )
        self.assertEqual(deny.effect, "Deny")
        self.assertEqual(deny.actions, ["kms:ScheduleKeyDeletion"])
        self.assertEqual(quiet.actions, list(_AWS_QUIET_ADMIN_ACTIONS))

        data_facts = aws_facts(data_key)
        imported_facts = aws_facts(imported_key)
        self.assertEqual(data_key.arn, _AWS_KEY_ARNS["data"])
        self.assertEqual(data_facts.kms_key_origin, "AWS_KMS")
        self.assertEqual(data_facts.kms_deletion_window_in_days, 30)
        self.assertEqual(imported_key.arn, _AWS_IMPORTED_KEY_ARN)
        self.assertEqual(imported_facts.kms_key_origin, "EXTERNAL")
        self.assertEqual(imported_facts.kms_deletion_window_in_days, 30)

        grant_facts = aws_facts(grant)
        self.assertEqual(
            grant_facts.kms_grant_resolved_key_address,
            data_key.address,
        )
        self.assertEqual(grant_facts.kms_grant_operations, ["CreateGrant"])
        self.assertEqual(
            grant_facts.kms_grant_constraints,
            {"encryption_context_equals": {"service": "orders"}},
        )

        data_authorizations = {
            authorization["operation"]: authorization for authorization in data_facts.kms_operation_authorizations
        }
        self.assertEqual(set(data_authorizations), set(all_data_actions))

        create_grant = data_authorizations["kms:CreateGrant"]
        self.assertEqual(create_grant["authorization_state"], "allowed")
        self.assertEqual(
            create_grant["authorization_bases"],
            ["direct_key_policy", "kms_grant"],
        )
        self.assertEqual(
            create_grant["supported_authorization_bases"],
            [
                "direct_key_policy",
                "iam_via_account_principal",
                "kms_grant",
            ],
        )
        self.assertEqual(create_grant["constraint_state"], "encryption_context")

        schedule_deletion = data_authorizations["kms:ScheduleKeyDeletion"]
        self.assertEqual(
            schedule_deletion["operation_class"],
            "destructive_administration",
        )
        self.assertEqual(schedule_deletion["authorization_state"], "denied")
        self.assertTrue(schedule_deletion["explicit_deny"])

        self.assertEqual(
            data_authorizations["kms:PutKeyPolicy"]["operation_class"],
            "authorization_administration",
        )
        self.assertEqual(
            {operation: data_authorizations[operation]["operation_class"] for operation in _AWS_QUIET_ADMIN_ACTIONS},
            {
                "kms:CancelKeyDeletion": "recovery",
                "kms:EnableKey": "recovery",
                "kms:GetKeyPolicy": "metadata_read",
                "kms:RotateKeyOnDemand": "lifecycle_administration",
            },
        )

        imported_authorizations = imported_facts.kms_operation_authorizations
        self.assertEqual(len(imported_authorizations), 1)
        imported_material = imported_authorizations[0]
        self.assertEqual(
            imported_material["operation"],
            "kms:DeleteImportedKeyMaterial",
        )
        self.assertEqual(imported_material["authorization_state"], "allowed")
        self.assertEqual(imported_material["key_origin"], "EXTERNAL")
        self.assertEqual(
            imported_material["required_key_origins"],
            ["EXTERNAL"],
        )
        self.assertEqual(
            imported_material["key_origin_compatibility_state"],
            "compatible",
        )
        self.assertTrue(imported_material["conditional_policy_evidence_present"])
        self.assertFalse(imported_material["authorization_requires_condition_evaluation"])

        # Administrative authority uses a separate path family; recovery,
        # rotation, and metadata-only operations remain quiet.
        task_management_paths = aws_facts(task_definition).ecs_kms_management_paths
        self.assertEqual(
            [(path["key_address"], path["operation"], path["management_effect"]) for path in task_management_paths],
            [
                ("aws_kms_key.data", "kms:CreateGrant", "delegation"),
                ("aws_kms_key.data", "kms:PutKeyPolicy", "delegation"),
                ("aws_kms_key.data", "kms:DisableKey", "disruption"),
                ("aws_kms_key.imported", "kms:DeleteImportedKeyMaterial", "disruption"),
            ],
        )
        self.assertEqual(
            task_management_paths[0]["grant_constraints"],
            [{"encryption_context_equals": {"service": "orders"}}],
        )
        imported_path = task_management_paths[-1]
        self.assertEqual(imported_path["key_origin"], "EXTERNAL")
        self.assertEqual(imported_path["key_origin_compatibility_state"], "compatible")
        self.assertTrue(imported_path["conditional_policy_evidence_present"])
        self.assertFalse(imported_path["authorization_requires_condition_evaluation"])

        service_management_paths = workload_facts.ecs_kms_management_paths
        self.assertEqual(len(service_management_paths), 4)
        self.assertTrue(all(path["workload_address"] == workload.address for path in service_management_paths))
        self.assertTrue(
            all(path["task_definition_address"] == task_definition.address for path in service_management_paths)
        )
        self.assertTrue(
            all(path.get("internet_facing_load_balancers") == ["aws_lb.public"] for path in service_management_paths)
        )
        self.assertEqual(aws_facts(task_definition).ecs_kms_operation_paths, [])
        self.assertEqual(workload_facts.ecs_kms_operation_paths, [])

    def test_gcp_public_cloud_run_preserves_admin_scopes_and_version_recovery(
        self,
    ) -> None:
        condition = {
            "title": "maintenance-window",
            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
        }
        key = _gcp_key("data", "ENCRYPT_DECRYPT")
        key.values["rotation_period"] = "7776000s"
        key.values["destroy_scheduled_duration"] = "604800s"
        version = _gcp_version(
            "data",
            algorithm="GOOGLE_SYMMETRIC_ENCRYPTION",
        )
        version.values["state"] = "DESTROY_SCHEDULED"
        version.values["deletion_policy"] = "ABANDON"
        inventory = GcpNormalizer().normalize(
            [
                _gcp_cloud_run(),
                _gcp_public_invoker(),
                key,
                version,
                _gcp_project_member(
                    "runtime_project_admin",
                    "roles/cloudkms.admin",
                ),
                _gcp_ring_member(
                    "runtime_ring_admin",
                    condition=condition,
                ),
                _gcp_key_member(
                    "runtime_key_admin",
                    "data",
                    "roles/cloudkms.admin",
                ),
            ]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
        normalized_key = inventory.get_by_address("google_kms_crypto_key.data")
        normalized_version = inventory.get_by_address("google_kms_crypto_key_version.data")
        assert workload is not None
        assert normalized_key is not None
        assert normalized_version is not None

        workload_facts = gcp_facts(workload)
        key_facts = gcp_facts(normalized_key)
        version_facts = gcp_facts(normalized_version)
        self.assertTrue(workload.public_exposure)
        self.assertEqual(
            workload_facts.service_account_member,
            _GCP_SERVICE_ACCOUNT_MEMBER,
        )
        self.assertEqual(
            normalized_key.identifier,
            f"{_GCP_KEY_RING}/cryptoKeys/data",
        )

        grants = {grant["source"]: grant for grant in key_facts.kms_iam_grants}
        project_grant = grants["google_project_iam_member.runtime_project_admin"]
        ring_grant = grants["google_kms_key_ring_iam_member.runtime_ring_admin"]
        key_grant = grants["google_kms_crypto_key_iam_member.runtime_key_admin"]
        self.assertEqual(project_grant["scope_type"], "project")
        self.assertEqual(project_grant["scope"], _GCP_PROJECT)
        self.assertEqual(project_grant["authorization_state"], "granted")
        self.assertEqual(ring_grant["scope_type"], "key_ring")
        self.assertEqual(ring_grant["scope"], _GCP_KEY_RING)
        self.assertEqual(ring_grant.get("condition"), condition)
        self.assertEqual(ring_grant["authorization_state"], "conditional")
        self.assertEqual(key_grant["scope_type"], "crypto_key")
        self.assertEqual(key_grant["scope"], normalized_key.identifier)
        self.assertEqual(key_grant["authorization_state"], "granted")

        effective_permissions = set(key_grant["scope_effective_permissions"])
        self.assertTrue(
            {
                "cloudkms.cryptoKeys.delete",
                "cloudkms.cryptoKeys.setIamPolicy",
                "cloudkms.cryptoKeyVersions.destroy",
                "cloudkms.cryptoKeyVersions.update",
            }.issubset(effective_permissions)
        )
        self.assertTrue(
            {
                "cloudkms.cryptoKeys.create",
                "cloudkms.cryptoKeyVersions.restore",
                "cloudkms.cryptoKeyVersions.trustedImportExport",
            }.issubset(effective_permissions)
        )
        self.assertNotIn(
            "cloudkms.keyRings.setIamPolicy",
            effective_permissions,
        )
        self.assertIn(
            "cloudkms.keyRings.setIamPolicy",
            project_grant["scope_effective_permissions"],
        )

        self.assertEqual(key_facts.kms_destroy_scheduled_duration, "604800s")
        self.assertEqual(
            version_facts.kms_crypto_key_version_resolved_key_address,
            normalized_key.address,
        )
        self.assertEqual(
            version_facts.kms_crypto_key_version_state,
            "DESTROY_SCHEDULED",
        )
        self.assertEqual(
            version_facts.kms_crypto_key_version_destroy_scheduled_duration,
            "604800s",
        )
        self.assertEqual(
            version_facts.kms_crypto_key_version_deletion_policy_state,
            "abandon",
        )

        management_paths = workload_facts.cloud_run_kms_management_paths
        by_source: dict[str, list[dict[str, Any]]] = {}
        for path in management_paths:
            by_source.setdefault(path["iam_resource_address"], []).append(path)
        project_paths = by_source["google_project_iam_member.runtime_project_admin"]
        self.assertEqual(
            {path["operation"] for path in project_paths},
            {
                "cloudkms.cryptoKeys.setIamPolicy",
                "cloudkms.keyRings.setIamPolicy",
            },
        )
        key_paths = by_source["google_kms_crypto_key_iam_member.runtime_key_admin"]
        self.assertEqual(
            {path["operation"] for path in key_paths},
            {
                "cloudkms.cryptoKeys.setIamPolicy",
            },
        )
        self.assertNotIn(
            "google_kms_key_ring_iam_member.runtime_ring_admin",
            by_source,
        )
        self.assertTrue(
            any(
                "authorization_state=conditional" in uncertainty
                for uncertainty in (workload_facts.cloud_run_kms_management_path_uncertainties)
            )
        )

        version_paths = [path for path in management_paths if path["target_type"] == "crypto_key_version"]
        self.assertEqual(version_paths, [])

        ring_policy_path = next(
            path for path in management_paths if path["operation"] == "cloudkms.keyRings.setIamPolicy"
        )
        self.assertEqual(ring_policy_path["target_type"], "key_ring")
        self.assertEqual(ring_policy_path["target_resource_name"], _GCP_KEY_RING)
        self.assertEqual(ring_policy_path["scope_type"], "project")
        self.assertIsNone(ring_policy_path["target_address"])
        self.assertEqual(
            ring_policy_path["target_model_evidence_addresses"],
            [normalized_key.address],
        )
        self.assertFalse(any(path["target_type"] == "project" for path in management_paths))
        self.assertEqual(workload_facts.cloud_run_kms_operation_paths, [])

    def test_azure_public_app_preserves_admin_scopes_exclusions_and_recovery(
        self,
    ) -> None:
        condition = "@Resource[Microsoft.KeyVault/vaults/keys:Name] StringEqualsIgnoreCase 'data'"
        vault = _azure_vault()
        vault.values["purge_protection_enabled"] = False
        key = _azure_key(
            "data",
            key_type="RSA-HSM",
            key_opts=["encrypt", "verify"],
        )
        inventory = AzureNormalizer().normalize(
            [
                vault,
                key,
                _azure_web_app(),
                _azure_role_assignment(
                    "subscription_admin",
                    role_id=_AZURE_CRYPTO_OFFICER_ROLE_ID,
                    role_name="Key Vault Crypto Officer",
                    scope=f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}",
                ),
                _azure_role_assignment(
                    "resource_group_admin",
                    role_id=_AZURE_CRYPTO_OFFICER_ROLE_ID,
                    role_name="Key Vault Crypto Officer",
                    scope=(f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}/resourceGroups/app"),
                ),
                _azure_role_assignment(
                    "vault_admin",
                    role_id=_AZURE_CRYPTO_OFFICER_ROLE_ID,
                    role_name="Key Vault Crypto Officer",
                ),
                _azure_role_assignment(
                    "conditioned_key_admin",
                    role_id=_AZURE_CRYPTO_OFFICER_ROLE_ID,
                    role_name="Key Vault Crypto Officer",
                    scope=("azurerm_key_vault_key.data.resource_versionless_id"),
                    condition=condition,
                ),
                _azure_custom_admin_role(),
                _azure_role_assignment(
                    "restricted_key_admin",
                    role_id=_AZURE_CUSTOM_ADMIN_ROLE_ID,
                    role_name="Orders Key Administrator",
                    scope=("azurerm_key_vault_key.data.resource_versionless_id"),
                ),
                _azure_control_plane_admin_role(),
                _azure_role_assignment(
                    "authorization_admin",
                    role_id=_AZURE_CONTROL_PLANE_ROLE_ID,
                    role_name="Orders Key Authorization Administrator",
                    scope=_AZURE_VAULT_ID,
                ),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        normalized_vault = inventory.get_by_address("azurerm_key_vault.orders")
        normalized_key = inventory.get_by_address("azurerm_key_vault_key.data")
        authorization_role = inventory.get_by_address("azurerm_role_definition.key_authorization_admin")
        authorization_assignment = inventory.get_by_address("azurerm_role_assignment.authorization_admin")
        assert workload is not None
        assert normalized_vault is not None
        assert normalized_key is not None
        assert authorization_role is not None
        assert authorization_assignment is not None

        workload_facts = azure_facts(workload)
        vault_facts = azure_facts(normalized_vault)
        key_facts = azure_facts(normalized_key)
        self.assertTrue(workload.public_access_configured)
        self.assertTrue(workload_facts.public_network_access_enabled)
        self.assertEqual(
            workload_facts.principal_id,
            _AZURE_RUNTIME_PRINCIPAL_ID,
        )
        self.assertFalse(vault_facts.purge_protection_enabled)
        self.assertEqual(
            key_facts.key_vault_key_versionless_resource_id,
            f"{_AZURE_VAULT_ID}/keys/data",
        )

        grants = {grant["grant_source_address"]: grant for grant in key_facts.key_vault_key_authorization_grants}
        expected_scopes = {
            "azurerm_role_assignment.subscription_admin": "subscription",
            "azurerm_role_assignment.resource_group_admin": "resource_group",
            "azurerm_role_assignment.vault_admin": "vault",
            "azurerm_role_assignment.conditioned_key_admin": "key",
            "azurerm_role_assignment.restricted_key_admin": "key",
        }
        self.assertEqual(
            {source: grant["grant_scope_type"] for source, grant in grants.items()},
            expected_scopes,
        )

        broad_grant = grants["azurerm_role_assignment.subscription_admin"]
        self.assertEqual(broad_grant["authorization_state"], "granted")
        self.assertTrue(
            {
                "update",
                "delete",
                "purge",
            }.issubset(set(broad_grant["matched_operations"]))
        )
        self.assertTrue(
            {
                "backup",
                "recover",
                "restore",
                "rotate",
            }.issubset(set(broad_grant["matched_operations"]))
        )
        self.assertTrue(
            {
                "key_backup",
                "key_recovery",
                "key_management",
                "destructive_administration",
            }.issubset(set(broad_grant["access_classes"]))
        )

        conditioned = grants["azurerm_role_assignment.conditioned_key_admin"]
        self.assertEqual(conditioned["condition"], condition)
        self.assertEqual(conditioned["condition_state"], "configured")
        self.assertEqual(
            conditioned["condition_applicability_state"],
            "unsupported",
        )
        self.assertEqual(conditioned["authorization_state"], "unknown")

        restricted = grants["azurerm_role_assignment.restricted_key_admin"]
        self.assertEqual(restricted.get("role_kind"), "custom")
        self.assertEqual(
            restricted.get("excluded_data_actions"),
            [
                "Microsoft.KeyVault/vaults/keys/delete",
                "Microsoft.KeyVault/vaults/keys/purge/action",
            ],
        )
        self.assertNotIn("delete", restricted["matched_operations"])
        self.assertNotIn("purge", restricted["matched_operations"])

        authorization_role_facts = azure_facts(authorization_role)
        authorization_assignment_facts = azure_facts(authorization_assignment)
        self.assertEqual(
            authorization_role_facts.role_definition_actions,
            [
                "Microsoft.Authorization/roleAssignments/write",
                "Microsoft.KeyVault/vaults/accessPolicies/write",
            ],
        )
        self.assertEqual(
            authorization_assignment_facts.resolved_role_definition_address,
            authorization_role.address,
        )
        self.assertEqual(
            authorization_assignment_facts.role_assignment_target_resource_address,
            normalized_vault.address,
        )
        self.assertNotIn(
            authorization_assignment.address,
            grants,
        )

        # The key supports only quiet cryptographic operations, so broad key
        # administration does not create a decrypt or signing path.
        self.assertEqual(
            workload_facts.app_service_key_vault_operation_paths,
            [],
        )
        management_paths = workload_facts.app_service_key_vault_management_paths
        self.assertEqual(
            [
                (
                    path["operation"],
                    path["target_address"],
                    path["management_effect"],
                )
                for path in management_paths
            ],
            [
                (
                    "rbac_role_assignment_management",
                    normalized_vault.address,
                    "delegation",
                ),
                ("delete", normalized_key.address, "disruption"),
                ("delete_plus_purge", normalized_key.address, "disruption"),
                ("update", normalized_key.address, "disruption"),
            ],
        )
        delegation_path = management_paths[0]
        self.assertEqual(
            delegation_path["evaluation_basis"],
            "modeled_arm_control_plane_authority",
        )
        self.assertEqual(delegation_path["data_plane_grants"], [])
        self.assertEqual(
            delegation_path["control_plane_grants"][0]["matched_actions"],
            ["Microsoft.Authorization/roleAssignments/write"],
        )
        delete_sequence = next(path for path in management_paths if path["operation"] == "delete_plus_purge")
        self.assertEqual(delete_sequence["step_operations"], ["delete", "purge"])
        self.assertFalse(delete_sequence["purge_protection_enabled"])

    def test_azure_legacy_policy_preserves_admin_and_recovery_operations(
        self,
    ) -> None:
        vault = _azure_vault(rbac_enabled=False)
        vault.values["purge_protection_enabled"] = True
        inventory = AzureNormalizer().normalize(
            [
                vault,
                _azure_key(
                    "data",
                    key_type="RSA-HSM",
                    key_opts=["encrypt"],
                ),
                _azure_web_app(),
                _resource(
                    "azurerm",
                    AzureResourceType.KEY_VAULT_ACCESS_POLICY,
                    "runtime_admin",
                    {
                        "key_vault_id": "azurerm_key_vault.orders.id",
                        "tenant_id": "tenant-id",
                        "object_id": _AZURE_RUNTIME_PRINCIPAL_ID,
                        "key_permissions": [
                            "Update",
                            "Delete",
                            "Purge",
                            "Backup",
                            "Recover",
                            "Restore",
                            "Rotate",
                            "GetRotationPolicy",
                        ],
                    },
                ),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        normalized_key = inventory.get_by_address("azurerm_key_vault_key.data")
        normalized_vault = inventory.get_by_address("azurerm_key_vault.orders")
        assert workload is not None
        assert normalized_key is not None
        assert normalized_vault is not None

        grants = azure_facts(normalized_key).key_vault_key_authorization_grants
        self.assertEqual(len(grants), 1)
        grant = grants[0]
        self.assertEqual(grant["grant_kind"], "access_policy")
        self.assertEqual(grant["grant_scope_type"], "vault")
        self.assertEqual(grant["authorization_model"], "access_policy")
        self.assertEqual(grant["authorization_state"], "granted")
        self.assertEqual(
            grant["matched_operations"],
            [
                "update",
                "recover",
                "restore",
                "delete",
                "backup",
                "purge",
                "rotate",
                "get_rotation_policy",
            ],
        )
        self.assertTrue(azure_facts(normalized_vault).purge_protection_enabled)
        workload_facts = azure_facts(workload)
        self.assertEqual(
            workload_facts.app_service_key_vault_operation_paths,
            [],
        )
        self.assertEqual(
            [path["operation"] for path in workload_facts.app_service_key_vault_management_paths],
            ["delete", "update"],
        )
        self.assertTrue(
            all(
                path["authorization_model"] == "access_policy"
                for path in workload_facts.app_service_key_vault_management_paths
            )
        )
        self.assertTrue(
            all(
                path["purge_protection_enabled"] is True
                for path in workload_facts.app_service_key_vault_management_paths
            )
        )

    def test_incomplete_admin_authorization_remains_non_authoritative(
        self,
    ) -> None:
        aws_role = _aws_admin_role()
        aws_inventory = AwsNormalizer().normalize(
            [
                aws_role,
                _aws_admin_key(
                    "data",
                    key_id=_AWS_KEY_IDS["data"],
                    key_arn=_AWS_KEY_ARNS["data"],
                    origin="AWS_KMS",
                    policy_actions=[
                        *_AWS_DISRUPTIVE_ACTIONS,
                        *_AWS_DELEGATION_ACTIONS,
                        *_AWS_QUIET_ADMIN_ACTIONS,
                    ],
                ),
                _resource(
                    "aws",
                    "aws_iam_role_policy_attachment",
                    "external_admin",
                    {
                        "role": _AWS_TASK_ROLE_ARN,
                        "policy_arn": _AWS_EXTERNAL_POLICY_ARN,
                    },
                ),
            ]
        )
        normalized_aws_role = aws_inventory.get_by_address("aws_iam_role.orders_task")
        incomplete_aws_key = aws_inventory.get_by_address("aws_kms_key.data")
        assert normalized_aws_role is not None
        assert incomplete_aws_key is not None
        self.assertEqual(
            aws_facts(normalized_aws_role).iam_policy_completeness_state,
            "unknown",
        )
        self.assertEqual(
            aws_facts(normalized_aws_role).unresolved_attached_policy_arns,
            [_AWS_EXTERNAL_POLICY_ARN],
        )
        incomplete_authorizations = {
            authorization["operation"]: authorization
            for authorization in aws_facts(incomplete_aws_key).kms_operation_authorizations
        }
        self.assertEqual(
            incomplete_authorizations["kms:ScheduleKeyDeletion"]["authorization_state"],
            "denied",
        )
        self.assertTrue(
            all(
                authorization["authorization_state"] == "unknown"
                for operation, authorization in incomplete_authorizations.items()
                if operation != "kms:ScheduleKeyDeletion"
            )
        )

        gcp_inventory = GcpNormalizer().normalize(
            [
                _gcp_cloud_run(),
                _gcp_public_invoker(),
                _gcp_key("data", "ENCRYPT_DECRYPT"),
                _resource(
                    "google",
                    GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
                    "runtime_admin",
                    {
                        "project": _GCP_PROJECT,
                        "role_id": "runtimeAdmin",
                        "name": (f"projects/{_GCP_PROJECT}/roles/runtimeAdmin"),
                        "permissions": [
                            "cloudkms.cryptoKeyVersions.destroy",
                            "cloudkms.cryptoKeys.setIamPolicy",
                        ],
                    },
                    unknown_values={"permissions": True},
                ),
                _gcp_key_member(
                    "runtime_custom_admin",
                    "data",
                    "google_project_iam_custom_role.runtime_admin.id",
                ),
            ]
        )
        gcp_key = gcp_inventory.get_by_address("google_kms_crypto_key.data")
        gcp_workload = gcp_inventory.get_by_address("google_cloud_run_v2_service.orders")
        assert gcp_key is not None
        assert gcp_workload is not None
        gcp_grant = gcp_facts(gcp_key).kms_iam_grants[0]
        self.assertEqual(gcp_grant["role_kind"], "custom")
        self.assertEqual(gcp_grant["role_resolution_state"], "unknown")
        self.assertEqual(gcp_grant["scope_effective_permissions"], [])
        self.assertEqual(gcp_grant["authorization_state"], "unknown")
        self.assertEqual(gcp_facts(gcp_workload).cloud_run_kms_operation_paths, [])
        self.assertTrue(gcp_facts(gcp_workload).cloud_run_kms_operation_path_uncertainties)
        self.assertEqual(
            gcp_facts(gcp_workload).cloud_run_kms_management_paths,
            [],
        )
        self.assertTrue(gcp_facts(gcp_workload).cloud_run_kms_management_path_uncertainties)

        azure_inventory = AzureNormalizer().normalize(
            [
                _azure_vault(),
                _azure_key(
                    "data",
                    key_type="RSA-HSM",
                    key_opts=["encrypt"],
                ),
                _azure_web_app(),
                _azure_custom_admin_role(unknown_permissions=True),
                _azure_role_assignment(
                    "unknown_key_admin",
                    role_id=_AZURE_CUSTOM_ADMIN_ROLE_ID,
                    role_name="Orders Key Administrator",
                    scope=("azurerm_key_vault_key.data.resource_versionless_id"),
                ),
            ]
        )
        azure_key = azure_inventory.get_by_address("azurerm_key_vault_key.data")
        azure_workload = azure_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert azure_key is not None
        assert azure_workload is not None
        azure_grant = azure_facts(azure_key).key_vault_key_authorization_grants[0]
        self.assertEqual(azure_grant.get("role_kind"), "custom")
        self.assertEqual(azure_grant.get("role_resolution_state"), "unknown")
        self.assertEqual(azure_grant["matched_operations"], [])
        self.assertEqual(azure_grant["authorization_state"], "unknown")
        azure_workload_facts = azure_facts(azure_workload)
        self.assertEqual(
            azure_workload_facts.app_service_key_vault_operation_paths,
            [],
        )
        self.assertEqual(
            azure_workload_facts.app_service_key_vault_management_paths,
            [],
        )
        self.assertTrue(
            azure_workload_facts.app_service_key_vault_management_path_uncertainties,
        )


if __name__ == "__main__":
    unittest.main()

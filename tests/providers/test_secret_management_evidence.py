from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.secret_management_evidence import (
    AwsEcsSecretsManagerManagementPath,
    AwsSecretsManagerOperationAuthorization,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.secret_management_evidence import (
    AzureAppServiceKeyVaultSecretManagementPath,
    AzureKeyVaultSecretAuthorizationGrant,
)
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.secret_management_evidence import (
    GcpCloudRunSecretManagementPath,
    GcpSecretManagerIamGrant,
    GcpSecretManagerVersionEvidence,
)


def _resource(provider: str, resource_type: str, name: str) -> NormalizedResource:
    return NormalizedResource(
        address=f"{resource_type}.{name}",
        provider=provider,
        resource_type=resource_type,
        name=name,
        category=ResourceCategory.DATA,
    )


class SecretManagementEvidenceTests(unittest.TestCase):
    def test_aws_contract_preserves_two_sided_authorization_and_recovery_scope(
        self,
    ) -> None:
        secret = _resource("aws", "aws_secretsmanager_secret", "orders")
        workload = _resource("aws", "aws_ecs_service", "orders")
        authorization: AwsSecretsManagerOperationAuthorization = {
            "secret_address": secret.address,
            "secret_resource_type": secret.resource_type,
            "secret_arn": ("arn:aws:secretsmanager:us-east-1:111122223333:secret:orders"),
            "secret_name": "orders",
            "principal_address": "aws_iam_role.task",
            "principal_arn": "arn:aws:iam::111122223333:role/task",
            "principal_kind": "iam_role",
            "operation": "secretsmanager:PutSecretValue",
            "operation_class": "value_mutation",
            "management_effect": "tampering",
            "supported_authorization_bases": [
                "identity_policy",
                "resource_policy_direct",
                "cross_account_identity_and_resource_policy",
            ],
            "authorization_state": "allowed",
            "authorization_bases": ["identity_policy"],
            "candidate_authorization_bases": ["identity_policy"],
            "same_account": True,
            "identity_policy_required": True,
            "resource_policy_required": False,
            "identity_policy_complete": True,
            "resource_policy_complete": True,
            "identity_policy_source_addresses": ["aws_iam_role_policy.task"],
            "resource_policy_source_addresses": [],
            "unresolved_attached_policy_arns": [],
            "identity_policy_uncertainties": [],
            "resource_policy_uncertainties": [],
            "explicit_deny": False,
            "conditional_policy_evidence_present": False,
            "authorization_requires_condition_evaluation": False,
            "identity_policy_statements": [],
            "resource_policy_statements": [],
            "evaluation_scope": ("modeled_identity_and_secrets_manager_resource_policies"),
        }
        path: AwsEcsSecretsManagerManagementPath = {
            "workload_address": workload.address,
            "workload_type": workload.resource_type,
            "task_definition_address": "aws_ecs_task_definition.orders",
            "task_definition_arn": ("arn:aws:ecs:us-east-1:111122223333:task-definition/orders:1"),
            "secret_address": secret.address,
            "secret_resource_type": secret.resource_type,
            "secret_arn": authorization["secret_arn"],
            "secret_name": "orders",
            "operation": "secretsmanager:PutSecretValue",
            "operation_class": "value_mutation",
            "management_effect": "tampering",
            "role_kind": "ecs_task_role",
            "credential_context": "workload_runtime",
            "role_address": authorization["principal_address"],
            "role_arn": authorization["principal_arn"],
            "role_policy_complete": True,
            "authorization_state": "allowed",
            "authorization_bases": ["identity_policy"],
            "candidate_authorization_bases": ["identity_policy"],
            "evaluation_basis": "modeled_secrets_manager_authorization",
            "same_account": True,
            "explicit_deny": False,
            "conditional_policy_evidence_present": False,
            "authorization_requires_condition_evaluation": False,
            "identity_policy_source_addresses": ["aws_iam_role_policy.task"],
            "resource_policy_source_addresses": [],
            "identity_policy_statements": [],
            "resource_policy_statements": [],
            "terraform_recovery_window_in_days": 30,
            "recovery_window_evidence_scope": "terraform_resource_deletion_only",
            "authorization_record": authorization,
        }

        secret_facts = aws_facts(secret)
        secret_facts.set_secrets_manager_operation_authorization_posture(
            authorizations=[authorization],
            uncertainties=[],
        )
        workload_facts = aws_facts(workload)
        workload_facts.set_ecs_secret_management_paths([path])

        self.assertEqual(
            secret_facts.secrets_manager_operation_authorizations,
            [authorization],
        )
        self.assertEqual(workload_facts.ecs_secret_management_paths, [path])
        self.assertEqual(path["role_kind"], "ecs_task_role")
        self.assertEqual(
            path["recovery_window_evidence_scope"],
            "terraform_resource_deletion_only",
        )

    def test_gcp_contract_preserves_native_iam_scope_and_version_lifecycle(
        self,
    ) -> None:
        secret = _resource("gcp", "google_secret_manager_secret", "orders")
        workload = _resource("gcp", "google_cloud_run_v2_service", "orders")
        grant: GcpSecretManagerIamGrant = {
            "role": "roles/secretmanager.admin",
            "role_kind": "predefined",
            "role_resolution_state": "resolved",
            "modeled_secret_permissions": [
                "secretmanager.versions.add",
                "secretmanager.versions.destroy",
            ],
            "scope_effective_permissions": [
                "secretmanager.versions.add",
                "secretmanager.versions.destroy",
            ],
            "members": ["serviceAccount:runtime@example.iam.gserviceaccount.com"],
            "source": "google_project_iam_member.runtime",
            "source_type": "google_project_iam_member",
            "scope_type": "project",
            "scope": "example",
            "source_scope_reference": "example",
            "project": "example",
            "secret_address": secret.address,
            "secret_resource_name": "projects/example/secrets/orders",
            "condition_state": "not_configured",
            "authorization_state": "granted",
            "management_mode": "additive",
            "management_state": "unambiguous",
            "grant_basis": "project_iam",
        }
        version: GcpSecretManagerVersionEvidence = {
            "version_address": "google_secret_manager_secret_version.orders",
            "version_resource_type": "google_secret_manager_secret_version",
            "version_resource_name": "projects/example/secrets/orders/versions/1",
            "version_number": "1",
            "version_state": "ENABLED",
            "secret_address": secret.address,
            "secret_resource_name": "projects/example/secrets/orders",
            "resolved_secret_address": secret.address,
            "lifecycle_state": "enabled",
            "deletion_policy": "DELETE",
            "posture_uncertainties": [],
        }
        path: GcpCloudRunSecretManagementPath = {
            "workload_address": workload.address,
            "workload_type": workload.resource_type,
            "service_account_email": "runtime@example.iam.gserviceaccount.com",
            "service_account_member": ("serviceAccount:runtime@example.iam.gserviceaccount.com"),
            "identity_kind": "cloud_run_service_account",
            "credential_context": "workload_runtime",
            "operation": "secretmanager.versions.destroy",
            "operation_class": "version_disruption",
            "management_effect": "disruption",
            "matched_permissions": ["secretmanager.versions.destroy"],
            "target_type": "secret_version",
            "target_address": version["version_address"],
            "target_resource_type": version["version_resource_type"],
            "target_resource_name": version["version_resource_name"],
            "target_model_evidence_addresses": [version["version_address"]],
            "secret_address": secret.address,
            "secret_resource_name": "projects/example/secrets/orders",
            "secret_project": "example",
            "secret_version": version,
            "version_destroy_ttl": "86400s",
            "recovery_evidence_scope": "secret_version_destruction_delay",
            "lifecycle_compatibility_state": "compatible",
            "iam_resource_address": grant["source"],
            "iam_resource_type": grant["source_type"],
            "role": grant["role"],
            "role_kind": grant["role_kind"],
            "role_resolution_state": grant["role_resolution_state"],
            "modeled_secret_permissions": grant["modeled_secret_permissions"],
            "custom_role_permissions": [],
            "role_definition_address": None,
            "scope_effective_permissions": grant["scope_effective_permissions"],
            "grant_members": grant["members"],
            "grant_basis": "project_iam",
            "scope_type": "project",
            "scope": "example",
            "source_scope_reference": "example",
            "management_mode": "additive",
            "management_state": "unambiguous",
            "condition": None,
            "condition_state": "not_configured",
            "authorization_state": "granted",
            "authorization_model": "secret_manager_iam",
            "iam_scope_is_secret_version": False,
            "iam_grant_record": grant,
        }

        secret_facts = gcp_facts(secret)
        secret_facts.set_secret_manager_iam_posture(grants=[grant], uncertainties=[])
        workload_facts = gcp_facts(workload)
        workload_facts.set_cloud_run_secret_management_paths([path])

        self.assertEqual(secret_facts.secret_manager_iam_grants, [grant])
        self.assertEqual(workload_facts.cloud_run_secret_management_paths, [path])
        self.assertEqual(path["scope_type"], "project")
        self.assertFalse(path["iam_scope_is_secret_version"])
        self.assertEqual(path["secret_version"], version)
        self.assertEqual(path["version_destroy_ttl"], "86400s")
        self.assertEqual(
            path["recovery_evidence_scope"],
            "secret_version_destruction_delay",
        )

    def test_azure_contract_preserves_runtime_identity_and_purge_sequence(
        self,
    ) -> None:
        secret = _resource("azure", "azurerm_key_vault_secret", "orders")
        workload = _resource("azure", "azurerm_linux_web_app", "orders")
        vault_id = (
            "/subscriptions/00000000-0000-0000-0000-000000000001/"
            "resourceGroups/app/providers/Microsoft.KeyVault/vaults/orders"
        )
        secret_uri = "https://orders.vault.azure.net/secrets/orders/version-1"
        versionless_uri = "https://orders.vault.azure.net/secrets/orders"
        grant: AzureKeyVaultSecretAuthorizationGrant = {
            "grant_kind": "rbac",
            "grant_source_address": "azurerm_role_assignment.runtime",
            "grant_basis": "azure_rbac_assignment",
            "authorization_model": "azure_rbac",
            "authorization_model_state": "active",
            "authorization_state": "granted",
            "grant_scope_type": "vault",
            "grant_scope": vault_id,
            "key_vault_address": "azurerm_key_vault.orders",
            "key_vault_id": vault_id,
            "secret_address": secret.address,
            "secret_uri": secret_uri,
            "secret_versionless_uri": versionless_uri,
            "secret_resource_id": f"{vault_id}/secrets/orders",
            "secret_version": "version-1",
            "principal_id": "11111111-1111-1111-1111-111111111111",
            "principal_type": "ServicePrincipal",
            "principal_state": "resolved",
            "matched_operations": ["delete", "purge"],
            "condition": None,
            "condition_state": "not_configured",
            "condition_applicability_state": "not_applicable",
            "role_definition_name": "Key Vault Administrator",
            "role_definition_id": (
                "/providers/Microsoft.Authorization/roleDefinitions/00482a5a-887f-4fb3-b363-3b7fe8e74483"
            ),
            "role_kind": "built_in",
            "role_resolution_state": "resolved",
            "matched_data_actions": [
                "Microsoft.KeyVault/vaults/secrets/delete",
                "Microsoft.KeyVault/vaults/secrets/purge/action",
            ],
        }
        path: AzureAppServiceKeyVaultSecretManagementPath = {
            "workload_address": workload.address,
            "workload_type": workload.resource_type,
            "identity_address": "azurerm_user_assigned_identity.runtime",
            "identity_kind": "user_assigned",
            "principal_id": "11111111-1111-1111-1111-111111111111",
            "credential_context": "workload_runtime",
            "key_vault_address": "azurerm_key_vault.orders",
            "key_vault_id": vault_id,
            "secret_address": secret.address,
            "secret_resource_type": secret.resource_type,
            "secret_name": "orders",
            "secret_uri": secret_uri,
            "secret_versionless_uri": versionless_uri,
            "secret_resource_id": f"{vault_id}/secrets/orders",
            "secret_version": "version-1",
            "operation": "delete_plus_purge",
            "step_operations": ["delete", "purge"],
            "operation_class": "destructive_administration",
            "management_effect": "disruption",
            "target_type": "secret",
            "target_address": secret.address,
            "target_resource_id": f"{vault_id}/secrets/orders",
            "authorization_model": "azure_rbac",
            "authorization_model_state": "active",
            "authorization_state": "granted",
            "grant_source_addresses": ["azurerm_role_assignment.runtime"],
            "scope_types": ["vault"],
            "scopes": [vault_id],
            "scope_arm_ids": [vault_id],
            "data_plane_grants": [grant],
            "purge_protection_enabled": False,
            "recovery_uncertainties": [],
            "lifecycle_compatibility_state": "compatible",
            "condition": None,
            "condition_state": "not_configured",
            "evaluation_basis": "modeled_key_vault_secret_authorization",
        }

        secret_facts = azure_facts(secret)
        secret_facts.set_key_vault_secret_authorization_posture(
            grants=[grant],
            uncertainties=[],
        )
        workload_facts = azure_facts(workload)
        workload_facts.set_app_service_key_vault_secret_management_paths([path])

        self.assertEqual(secret_facts.key_vault_secret_authorization_grants, [grant])
        self.assertEqual(
            workload_facts.app_service_key_vault_secret_management_paths,
            [path],
        )
        self.assertEqual(path["identity_kind"], "user_assigned")
        self.assertEqual(path["step_operations"], ["delete", "purge"])
        self.assertFalse(path["purge_protection_enabled"])


if __name__ == "__main__":
    unittest.main()

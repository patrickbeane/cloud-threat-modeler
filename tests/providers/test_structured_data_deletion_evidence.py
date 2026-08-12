from __future__ import annotations

import unittest

from tfstride.providers.aws.structured_data_deletion_evidence import (
    AwsDynamoDbBatchWriteDeletePolicyStatementEvidence,
    AwsDynamoDbPitrProviderDefaultRecoveryEvidence,
    AwsEcsDynamoDbBatchWriteDeletePath,
)
from tfstride.providers.azure.structured_data_deletion_evidence import (
    AzureAppServiceCosmosDbContainerItemDeletionPath,
    AzureCosmosDbProviderDefaultBackupRecoveryEvidence,
)
from tfstride.providers.gcp.structured_data_deletion_evidence import (
    GcpCloudRunFirestoreDatabaseEntityDeletionPath,
    GcpFirestorePitrProviderDefaultRecoveryEvidence,
)


class StructuredDataDeletionEvidenceTests(unittest.TestCase):
    def test_aws_contract_preserves_batch_delete_and_default_pitr(self) -> None:
        statement: AwsDynamoDbBatchWriteDeletePolicyStatementEvidence = {
            "effect": "allow",
            "actions": ["dynamodb:BatchWriteItem"],
            "matched_actions": ["dynamodb:BatchWriteItem"],
            "matching_action_patterns": [
                "dynamodb:BatchWriteItem",
            ],
            "resources": ["arn:aws:dynamodb:us-east-1:111122223333:table/orders"],
            "matching_resources": ["arn:aws:dynamodb:us-east-1:111122223333:table/orders"],
            "resource_scopes": ["exact_table"],
            "conditions": [],
            "conditional": False,
        }
        recovery: AwsDynamoDbPitrProviderDefaultRecoveryEvidence = {
            "recovery_evidence_scope": ("dynamodb_point_in_time_recovery"),
            "pitr_state": "not_configured",
            "pitr_enabled": False,
            "pitr_recovery_period_days": None,
            "uncertainties": [],
        }
        path: AwsEcsDynamoDbBatchWriteDeletePath = {
            "workload_address": "aws_ecs_service.orders",
            "workload_type": "aws_ecs_service",
            "task_definition_address": ("aws_ecs_task_definition.orders"),
            "task_definition_arn": ("arn:aws:ecs:us-east-1:111122223333:task-definition/orders:1"),
            "internet_facing_load_balancers": ["aws_lb.public"],
            "role_kind": "ecs_task_role",
            "credential_context": "workload_runtime",
            "role_address": "aws_iam_role.orders_task",
            "role_reference": ("arn:aws:iam::111122223333:role/orders-task"),
            "role_arn": ("arn:aws:iam::111122223333:role/orders-task"),
            "dynamodb_table_address": "aws_dynamodb_table.orders",
            "dynamodb_table_resource_type": "aws_dynamodb_table",
            "dynamodb_table_name": "orders",
            "dynamodb_table_reference": ("arn:aws:dynamodb:us-east-1:111122223333:table/orders"),
            "dynamodb_table_arn": ("arn:aws:dynamodb:us-east-1:111122223333:table/orders"),
            "target_granularity": "table_item_namespace",
            "target_scope": "exact_table_item_namespace",
            "target_model_evidence_addresses": ["aws_dynamodb_table.orders"],
            "operation": "dynamodb:BatchWriteItem",
            "operation_class": "batch_item_deletion",
            "internal_operation": "batch_write_delete",
            "management_effect": "disruption",
            "batch_write_includes_put_capability": True,
            "authorization_source_addresses": ["aws_iam_role.orders_task"],
            "evaluation_basis": "modeled_identity_policy",
            "authorization_state": "allowed",
            "role_policy_complete": True,
            "matched_actions": ["dynamodb:BatchWriteItem"],
            "policy_action_patterns": ["dynamodb:BatchWriteItem"],
            "policy_resources": ["arn:aws:dynamodb:us-east-1:111122223333:table/orders"],
            "resource_scopes": ["exact_table"],
            "policy_statements": [statement],
            "explicit_deny": False,
            "conditional_evaluation_required": False,
            "lifecycle_compatibility_state": "not_applicable",
            "recovery_evidence": recovery,
            "posture_uncertainties": [],
        }

        self.assertEqual(
            path["target_granularity"],
            "table_item_namespace",
        )
        self.assertTrue(path["batch_write_includes_put_capability"])
        self.assertEqual(
            path["recovery_evidence"]["pitr_state"],
            "not_configured",
        )
        self.assertNotIn("item_key", path)

    def test_gcp_contract_preserves_static_database_scope_and_default_pitr(
        self,
    ) -> None:
        recovery: GcpFirestorePitrProviderDefaultRecoveryEvidence = {
            "recovery_evidence_scope": ("firestore_point_in_time_recovery"),
            "pitr_state": "not_configured",
            "pitr_enabled": False,
            "historical_version_retention_state": ("native_approximately_one_hour"),
            "uncertainties": [],
        }
        path: GcpCloudRunFirestoreDatabaseEntityDeletionPath = {
            "workload_address": ("google_cloud_run_v2_service.orders"),
            "workload_type": "google_cloud_run_v2_service",
            "service_account_email": ("runtime@example.iam.gserviceaccount.com"),
            "service_account_member": ("serviceAccount:runtime@example.iam.gserviceaccount.com"),
            "identity_kind": "cloud_run_service_account",
            "credential_context": "workload_runtime",
            "firestore_database_address": ("google_firestore_database.orders"),
            "firestore_database_resource_type": ("google_firestore_database"),
            "firestore_database_resource_name": ("projects/example/databases/orders"),
            "firestore_database_name": "orders",
            "firestore_database_project": "example",
            "firestore_database_type": "FIRESTORE_NATIVE",
            "target_model_evidence_addresses": ["google_firestore_database.orders"],
            "operation": "datastore.entities.delete",
            "operation_class": "entity_deletion",
            "management_effect": "disruption",
            "target_granularity": "database_entity_namespace",
            "iam_resource_address": ("google_project_iam_member.runtime"),
            "iam_resource_type": "google_project_iam_member",
            "iam_source_addresses": [
                "google_project_iam_member.runtime",
                "google_project_iam_custom_role.entity_delete",
            ],
            "role": ("projects/example/roles/entityDelete"),
            "role_kind": "custom",
            "role_definition_address": ("google_project_iam_custom_role.entity_delete"),
            "custom_role_permissions": ["datastore.entities.delete"],
            "custom_role_stage": "GA",
            "custom_role_deleted": False,
            "grant_basis": "project_iam_condition",
            "matched_permissions": ["datastore.entities.delete"],
            "scope_type": "database",
            "scope": "projects/example/databases/orders",
            "resource_scope": "exact_firestore_database",
            "condition": {
                "title": "orders-only",
                "expression": ('resource.name == "projects/example/databases/orders"'),
            },
            "condition_state": "configured",
            "condition_evaluation": ("exact_database_scope_match"),
            "authorization_state": "granted",
            "policy_complete": True,
            "authorization_model": "iam_authorized_server_api",
            "firestore_security_rules_evaluated": False,
            "firestore_security_rules_applicability": ("not_in_server_api_authorization_path"),
            "lifecycle_compatibility_state": "not_applicable",
            "recovery_evidence": recovery,
            "posture_uncertainties": [],
        }

        self.assertEqual(path["scope_type"], "database")
        self.assertEqual(
            path["condition_evaluation"],
            "exact_database_scope_match",
        )
        self.assertEqual(
            path["recovery_evidence"]["historical_version_retention_state"],
            "native_approximately_one_hour",
        )
        self.assertNotIn("document_name", path)

    def test_azure_contract_preserves_container_scope_and_default_backup(
        self,
    ) -> None:
        account_id = (
            "/subscriptions/00000000-0000-0000-0000-000000000001/"
            "resourceGroups/data/providers/Microsoft.DocumentDB/"
            "databaseAccounts/orders"
        )
        database_id = f"{account_id}/dbs/app"
        container_id = f"{database_id}/colls/events"
        recovery: AzureCosmosDbProviderDefaultBackupRecoveryEvidence = {
            "recovery_evidence_scope": "cosmosdb_backup_policy",
            "backup_posture_state": "provider_default_periodic",
            "backup_configuration_state": "not_configured",
            "backup_type": "Periodic",
            "backup_tier": None,
            "backup_interval_minutes": 240,
            "backup_retention_hours": 8,
            "backup_storage_redundancy": "Geo",
            "uncertainties": [],
        }
        path: AzureAppServiceCosmosDbContainerItemDeletionPath = {
            "workload_address": "azurerm_linux_web_app.orders",
            "workload_type": "azurerm_linux_web_app",
            "identity_address": "azurerm_linux_web_app.orders",
            "identity_kind": "system_assigned",
            "principal_id": ("11111111-1111-1111-1111-111111111111"),
            "credential_context": "workload_runtime",
            "cosmosdb_account_address": ("azurerm_cosmosdb_account.orders"),
            "cosmosdb_account_id": account_id,
            "cosmosdb_resource_address": ("azurerm_cosmosdb_sql_container.events"),
            "cosmosdb_resource_type": ("azurerm_cosmosdb_sql_container"),
            "cosmosdb_resource_id": container_id,
            "cosmosdb_database_address": ("azurerm_cosmosdb_sql_database.app"),
            "cosmosdb_database_id": database_id,
            "cosmosdb_database_name": "app",
            "cosmosdb_container_address": ("azurerm_cosmosdb_sql_container.events"),
            "cosmosdb_container_id": container_id,
            "cosmosdb_container_name": "events",
            "operation": ("Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/delete"),
            "operation_class": "item_deletion",
            "management_effect": "disruption",
            "scope_type": "container",
            "target_granularity": "container_item_namespace",
            "target_scope": ("exact_cosmosdb_for_nosql_container"),
            "target_model_evidence_addresses": [
                "azurerm_cosmosdb_account.orders",
                "azurerm_cosmosdb_sql_database.app",
                "azurerm_cosmosdb_sql_container.events",
            ],
            "role_assignment_address": ("azurerm_cosmosdb_sql_role_assignment.runtime"),
            "role_assignment_id": "assignment-1",
            "role_definition_reference": ("azurerm_cosmosdb_sql_role_definition.runtime.id"),
            "role_definition_address": ("azurerm_cosmosdb_sql_role_definition.runtime"),
            "role_definition_name": "Item delete",
            "role_kind": "custom",
            "role_data_actions": ["Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/delete"],
            "matched_data_actions": ["Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/delete"],
            "grant_basis": ("cosmosdb_for_nosql_native_role_assignment"),
            "evaluation_basis": "modeled_native_rbac_assignment",
            "authorization_source_addresses": [
                "azurerm_cosmosdb_sql_role_assignment.runtime",
                "azurerm_cosmosdb_sql_role_definition.runtime",
            ],
            "assignment_scope": "/dbs/app/colls/events",
            "assignment_scope_state": "resolved",
            "assignable_scope_compatibility_state": "resolved",
            "authorization_state": "granted",
            "policy_complete": True,
            "authorization_model": ("cosmosdb_for_nosql_native_rbac"),
            "lifecycle_compatibility_state": "not_applicable",
            "recovery_evidence": recovery,
            "posture_uncertainties": [],
        }

        self.assertEqual(
            path["target_granularity"],
            "container_item_namespace",
        )
        self.assertEqual(
            path["recovery_evidence"]["backup_configuration_state"],
            "not_configured",
        )
        self.assertEqual(
            path["recovery_evidence"]["backup_retention_hours"],
            8,
        )
        self.assertNotIn("item_id", path)


if __name__ == "__main__":
    unittest.main()

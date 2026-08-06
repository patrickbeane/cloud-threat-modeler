from __future__ import annotations

import unittest

from tests.providers.test_protected_data_key_authority_convergence import (
    _aws_resources,
    _azure_resources,
    _gcp_resources,
)
from tfstride.models import NormalizedResource, ResourceInventory
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.protected_data_evidence import (
    AwsEcsS3ProtectedDataConvergence,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.protected_data_evidence import (
    AzureAppServiceStorageProtectedDataConvergence,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.protected_data_evidence import (
    GcpCloudRunGcsProtectedDataConvergence,
)
from tfstride.providers.gcp.resource_facts import gcp_facts


def _resource(inventory: ResourceInventory, address: str) -> NormalizedResource:
    resource = inventory.get_by_address(address)
    assert resource is not None
    return resource


class ProtectedDataConvergenceEvidenceTests(unittest.TestCase):
    def test_aws_contract_composes_exact_s3_and_kms_evidence(self) -> None:
        inventory = AwsNormalizer().normalize(_aws_resources())
        workload = _resource(inventory, "aws_ecs_service.orders")
        bucket = _resource(inventory, "aws_s3_bucket.orders")
        access_path = aws_facts(workload).ecs_s3_access_paths[0]
        operation_path = aws_facts(workload).ecs_kms_operation_paths[0]
        dependency = aws_facts(bucket).kms_encryption_dependencies[0]
        task_definition_address = access_path.get("task_definition_address")
        role_arn = access_path["role_arn"]
        key_arn = dependency["key_arn"]
        assert task_definition_address is not None
        assert role_arn is not None
        assert key_arn is not None

        convergence: AwsEcsS3ProtectedDataConvergence = {
            "workload_address": workload.address,
            "workload_type": workload.resource_type,
            "task_definition_address": task_definition_address,
            "role_address": access_path["role_address"],
            "role_arn": role_arn,
            "bucket_address": access_path["bucket_address"],
            "bucket_arn": access_path["bucket_arn"],
            "key_address": operation_path["key_address"],
            "key_arn": key_arn,
            "operation": "kms:Decrypt",
            "access_class": "read",
            "runtime_identity_match": True,
            "protected_resource_match": True,
            "key_identity_match": True,
            "convergence_state": "resolved",
            "evaluation_basis": "exact_s3_access_kms_dependency_and_decrypt_authority",
            "access_path": access_path,
            "key_operation_path": operation_path,
            "encryption_dependency": dependency,
            "posture_uncertainties": [],
        }

        self.assertEqual(
            convergence["access_path"]["bucket_address"],
            convergence["encryption_dependency"]["dependent_address"],
        )
        self.assertEqual(
            convergence["access_path"]["role_arn"],
            convergence["key_operation_path"]["role_arn"],
        )
        self.assertEqual(
            convergence["key_operation_path"]["key_address"],
            convergence["encryption_dependency"]["key_address"],
        )

    def test_gcp_contract_composes_exact_gcs_and_cmek_evidence(self) -> None:
        inventory = GcpNormalizer().normalize(_gcp_resources())
        workload = _resource(inventory, "google_cloud_run_v2_service.orders")
        bucket = _resource(inventory, "google_storage_bucket.orders")
        access_path = gcp_facts(workload).cloud_run_gcs_access_paths[0]
        operation_path = gcp_facts(workload).cloud_run_kms_operation_paths[0]
        dependency = gcp_facts(bucket).kms_encryption_dependencies[0]
        service_account_email = access_path["service_account_email"]
        key_resource_name = dependency["key_resource_name"]
        assert service_account_email is not None
        assert key_resource_name is not None

        convergence: GcpCloudRunGcsProtectedDataConvergence = {
            "workload_address": workload.address,
            "workload_type": workload.resource_type,
            "service_account_email": service_account_email,
            "service_account_member": access_path["service_account_member"],
            "bucket_address": access_path["bucket_address"],
            "bucket_name": access_path["bucket_name"],
            "key_address": operation_path["key_address"],
            "key_resource_name": key_resource_name,
            "operation": "cloudkms.cryptoKeyVersions.useToDecrypt",
            "access_class": "read",
            "runtime_identity_match": True,
            "protected_resource_match": True,
            "key_identity_match": True,
            "convergence_state": "resolved",
            "evaluation_basis": "exact_gcs_access_cmek_dependency_and_decrypt_authority",
            "access_path": access_path,
            "key_operation_path": operation_path,
            "encryption_dependency": dependency,
            "posture_uncertainties": [],
        }

        self.assertEqual(
            convergence["access_path"]["service_account_member"],
            convergence["key_operation_path"]["service_account_member"],
        )
        self.assertEqual(
            convergence["access_path"]["bucket_address"],
            convergence["encryption_dependency"]["dependent_address"],
        )
        self.assertEqual(
            convergence["key_operation_path"]["key_address"],
            convergence["encryption_dependency"]["key_address"],
        )

    def test_azure_contract_composes_exact_storage_and_key_vault_evidence(
        self,
    ) -> None:
        inventory = AzureNormalizer().normalize(_azure_resources())
        workload = _resource(inventory, "azurerm_linux_web_app.orders")
        storage_account = _resource(inventory, "azurerm_storage_account.orders")
        access_path = azure_facts(workload).app_service_storage_access_paths[0]
        operation_path = next(
            path
            for path in azure_facts(workload).app_service_key_vault_operation_paths
            if path["operation"] == "decrypt"
        )
        dependency = azure_facts(storage_account).key_vault_encryption_dependencies[0]
        principal_id = access_path["principal_id"]
        storage_account_address = access_path["storage_account_address"]
        storage_account_id = access_path["storage_account_id"]
        key_versionless_uri = dependency["key_versionless_uri"]
        assert principal_id is not None
        assert storage_account_address is not None
        assert storage_account_id is not None
        assert key_versionless_uri is not None

        convergence: AzureAppServiceStorageProtectedDataConvergence = {
            "workload_address": workload.address,
            "workload_type": workload.resource_type,
            "identity_address": access_path["identity_address"],
            "identity_kind": access_path["identity_kind"],
            "principal_id": principal_id,
            "storage_resource_address": access_path["storage_resource_address"],
            "storage_account_address": storage_account_address,
            "storage_account_id": storage_account_id,
            "key_address": operation_path["key_address"],
            "key_uri": dependency["key_uri"],
            "key_versionless_uri": key_versionless_uri,
            "operation": "decrypt",
            "access_class": "read",
            "runtime_identity_match": True,
            "protected_resource_match": True,
            "key_identity_match": True,
            "convergence_state": "resolved",
            "evaluation_basis": ("exact_storage_access_key_vault_dependency_and_plaintext_recovery_authority"),
            "access_path": access_path,
            "key_operation_path": operation_path,
            "encryption_dependency": dependency,
            "posture_uncertainties": [],
        }

        self.assertEqual(
            convergence["access_path"]["principal_id"],
            convergence["key_operation_path"]["principal_id"],
        )
        self.assertEqual(
            convergence["access_path"]["storage_account_address"],
            convergence["encryption_dependency"]["dependent_address"],
        )
        self.assertEqual(
            convergence["key_operation_path"]["key_address"],
            convergence["encryption_dependency"]["key_address"],
        )


if __name__ == "__main__":
    unittest.main()

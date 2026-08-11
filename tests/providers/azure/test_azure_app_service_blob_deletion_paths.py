from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _STORAGE_ACCOUNT_ID,
    _SYSTEM_PRINCIPAL_ID,
    _USER_PRINCIPAL_ID,
    _custom_role,
    _custom_role_assignment,
    _resource,
    _role_assignment,
    _user_assigned_identity,
    _web_app,
)
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_decoration_stages import (
    default_azure_decoration_stages,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_DELETE = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
_DELETE_VERSION = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action"
_PERMANENT_DELETE = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/permanentDelete/action"
_USER_IDENTITY_REFERENCE = "azurerm_user_assigned_identity.orders_runtime.id"


def _storage_account(
    *,
    versioning_enabled: bool | None = True,
    blob_delete_days: int | None = 30,
    container_delete_days: int | None = 14,
    permanent_delete_enabled: bool | None = False,
    hns_enabled: bool | None = False,
    unknown_recovery: bool = False,
) -> TerraformResource:
    unknown_values: dict[str, object] = {}
    if unknown_recovery:
        unknown_values = {
            "is_hns_enabled": True,
            "blob_properties": [
                {
                    "versioning_enabled": True,
                    "delete_retention_policy": [
                        {
                            "days": True,
                            "permanent_delete_enabled": True,
                        }
                    ],
                }
            ],
        }
    return _resource(
        AzureResourceType.STORAGE_ACCOUNT,
        {
            "id": _STORAGE_ACCOUNT_ID,
            "name": "ordersdata",
            "is_hns_enabled": hns_enabled,
            "public_network_access_enabled": False,
            "network_rules": [{"default_action": "Deny"}],
            "blob_properties": [
                {
                    "versioning_enabled": versioning_enabled,
                    "delete_retention_policy": [
                        {
                            "days": blob_delete_days,
                            "permanent_delete_enabled": permanent_delete_enabled,
                        }
                    ],
                    "container_delete_retention_policy": [{"days": container_delete_days}],
                }
            ],
        },
        name="orders",
        unknown_values=unknown_values,
    )


def _storage_container(
    *,
    name: str = "orders",
) -> TerraformResource:
    return _resource(
        AzureResourceType.STORAGE_CONTAINER,
        {
            "id": f"https://ordersdata.blob.core.windows.net/{name}",
            "resource_manager_id": (f"{_STORAGE_ACCOUNT_ID}/blobServices/default/containers/{name}"),
            "name": name,
            "storage_account_id": "azurerm_storage_account.orders.id",
            "container_access_type": "private",
        },
        name=name,
    )


def _facts(resources: list[TerraformResource]):
    inventory = AzureNormalizer().normalize(resources)
    workload = inventory.get_by_address("azurerm_linux_web_app.orders")
    assert workload is not None
    return inventory, azure_facts(workload)


class AzureAppServiceBlobDeletionPathTests(unittest.TestCase):
    def test_account_contributor_fans_current_delete_to_modeled_containers(self) -> None:
        inventory, facts = _facts(
            [
                _storage_account(),
                _storage_container(),
                _storage_container(name="archive"),
                _web_app(),
                _role_assignment(),
            ]
        )

        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None
        self.assertFalse(workload.public_access_configured)

        paths = facts.app_service_blob_deletion_paths
        self.assertEqual(len(paths), 2)
        self.assertEqual({path["operation"] for path in paths}, {_DELETE})
        self.assertEqual(
            {path["container_address"] for path in paths},
            {
                "azurerm_storage_container.orders",
                "azurerm_storage_container.archive",
            },
        )
        for path in paths:
            self.assertEqual(path["operation_class"], "logical_blob_deletion")
            self.assertEqual(
                path["target_granularity"],
                "container_blob_namespace",
            )
            self.assertEqual(path["matched_data_actions"], [_DELETE])
            self.assertEqual(path["authorization_state"], "granted")
            self.assertTrue(path["policy_complete"])
            self.assertEqual(path["identity_address"], path["workload_address"])
            self.assertEqual(path["principal_id"], _SYSTEM_PRINCIPAL_ID)
            self.assertEqual(
                path["target_model_evidence_addresses"],
                [path["storage_account_address"], path["container_address"]],
            )
            recovery = path["recovery_evidence"]
            self.assertTrue(recovery["versioning_enabled"])
            self.assertEqual(recovery["blob_delete_retention_days"], 30)
            self.assertFalse(recovery["permanent_delete_enabled"])
            self.assertFalse(recovery["hierarchical_namespace_enabled"])
            self.assertNotIn("container_delete_retention_days", recovery)

        account = inventory.get_by_address("azurerm_storage_account.orders")
        assert account is not None
        self.assertEqual(
            azure_facts(account).storage_container_delete_retention_days,
            14,
        )
        self.assertEqual(facts.app_service_blob_deletion_path_uncertainties, [])

    def test_owner_models_standard_namespaces_without_inventing_permanent_target(self) -> None:
        _, facts = _facts(
            [
                _storage_account(permanent_delete_enabled=True),
                _storage_container(),
                _web_app(),
                _role_assignment(
                    scope="azurerm_storage_container.orders.resource_manager_id",
                    role_name="Storage Blob Data Owner",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/"
                        "roleDefinitions/b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
                    ),
                ),
            ]
        )

        paths = facts.app_service_blob_deletion_paths
        self.assertEqual(
            {path["operation"] for path in paths},
            {_DELETE, _DELETE_VERSION},
        )
        version_path = next(path for path in paths if path["operation"] == _DELETE_VERSION)
        self.assertEqual(version_path["operation_class"], "blob_version_deletion")
        self.assertEqual(
            version_path["target_granularity"],
            "container_blob_version_namespace",
        )
        self.assertEqual(
            version_path["lifecycle_compatibility_state"],
            "compatible",
        )
        self.assertFalse(any(path["operation"] == _PERMANENT_DELETE for path in paths))
        self.assertTrue(
            any(
                "exact modeled soft-deleted blob version or snapshot" in value
                for value in facts.app_service_blob_deletion_path_uncertainties
            )
        )

    def test_permanent_delete_only_requires_feature_and_exact_soft_deleted_target(
        self,
    ) -> None:
        def authority_resources() -> list[TerraformResource]:
            return [
                _storage_container(),
                _web_app(),
                _custom_role(data_actions=[_PERMANENT_DELETE]),
                _custom_role_assignment(scope="azurerm_storage_container.orders.resource_manager_id"),
            ]

        omitted_account = _storage_account()
        blob_properties = omitted_account.values["blob_properties"]
        assert isinstance(blob_properties, list)
        blob_property = blob_properties[0]
        assert isinstance(blob_property, dict)
        delete_policies = blob_property["delete_retention_policy"]
        assert isinstance(delete_policies, list)
        delete_policy = delete_policies[0]
        assert isinstance(delete_policy, dict)
        del delete_policy["permanent_delete_enabled"]

        _, disabled = _facts(
            [
                _storage_account(permanent_delete_enabled=False),
                *authority_resources(),
            ]
        )
        _, omitted = _facts([omitted_account, *authority_resources()])
        _, enabled = _facts(
            [
                _storage_account(permanent_delete_enabled=True),
                *authority_resources(),
            ]
        )

        for facts in (disabled, omitted):
            self.assertEqual(facts.app_service_blob_deletion_paths, [])
            self.assertEqual(
                facts.app_service_blob_deletion_path_uncertainties,
                [],
            )
        self.assertEqual(enabled.app_service_blob_deletion_paths, [])
        self.assertTrue(
            any(
                "exact modeled soft-deleted blob version or snapshot" in value
                for value in enabled.app_service_blob_deletion_path_uncertainties
            )
        )

    def test_hns_blocks_version_namespace_but_not_current_blob_delete(self) -> None:
        _, facts = _facts(
            [
                _storage_account(
                    versioning_enabled=False,
                    hns_enabled=True,
                ),
                _storage_container(),
                _web_app(),
                _role_assignment(
                    scope="azurerm_storage_container.orders.resource_manager_id",
                    role_name="Storage Blob Data Owner",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/"
                        "roleDefinitions/b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
                    ),
                ),
            ]
        )

        self.assertEqual(
            [path["operation"] for path in facts.app_service_blob_deletion_paths],
            [_DELETE],
        )
        self.assertTrue(facts.app_service_blob_deletion_paths[0]["recovery_evidence"]["hierarchical_namespace_enabled"])

    def test_unknown_hns_keeps_version_authority_lifecycle_uncertain(self) -> None:
        _, facts = _facts(
            [
                _storage_account(
                    versioning_enabled=None,
                    blob_delete_days=None,
                    permanent_delete_enabled=None,
                    hns_enabled=None,
                    unknown_recovery=True,
                ),
                _storage_container(),
                _web_app(),
                _role_assignment(
                    scope="azurerm_storage_container.orders.resource_manager_id",
                    role_name="Storage Blob Data Owner",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/"
                        "roleDefinitions/b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
                    ),
                ),
            ]
        )

        version_path = next(
            path for path in facts.app_service_blob_deletion_paths if path["operation"] == _DELETE_VERSION
        )
        self.assertEqual(
            version_path["lifecycle_compatibility_state"],
            "unknown",
        )
        self.assertIsNone(version_path["recovery_evidence"]["hierarchical_namespace_enabled"])
        self.assertTrue(version_path["recovery_evidence"]["uncertainties"])
        self.assertTrue(
            any(
                "permanent-delete feature state is unknown" in value
                for value in facts.app_service_blob_deletion_path_uncertainties
            )
        )

    def test_custom_not_data_actions_preserve_operation_exact_authority(self) -> None:
        _, facts = _facts(
            [
                _storage_account(),
                _storage_container(),
                _web_app(),
                _custom_role(
                    data_actions=["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"],
                    not_data_actions=[_DELETE, _PERMANENT_DELETE],
                ),
                _custom_role_assignment(scope="azurerm_storage_container.orders.resource_manager_id"),
            ]
        )

        self.assertEqual(len(facts.app_service_blob_deletion_paths), 1)
        path = facts.app_service_blob_deletion_paths[0]
        self.assertEqual(path["operation"], _DELETE_VERSION)
        self.assertEqual(path["matched_data_actions"], [_DELETE_VERSION])
        self.assertEqual(
            path["authorization_source_addresses"],
            [
                "azurerm_role_assignment.orders_blob",
                "azurerm_role_definition.blob_writer",
            ],
        )
        self.assertEqual(
            path["role_definition_id"],
            "azurerm_role_definition.blob_writer.role_definition_resource_id",
        )

    def test_system_and_attached_user_assigned_identities_remain_distinct(self) -> None:
        _, facts = _facts(
            [
                _storage_account(),
                _storage_container(),
                _user_assigned_identity(),
                _web_app(
                    identity_type="SystemAssigned, UserAssigned",
                    identity_ids=[_USER_IDENTITY_REFERENCE],
                ),
                _role_assignment(
                    scope="azurerm_storage_container.orders.resource_manager_id",
                    name="system_delete",
                ),
                _role_assignment(
                    principal_id=_USER_PRINCIPAL_ID,
                    scope="azurerm_storage_container.orders.resource_manager_id",
                    role_name="Storage Blob Data Owner",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/"
                        "roleDefinitions/b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
                    ),
                    name="user_delete",
                ),
            ]
        )

        paths = facts.app_service_blob_deletion_paths
        self.assertEqual(len(paths), 3)
        self.assertEqual(
            {(path["identity_kind"], path["identity_address"], path["principal_id"]) for path in paths},
            {
                (
                    "system_assigned",
                    "azurerm_linux_web_app.orders",
                    _SYSTEM_PRINCIPAL_ID,
                ),
                (
                    "user_assigned",
                    "azurerm_user_assigned_identity.orders_runtime",
                    _USER_PRINCIPAL_ID,
                ),
            },
        )

    def test_conditional_and_incomplete_delete_authority_stays_uncertain(self) -> None:
        condition = "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'orders'"
        _, conditional = _facts(
            [
                _storage_account(),
                _storage_container(),
                _web_app(),
                _role_assignment(
                    scope="azurerm_storage_container.orders.resource_manager_id",
                    condition=condition,
                ),
            ]
        )
        _, incomplete = _facts(
            [
                _storage_account(),
                _storage_container(),
                _web_app(),
                _custom_role(
                    data_actions=[],
                    unknown_values={"permissions": [{"data_actions": True}]},
                ),
                _custom_role_assignment(scope="azurerm_storage_container.orders.resource_manager_id"),
            ]
        )

        for facts in (conditional, incomplete):
            self.assertEqual(facts.app_service_blob_deletion_paths, [])
            self.assertTrue(facts.app_service_blob_deletion_path_uncertainties)

    def test_reader_uncertainty_and_unmodeled_children_do_not_invent_delete_paths(self) -> None:
        unknown_condition = AzureNormalizer().normalize(
            [
                _storage_account(),
                _storage_container(),
                _web_app(),
                _role_assignment(
                    scope="azurerm_storage_container.orders.resource_manager_id",
                    role_name="Storage Blob Data Reader",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/"
                        "roleDefinitions/2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
                    ),
                    unknown_values={"condition": True},
                ),
            ]
        )
        no_children = AzureNormalizer().normalize(
            [
                _storage_account(),
                _web_app(),
                _role_assignment(),
            ]
        )
        for inventory in (unknown_condition, no_children):
            workload = inventory.get_by_address("azurerm_linux_web_app.orders")
            assert workload is not None
            facts = azure_facts(workload)
            self.assertEqual(facts.app_service_blob_deletion_paths, [])
            self.assertEqual(
                facts.app_service_blob_deletion_path_uncertainties,
                [],
            )

    def test_deletion_stage_follows_identity_storage_and_access_inputs(self) -> None:
        names = [stage.name for stage in default_azure_decoration_stages()]
        deletion = names.index("model_app_service_blob_deletion_paths")
        for stage_name in (
            "decorate_storage_relationships",
            "decorate_managed_identity_role_assignments",
            "model_app_service_storage_access_paths",
        ):
            with self.subTest(stage_name=stage_name):
                self.assertLess(names.index(stage_name), deletion)


if __name__ == "__main__":
    unittest.main()

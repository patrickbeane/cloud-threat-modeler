from __future__ import annotations

import json
import unittest

from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _STORAGE_ACCOUNT_ID,
    _SYSTEM_PRINCIPAL_ID,
    _USER_PRINCIPAL_ID,
    _resource,
    _role_assignment,
    _user_assigned_identity,
    _web_app,
)
from tfstride.models import TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_decoration.app_service_storage_container_topology_destruction_paths import (
    current_app_service_storage_container_topology_destruction_paths,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import (
    AzureDecorationContext,
    AzureResourceIndexBuilder,
)
from tfstride.providers.azure.resource_types import AzureResourceType

_DELETE_CONTAINER = "Microsoft.Storage/storageAccounts/blobServices/containers/delete"
_CONTROL_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/storage-container-topology-operator"
)
_WORKLOAD_ADDRESS = "azurerm_linux_web_app.orders"
_ACCOUNT_ADDRESS = "azurerm_storage_account.orders"
_CONTAINER_ADDRESS = "azurerm_storage_container.orders"
_CONTROL_ROLE_ADDRESS = "azurerm_role_definition.storage_topology"
_STORAGE_CONTAINER_DELETE_BUILT_IN_ROLES = (
    (
        "Storage Account Contributor",
        "17d1049b-9a84-46fb-8f53-869881c3d3ab",
    ),
    (
        "Storage Blob Data Contributor",
        "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
    ),
    (
        "Storage Blob Data Owner",
        "b7e6dc6d-f1e8-4753-8033-0f276bb0955b",
    ),
)


def _storage_account(
    *,
    name: str = "orders",
    account_id: str = _STORAGE_ACCOUNT_ID,
    container_delete_days: int | None = 14,
    unknown_recovery: bool = False,
) -> TerraformResource:
    blob_properties: dict[str, object] = {}
    if container_delete_days is not None:
        blob_properties["container_delete_retention_policy"] = [{"days": container_delete_days}]
    unknown_values: dict[str, object] = {}
    if unknown_recovery:
        unknown_values = {"blob_properties": [{"container_delete_retention_policy": [{"days": True}]}]}
    return _resource(
        AzureResourceType.STORAGE_ACCOUNT,
        {
            "id": account_id,
            "name": f"{name}data",
            "public_network_access_enabled": False,
            "network_rules": [{"default_action": "Deny"}],
            "blob_properties": [blob_properties],
        },
        name=name,
        unknown_values=unknown_values,
    )


def _storage_container(
    *,
    name: str = "orders",
    configured_name: str | None = None,
    account_name: str = "orders",
    account_id: str = _STORAGE_ACCOUNT_ID,
    has_immutability_policy: bool | None = False,
    has_legal_hold: bool | None = False,
    unknown_constraints: bool = False,
    unknown_immutability: bool = False,
    unknown_legal_hold: bool = False,
) -> TerraformResource:
    provider_name = configured_name or name
    values: dict[str, object] = {
        "id": f"https://{account_name}data.blob.core.windows.net/{provider_name}",
        "resource_manager_id": (f"{account_id}/blobServices/default/containers/{provider_name}"),
        "name": provider_name,
        "storage_account_id": f"azurerm_storage_account.{account_name}.id",
        "container_access_type": "private",
    }
    if has_immutability_policy is not None:
        values["has_immutability_policy"] = has_immutability_policy
    if has_legal_hold is not None:
        values["has_legal_hold"] = has_legal_hold
    unknown_values: dict[str, object] = {}
    if unknown_constraints:
        unknown_immutability = True
        unknown_legal_hold = True
    if unknown_immutability:
        unknown_values["has_immutability_policy"] = True
    if unknown_legal_hold:
        unknown_values["has_legal_hold"] = True
    return _resource(
        AzureResourceType.STORAGE_CONTAINER,
        values,
        name=name,
        unknown_values=unknown_values,
    )


def _control_role(
    *,
    actions: list[str],
    not_actions: list[str] | None = None,
    data_actions: list[str] | None = None,
    assignable_scopes: list[str] | None = None,
    unknown_actions: bool = False,
) -> TerraformResource:
    unknown_values: dict[str, object] = {}
    if unknown_actions:
        unknown_values = {"permissions": [{"actions": True}]}
    return _resource(
        AzureResourceType.ROLE_DEFINITION,
        {
            "id": _CONTROL_ROLE_ID,
            "role_definition_id": _CONTROL_ROLE_ID,
            "name": "Storage Container Topology Operator",
            "scope": "/subscriptions/sub-0001",
            "assignable_scopes": (assignable_scopes if assignable_scopes is not None else ["/subscriptions/sub-0001"]),
            "permissions": [
                {
                    "actions": actions,
                    "not_actions": not_actions or [],
                    "data_actions": data_actions or [],
                    "not_data_actions": [],
                }
            ],
        },
        name="storage_topology",
        unknown_values=unknown_values,
    )


def _control_assignment(
    *,
    scope: object = "azurerm_storage_container.orders.resource_manager_id",
    principal_id: object = _SYSTEM_PRINCIPAL_ID,
    condition: object | None = None,
    name: str = "storage_topology",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "scope": scope,
        "role_definition_id": ("azurerm_role_definition.storage_topology.role_definition_resource_id"),
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if condition is not None:
        values["condition"] = condition
        values["condition_version"] = "2.0"
    return _resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        values,
        name=name,
        unknown_values=unknown_values,
    )


def _inventory(*resources: TerraformResource):
    inventory = AzureNormalizer().normalize(list(resources))
    workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
    assert workload is not None
    return inventory, workload, azure_facts(workload)


class AzureAppServiceStorageContainerTopologyDestructionPathTests(
    unittest.TestCase,
):
    def test_exact_container_custom_role_preserves_authority_constraints_and_recovery(
        self,
    ) -> None:
        inventory, workload, facts = _inventory(
            _storage_account(),
            _storage_container(
                name="application_data",
                configured_name="orders",
            ),
            _web_app(),
            _control_role(
                actions=[
                    _DELETE_CONTAINER,
                    "Microsoft.Storage/storageAccounts/read",
                ]
            ),
            _control_assignment(scope=("azurerm_storage_container.application_data.resource_manager_id")),
        )

        self.assertFalse(workload.public_exposure)
        self.assertEqual(
            azure_facts(inventory.get_by_address("azurerm_storage_container.application_data")).bucket_name,
            "orders",
        )
        self.assertEqual(
            len(facts.app_service_storage_container_topology_destruction_paths),
            1,
        )
        path = facts.app_service_storage_container_topology_destruction_paths[0]
        self.assertEqual(path["workload_address"], _WORKLOAD_ADDRESS)
        self.assertEqual(path["identity_address"], _WORKLOAD_ADDRESS)
        self.assertEqual(path["identity_kind"], "system_assigned")
        self.assertEqual(path["principal_id"], _SYSTEM_PRINCIPAL_ID)
        self.assertEqual(path["storage_account_address"], _ACCOUNT_ADDRESS)
        self.assertEqual(path["storage_account_id"], _STORAGE_ACCOUNT_ID)
        self.assertEqual(
            path["container_address"],
            "azurerm_storage_container.application_data",
        )
        self.assertEqual(path["container_name"], "orders")
        self.assertEqual(
            path["container_resource_manager_id"],
            f"{_STORAGE_ACCOUNT_ID}/blobServices/default/containers/orders",
        )
        self.assertEqual(path["operation"], _DELETE_CONTAINER)
        self.assertEqual(path["operation_class"], "container_deletion")
        self.assertEqual(path["internal_operation"], "delete_container")
        self.assertEqual(path["management_effect"], "disruption")
        self.assertEqual(path["authorization_evidence_kind"], "azure_rbac_action")
        self.assertEqual(path["target_granularity"], "container_topology")
        self.assertEqual(path["target_scope"], "exact_storage_container")
        self.assertEqual(
            path["target_model_evidence_addresses"],
            [
                _ACCOUNT_ADDRESS,
                "azurerm_storage_container.application_data",
            ],
        )
        self.assertEqual(
            path["authorization_source_addresses"],
            [
                "azurerm_role_assignment.storage_topology",
                _CONTROL_ROLE_ADDRESS,
            ],
        )
        self.assertEqual(path["authorization_state"], "granted")
        self.assertTrue(path["modeled_allow_evidence_complete"])
        self.assertEqual(path["condition_state"], "not_configured")
        self.assertEqual(path["lifecycle_compatibility_state"], "compatible")

        grant = path["authorization_grant"]
        self.assertEqual(grant["target_arm_id"], path["container_resource_manager_id"])
        self.assertEqual(
            grant["assignment_scope_arm_id"],
            path["container_resource_manager_id"],
        )
        self.assertEqual(grant["assignment_scope_type"], "resource")
        self.assertEqual(grant["requested_actions"], [_DELETE_CONTAINER])
        self.assertEqual(grant["matched_actions"], [_DELETE_CONTAINER])
        self.assertEqual(grant["excluded_actions"], [])
        self.assertEqual(
            grant["evaluation_basis"],
            "modeled_azure_rbac_action_authority",
        )
        self.assertEqual(
            grant["role_evidence"],
            {
                "role_kind": "custom",
                "role_resolution_state": "resolved",
                "role_definition_address": _CONTROL_ROLE_ADDRESS,
                "assignable_scope_compatibility_state": "resolved",
            },
        )

        constraints = path["deletion_constraint_evidence"]
        self.assertFalse(constraints["has_immutability_policy"])
        self.assertFalse(constraints["has_legal_hold"])
        self.assertEqual(constraints["constraint_state"], "not_observed")
        self.assertFalse(constraints["protected_content_emptiness_required"])
        self.assertEqual(
            constraints["protected_content_emptiness_state"],
            "not_applicable",
        )
        self.assertEqual(
            constraints["arm_management_lock_applicability"],
            "not_applicable_to_storage_container_deletion",
        )

        recovery = path["recovery_evidence"]
        self.assertEqual(recovery["container_soft_delete_state"], "enabled")
        self.assertEqual(recovery["container_delete_retention_days"], 14)
        self.assertEqual(
            recovery["container_recovery_state"],
            "soft_delete_recovery_configured",
        )
        self.assertFalse(recovery["successful_deletion_observed"])
        self.assertFalse(recovery["restoration_observed"])
        self.assertFalse(recovery["storage_account_deletion_evaluated"])
        self.assertFalse(recovery["out_of_plan_blob_inventory_evaluated"])
        self.assertEqual(path["posture_uncertainties"], [])
        serialized = json.dumps(path, sort_keys=True)
        self.assertNotIn('"successful_deletion_observed": true', serialized)

    def test_account_scope_fans_out_only_to_exact_modeled_containers(self) -> None:
        foreign_account_id = (
            "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/foreign"
        )
        _inventory_value, _workload, facts = _inventory(
            _storage_account(),
            _storage_container(),
            _storage_container(name="archive"),
            _storage_account(name="foreign", account_id=foreign_account_id),
            _storage_container(
                name="foreign",
                account_name="foreign",
                account_id=foreign_account_id,
            ),
            _web_app(),
            _control_role(actions=[_DELETE_CONTAINER]),
            _control_assignment(scope="azurerm_storage_account.orders.id"),
        )

        paths = facts.app_service_storage_container_topology_destruction_paths
        self.assertEqual(len(paths), 2)
        self.assertEqual(
            {path["container_address"] for path in paths},
            {
                _CONTAINER_ADDRESS,
                "azurerm_storage_container.archive",
            },
        )
        self.assertFalse(any(path["container_address"] == "azurerm_storage_container.foreign" for path in paths))
        for path in paths:
            self.assertEqual(
                path["authorization_grant"]["assignment_scope_arm_id"],
                _STORAGE_ACCOUNT_ID,
            )

    def test_built_in_contributor_actions_and_data_actions_remain_distinct(
        self,
    ) -> None:
        _inventory_value, _workload, built_in = _inventory(
            _storage_account(),
            _storage_container(),
            _web_app(),
            _role_assignment(
                scope=("azurerm_storage_container.orders.resource_manager_id"),
                role_name="Contributor",
                role_definition_id=(
                    "/subscriptions/sub-0001/providers/"
                    "Microsoft.Authorization/roleDefinitions/"
                    "b24988ac-6180-42a0-ab88-20f7382dd24c"
                ),
            ),
        )
        self.assertEqual(
            len(built_in.app_service_storage_container_topology_destruction_paths),
            1,
        )
        self.assertEqual(
            built_in.app_service_storage_container_topology_destruction_paths[0]["authorization_grant"][
                "role_evidence"
            ]["role_kind"],
            "built_in",
        )

        _inventory_value, _workload, reader = _inventory(
            _storage_account(),
            _storage_container(),
            _web_app(),
            _role_assignment(
                scope=("azurerm_storage_container.orders.resource_manager_id"),
                role_name="Reader",
                role_definition_id=None,
            ),
        )
        self.assertEqual(
            reader.app_service_storage_container_topology_destruction_paths,
            [],
        )

        _inventory_value, _workload, data_only = _inventory(
            _storage_account(),
            _storage_container(),
            _web_app(),
            _control_role(
                actions=[],
                data_actions=[_DELETE_CONTAINER],
            ),
            _control_assignment(),
        )
        self.assertEqual(
            data_only.app_service_storage_container_topology_destruction_paths,
            [],
        )

    def test_storage_built_in_roles_resolve_by_name_and_id_at_container_scope(
        self,
    ) -> None:
        for role_name, role_id in _STORAGE_CONTAINER_DELETE_BUILT_IN_ROLES:
            for reference_kind in ("name", "id"):
                with self.subTest(role=role_name, reference=reference_kind):
                    assignment = _role_assignment(
                        scope=("azurerm_storage_container.orders.resource_manager_id"),
                        role_name=(role_name if reference_kind == "name" else "Reader"),
                        role_definition_id=(
                            None
                            if reference_kind == "name"
                            else (
                                f"/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/{role_id}"
                            )
                        ),
                    )
                    _inventory_value, _workload, facts = _inventory(
                        _storage_account(),
                        _storage_container(),
                        _web_app(),
                        assignment,
                    )

                    paths = facts.app_service_storage_container_topology_destruction_paths
                    self.assertEqual(len(paths), 1)
                    self.assertEqual(
                        paths[0]["container_address"],
                        _CONTAINER_ADDRESS,
                    )
                    grant = paths[0]["authorization_grant"]
                    self.assertEqual(
                        grant["role_evidence"]["role_kind"],
                        "built_in",
                    )
                    self.assertEqual(
                        grant["matched_actions"],
                        [_DELETE_CONTAINER],
                    )

    def test_storage_built_in_roles_resolve_by_name_and_id_at_account_scope(
        self,
    ) -> None:
        for role_name, role_id in _STORAGE_CONTAINER_DELETE_BUILT_IN_ROLES:
            for reference_kind in ("name", "id"):
                with self.subTest(role=role_name, reference=reference_kind):
                    assignment = _role_assignment(
                        scope="azurerm_storage_account.orders.id",
                        role_name=(role_name if reference_kind == "name" else "Reader"),
                        role_definition_id=(
                            None
                            if reference_kind == "name"
                            else (
                                f"/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/{role_id}"
                            )
                        ),
                    )
                    _inventory_value, _workload, facts = _inventory(
                        _storage_account(),
                        _storage_container(),
                        _storage_container(name="archive"),
                        _web_app(),
                        assignment,
                    )

                    paths = facts.app_service_storage_container_topology_destruction_paths
                    self.assertEqual(len(paths), 2)
                    self.assertEqual(
                        {path["container_address"] for path in paths},
                        {
                            _CONTAINER_ADDRESS,
                            "azurerm_storage_container.archive",
                        },
                    )
                    self.assertTrue(
                        all(path["authorization_grant"]["matched_actions"] == [_DELETE_CONTAINER] for path in paths)
                    )

    def test_conditions_exclusions_assignable_scope_and_identity_fail_closed(
        self,
    ) -> None:
        cases = {
            "condition": (
                _control_role(actions=[_DELETE_CONTAINER]),
                _control_assignment(
                    condition=(
                        "@Resource[Microsoft.Storage/storageAccounts/"
                        "blobServices/containers:Name] StringEquals 'orders'"
                    )
                ),
            ),
            "unknown condition version": (
                _control_role(actions=[_DELETE_CONTAINER]),
                _control_assignment(
                    unknown_values={"condition_version": True},
                ),
            ),
            "not action": (
                _control_role(
                    actions=["Microsoft.Storage/storageAccounts/*"],
                    not_actions=[_DELETE_CONTAINER],
                ),
                _control_assignment(),
            ),
            "outside assignable scope": (
                _control_role(
                    actions=[_DELETE_CONTAINER],
                    assignable_scopes=["/subscriptions/other-subscription"],
                ),
                _control_assignment(),
            ),
            "unknown actions": (
                _control_role(
                    actions=[_DELETE_CONTAINER],
                    unknown_actions=True,
                ),
                _control_assignment(),
            ),
            "other identity": (
                _control_role(actions=[_DELETE_CONTAINER]),
                _control_assignment(principal_id="other-principal"),
            ),
        }
        for case, (role, assignment) in cases.items():
            with self.subTest(case=case):
                _inventory_value, _workload, facts = _inventory(
                    _storage_account(),
                    _storage_container(),
                    _web_app(),
                    role,
                    assignment,
                )
                self.assertEqual(
                    facts.app_service_storage_container_topology_destruction_paths,
                    [],
                )

    def test_protection_posture_preserves_authority_and_qualifies_prerequisites(
        self,
    ) -> None:
        for case, container, expected_immutability, expected_legal_hold in (
            (
                "immutability",
                _storage_container(
                    has_immutability_policy=True,
                    has_legal_hold=False,
                ),
                True,
                False,
            ),
            (
                "legal hold",
                _storage_container(
                    has_immutability_policy=False,
                    has_legal_hold=True,
                ),
                False,
                True,
            ),
            (
                "known immutability with unknown legal hold",
                _storage_container(
                    has_immutability_policy=True,
                    has_legal_hold=None,
                    unknown_legal_hold=True,
                ),
                True,
                None,
            ),
            (
                "known legal hold with unknown immutability",
                _storage_container(
                    has_immutability_policy=None,
                    has_legal_hold=True,
                    unknown_immutability=True,
                ),
                None,
                True,
            ),
        ):
            with self.subTest(case=case):
                _inventory_value, _workload, facts = _inventory(
                    _storage_account(),
                    container,
                    _web_app(),
                    _control_role(actions=[_DELETE_CONTAINER]),
                    _control_assignment(),
                )
                self.assertEqual(
                    len(facts.app_service_storage_container_topology_destruction_paths),
                    1,
                )
                path = facts.app_service_storage_container_topology_destruction_paths[0]
                self.assertEqual(path["lifecycle_compatibility_state"], "unknown")
                constraints = path["deletion_constraint_evidence"]
                self.assertEqual(
                    constraints["has_immutability_policy"],
                    expected_immutability,
                )
                self.assertEqual(
                    constraints["has_legal_hold"],
                    expected_legal_hold,
                )
                self.assertEqual(
                    constraints["constraint_state"],
                    "protected_content_emptiness_not_established",
                )
                self.assertTrue(
                    constraints["protected_content_emptiness_required"],
                )
                self.assertEqual(
                    constraints["protected_content_emptiness_state"],
                    "not_established",
                )
                self.assertTrue(
                    any("protected-content emptiness" in uncertainty for uncertainty in constraints["uncertainties"])
                )
                self.assertTrue(path["posture_uncertainties"])
                self.assertFalse(path["recovery_evidence"]["successful_deletion_observed"])
                self.assertFalse(path["recovery_evidence"]["out_of_plan_blob_inventory_evaluated"])

        inventory, _workload, unknown = _inventory(
            _storage_account(),
            _storage_container(
                has_immutability_policy=None,
                has_legal_hold=None,
                unknown_constraints=True,
            ),
            _web_app(),
            _control_role(actions=[_DELETE_CONTAINER]),
            _control_assignment(),
        )
        container = inventory.get_by_address(_CONTAINER_ADDRESS)
        assert container is not None
        container_facts = azure_facts(container)
        self.assertIsNone(container_facts.storage_container_has_immutability_policy)
        self.assertIsNone(container_facts.storage_container_has_legal_hold)
        self.assertEqual(
            set(container_facts.storage_posture_uncertainties),
            {
                "has_immutability_policy is unknown after planning",
                "has_legal_hold is unknown after planning",
            },
        )
        self.assertEqual(
            len(unknown.app_service_storage_container_topology_destruction_paths),
            1,
        )
        path = unknown.app_service_storage_container_topology_destruction_paths[0]
        self.assertEqual(path["lifecycle_compatibility_state"], "unknown")
        constraints = path["deletion_constraint_evidence"]
        self.assertEqual(constraints["constraint_state"], "unknown")
        self.assertIsNone(constraints["has_immutability_policy"])
        self.assertIsNone(constraints["has_legal_hold"])
        self.assertIsNone(constraints["protected_content_emptiness_required"])
        self.assertEqual(
            constraints["protected_content_emptiness_state"],
            "unknown",
        )
        self.assertTrue(constraints["uncertainties"])
        self.assertTrue(path["posture_uncertainties"])
        self.assertTrue(unknown.app_service_storage_container_topology_destruction_path_uncertainties)

    def test_container_soft_delete_posture_qualifies_but_does_not_suppress_authority(
        self,
    ) -> None:
        cases = (
            ("enabled", 14, False, "enabled", 14),
            ("disabled", None, False, "disabled", None),
            ("unknown", 14, True, "unknown", None),
        )
        for case, days, unknown_recovery, expected_state, expected_days in cases:
            with self.subTest(case=case):
                _inventory_value, _workload, facts = _inventory(
                    _storage_account(
                        container_delete_days=days,
                        unknown_recovery=unknown_recovery,
                    ),
                    _storage_container(),
                    _web_app(),
                    _control_role(actions=[_DELETE_CONTAINER]),
                    _control_assignment(),
                )
                self.assertEqual(
                    len(facts.app_service_storage_container_topology_destruction_paths),
                    1,
                )
                recovery = facts.app_service_storage_container_topology_destruction_paths[0]["recovery_evidence"]
                self.assertEqual(
                    recovery["container_soft_delete_state"],
                    expected_state,
                )
                self.assertEqual(
                    recovery["container_delete_retention_days"],
                    expected_days,
                )
                self.assertFalse(recovery["successful_deletion_observed"])
                self.assertFalse(recovery["restoration_observed"])

    def test_system_and_user_assigned_identities_remain_distinct(self) -> None:
        app = _web_app(
            identity_type="SystemAssigned, UserAssigned",
            identity_ids=["azurerm_user_assigned_identity.orders_runtime.id"],
        )
        _inventory_value, _workload, facts = _inventory(
            _storage_account(),
            _storage_container(),
            _user_assigned_identity(),
            app,
            _control_role(actions=[_DELETE_CONTAINER]),
            _control_assignment(name="system_topology"),
            _control_assignment(
                principal_id=_USER_PRINCIPAL_ID,
                name="user_topology",
            ),
        )

        paths = facts.app_service_storage_container_topology_destruction_paths
        self.assertEqual(len(paths), 2)
        self.assertEqual(
            {
                (
                    path["identity_address"],
                    path["identity_kind"],
                    path["principal_id"],
                )
                for path in paths
            },
            {
                (
                    _WORKLOAD_ADDRESS,
                    "system_assigned",
                    _SYSTEM_PRINCIPAL_ID,
                ),
                (
                    "azurerm_user_assigned_identity.orders_runtime",
                    "user_assigned",
                    _USER_PRINCIPAL_ID,
                ),
            },
        )

    def test_current_helper_recomputes_authorization_and_private_paths_survive(
        self,
    ) -> None:
        inventory, workload, facts = _inventory(
            _storage_account(),
            _storage_container(),
            _web_app(),
            _control_role(actions=[_DELETE_CONTAINER]),
            _control_assignment(),
        )
        self.assertFalse(workload.public_exposure)
        self.assertEqual(
            len(facts.app_service_storage_container_topology_destruction_paths),
            1,
        )

        container = inventory.get_by_address(_CONTAINER_ADDRESS)
        role = inventory.get_by_address(_CONTROL_ROLE_ADDRESS)
        assert container is not None
        assert role is not None
        context = AzureDecorationContext(index=AzureResourceIndexBuilder().build(list(inventory.resources)))
        self.assertEqual(
            len(
                current_app_service_storage_container_topology_destruction_paths(
                    workload,
                    container,
                    list(inventory.resources),
                    context,
                )
            ),
            1,
        )

        azure_facts(role).set(AzureResourceMetadata.ROLE_DEFINITION_ACTIONS, [])
        self.assertEqual(
            current_app_service_storage_container_topology_destruction_paths(
                workload,
                container,
                list(inventory.resources),
                context,
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()

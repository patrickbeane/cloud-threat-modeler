from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _QUEUE_ID,
    _entity,
    _namespace,
    _subscription,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _role_assignment as service_bus_role_assignment,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _STORAGE_ACCOUNT_ID,
)
from tests.providers.azure.test_azure_key_vault_encryption_dependencies import (
    _resource as dependency_resource,
)
from tests.providers.test_protected_data_key_authority_convergence import (
    _AZURE_KEY_URI,
    _AZURE_KEY_VERSIONLESS_URI,
    AZURE_USER_PRINCIPAL_ID,
    _azure_dual_identity_resources,
    _azure_exact_key_mismatch_resources,
    _azure_key,
    _azure_resources,
    _azure_role_assignment,
    _azure_vault,
    _azure_web_app,
    azure_user_assigned_identity,
)
from tests.providers.test_public_workload_managed_key_operation_boundaries import (
    _AZURE_CRYPTO_USER_ROLE_ID,
    _AZURE_RUNTIME_PRINCIPAL_ID,
)
from tfstride.models import NormalizedResource, ResourceInventory, TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_decoration_stages import (
    default_azure_decoration_stages,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_RECEIVER_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0"
)
_SENDER_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/69a216fc-b8fb-44d8-bc22-1f3c2cd27a39"
)


def _resource(inventory: ResourceInventory, address: str) -> NormalizedResource:
    resource = inventory.get_by_address(address)
    assert resource is not None
    return resource


def _normalize(resources: list[TerraformResource]) -> ResourceInventory:
    return AzureNormalizer().normalize(resources)


def _user_assigned_storage_resources() -> list[TerraformResource]:
    resources = _azure_resources(key_principal_id=AZURE_USER_PRINCIPAL_ID)
    workload = next(resource for resource in resources if resource.address == "azurerm_linux_web_app.orders")
    identities = workload.values["identity"]
    assert isinstance(identities, list)
    identity = identities[0]
    assert isinstance(identity, dict)
    identity["type"] = "UserAssigned"
    identity["principal_id"] = None
    identity["identity_ids"] = ["azurerm_user_assigned_identity.orders_runtime.id"]
    storage_assignment = next(
        resource for resource in resources if resource.address == "azurerm_role_assignment.orders_blob"
    )
    storage_assignment.values["principal_id"] = AZURE_USER_PRINCIPAL_ID
    resources.append(azure_user_assigned_identity())
    return resources


def _direct_storage_account_resources() -> list[TerraformResource]:
    resources = _azure_resources()
    assignment = next(resource for resource in resources if resource.address == "azurerm_role_assignment.orders_blob")
    assignment.values["scope"] = _STORAGE_ACCOUNT_ID
    assignment.unknown_values.pop("scope", None)
    assignment.reference_resolutions = tuple(
        resolution for resolution in assignment.reference_resolutions if resolution.path != ("scope",)
    )
    return resources


def _versionless_storage_resources() -> list[TerraformResource]:
    resources = _azure_resources()
    account = next(resource for resource in resources if resource.address == "azurerm_storage_account.orders")
    customer_managed_key = account.values["customer_managed_key"]
    assert isinstance(customer_managed_key, list)
    record = customer_managed_key[0]
    assert isinstance(record, dict)
    record["key_vault_key_id"] = _AZURE_KEY_VERSIONLESS_URI
    return resources


def _service_bus_resources(
    target_type: str,
    *,
    receive: bool = True,
) -> list[TerraformResource]:
    key_role = _azure_role_assignment(
        "key_access",
        role_id=_AZURE_CRYPTO_USER_ROLE_ID,
        role_name="Key Vault Crypto User",
    )
    if target_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        target_resources = []
        target_reference = "azurerm_servicebus_namespace.orders.id"
    elif target_type == AzureResourceType.SERVICE_BUS_QUEUE:
        target_resources = [_entity(target_type, _QUEUE_ID)]
        target_reference = "azurerm_servicebus_queue.orders.id"
    elif target_type == AzureResourceType.SERVICE_BUS_SUBSCRIPTION:
        target_resources = [
            _entity(
                AzureResourceType.SERVICE_BUS_TOPIC,
                f"{_namespace_id()}/topics/orders",
            ),
            _subscription(),
        ]
        target_reference = "azurerm_servicebus_subscription.orders.id"
    else:
        raise AssertionError(f"unsupported test target {target_type}")

    role = service_bus_role_assignment(
        principal_id=_AZURE_RUNTIME_PRINCIPAL_ID,
        scope=target_reference,
        role_name=("Azure Service Bus Data Receiver" if receive else "Azure Service Bus Data Sender"),
        role_definition_id=_RECEIVER_ROLE_ID if receive else _SENDER_ROLE_ID,
    )
    customer_managed_key = dependency_resource(
        AzureResourceType.SERVICE_BUS_NAMESPACE_CUSTOMER_MANAGED_KEY,
        "orders",
        {
            "namespace_id": "azurerm_servicebus_namespace.orders.id",
            "key_vault_key_id": _AZURE_KEY_VERSIONLESS_URI,
        },
    )
    return [
        _azure_vault(rbac_enabled=True),
        _azure_key(
            "data",
            key_type="RSA-HSM",
            key_opts=["decrypt", "unwrapKey"],
        ),
        _azure_web_app(public=True),
        key_role,
        _namespace(),
        *target_resources,
        customer_managed_key,
        role,
    ]


def _namespace_id() -> str:
    return "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ServiceBus/namespaces/orders-events"


class AzureAppServiceKeyVaultProtectedDataConvergenceTests(unittest.TestCase):
    def test_system_identity_container_read_converges_with_versioned_key(self) -> None:
        inventory = _normalize(_azure_resources())
        workload = _resource(inventory, "azurerm_linux_web_app.orders")
        facts = azure_facts(workload)

        convergences = facts.app_service_storage_protected_data_convergences
        self.assertEqual(
            [convergence["operation"] for convergence in convergences],
            ["decrypt", "unwrap"],
        )
        for convergence in convergences:
            self.assertEqual(convergence["identity_kind"], "system_assigned")
            self.assertEqual(convergence["identity_address"], workload.address)
            self.assertEqual(
                convergence["principal_id"],
                _AZURE_RUNTIME_PRINCIPAL_ID,
            )
            self.assertEqual(
                convergence["storage_resource_address"],
                "azurerm_storage_container.orders",
            )
            self.assertEqual(
                convergence["storage_account_address"],
                "azurerm_storage_account.orders",
            )
            self.assertEqual(
                convergence["encryption_dependency"]["target_kind"],
                "key_version",
            )
            self.assertEqual(convergence["key_uri"], _AZURE_KEY_URI)
            self.assertEqual(
                convergence["key_versionless_uri"],
                _AZURE_KEY_VERSIONLESS_URI,
            )
            self.assertTrue(convergence["runtime_identity_match"])
            self.assertTrue(convergence["protected_resource_match"])
            self.assertTrue(convergence["key_identity_match"])
        self.assertEqual(
            facts.app_service_storage_protected_data_convergence_uncertainties,
            [],
        )

    def test_exact_storage_account_read_converges_directly(self) -> None:
        inventory = _normalize(_direct_storage_account_resources())
        workload = _resource(inventory, "azurerm_linux_web_app.orders")
        facts = azure_facts(workload)
        convergences = facts.app_service_storage_protected_data_convergences

        self.assertEqual(
            [convergence["operation"] for convergence in convergences],
            ["decrypt", "unwrap"],
        )
        for convergence in convergences:
            self.assertEqual(
                convergence["storage_resource_address"],
                "azurerm_storage_account.orders",
            )
            self.assertEqual(
                convergence["storage_account_address"],
                "azurerm_storage_account.orders",
            )
            self.assertEqual(
                convergence["access_path"]["resource_scope"],
                "exact_storage_account",
            )
            self.assertIsNone(convergence["access_path"]["container_address"])
            self.assertEqual(
                convergence["encryption_dependency"]["dependent_address"],
                "azurerm_storage_account.orders",
            )
        self.assertEqual(
            facts.app_service_storage_protected_data_convergence_uncertainties,
            [],
        )

    def test_user_assigned_identity_must_hold_both_authorities(self) -> None:
        inventory = _normalize(_user_assigned_storage_resources())
        workload = _resource(inventory, "azurerm_linux_web_app.orders")
        convergences = azure_facts(workload).app_service_storage_protected_data_convergences

        self.assertEqual(len(convergences), 2)
        self.assertEqual(
            {convergence["identity_kind"] for convergence in convergences},
            {"user_assigned"},
        )
        self.assertEqual(
            {convergence["identity_address"] for convergence in convergences},
            {"azurerm_user_assigned_identity.orders_runtime"},
        )
        self.assertEqual(
            {convergence["principal_id"] for convergence in convergences},
            {AZURE_USER_PRINCIPAL_ID},
        )

    def test_versionless_dependency_does_not_claim_a_versioned_target(self) -> None:
        inventory = _normalize(_versionless_storage_resources())
        workload = _resource(inventory, "azurerm_linux_web_app.orders")
        convergences = azure_facts(workload).app_service_storage_protected_data_convergences

        self.assertEqual(len(convergences), 2)
        for convergence in convergences:
            self.assertEqual(
                convergence["encryption_dependency"]["target_kind"],
                "key",
            )
            self.assertIsNone(convergence["key_uri"])
            self.assertEqual(
                convergence["key_versionless_uri"],
                _AZURE_KEY_VERSIONLESS_URI,
            )
            self.assertEqual(
                convergence["key_operation_path"]["key_uri"],
                _AZURE_KEY_URI,
            )

    def test_exact_service_bus_namespace_receive_converges_directly(self) -> None:
        inventory = _normalize(_service_bus_resources(AzureResourceType.SERVICE_BUS_NAMESPACE))
        workload = _resource(inventory, "azurerm_linux_web_app.orders")
        facts = azure_facts(workload)
        convergences = facts.app_service_service_bus_protected_data_convergences

        self.assertEqual(
            [convergence["operation"] for convergence in convergences],
            ["decrypt", "unwrap"],
        )
        for convergence in convergences:
            self.assertEqual(
                convergence["service_bus_resource_address"],
                "azurerm_servicebus_namespace.orders",
            )
            self.assertEqual(
                convergence["service_bus_namespace_address"],
                "azurerm_servicebus_namespace.orders",
            )
            self.assertEqual(
                convergence["access_path"]["resource_scope"],
                "exact_service_bus_namespace",
            )
            self.assertIsNone(convergence["access_path"]["queue_address"])
            self.assertIsNone(convergence["access_path"]["topic_address"])
            self.assertIsNone(convergence["access_path"]["subscription_address"])
            self.assertEqual(
                convergence["encryption_dependency"]["dependent_address"],
                "azurerm_servicebus_namespace.orders",
            )
        self.assertEqual(
            facts.app_service_service_bus_protected_data_convergence_uncertainties,
            [],
        )

    def test_queue_and_subscription_receive_resolve_namespace_dependency(self) -> None:
        for target_type in (
            AzureResourceType.SERVICE_BUS_QUEUE,
            AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
        ):
            with self.subTest(target_type=target_type):
                inventory = _normalize(_service_bus_resources(target_type))
                workload = _resource(
                    inventory,
                    "azurerm_linux_web_app.orders",
                )
                facts = azure_facts(workload)
                convergences = facts.app_service_service_bus_protected_data_convergences

                self.assertEqual(
                    [item["operation"] for item in convergences],
                    ["decrypt", "unwrap"],
                )
                self.assertEqual(
                    {item["service_bus_resource_type"] for item in convergences},
                    {target_type},
                )
                self.assertEqual(
                    {item["service_bus_namespace_address"] for item in convergences},
                    {"azurerm_servicebus_namespace.orders"},
                )
                self.assertEqual(
                    {item["encryption_dependency"]["target_kind"] for item in convergences},
                    {"key"},
                )
                self.assertEqual(
                    {item["key_uri"] for item in convergences},
                    {None},
                )
                self.assertEqual(
                    {item["key_versionless_uri"] for item in convergences},
                    {_AZURE_KEY_VERSIONLESS_URI},
                )
                self.assertEqual(
                    facts.app_service_service_bus_protected_data_convergence_uncertainties,
                    [],
                )

    def test_send_only_service_bus_authority_stays_out_of_convergence(self) -> None:
        inventory = _normalize(
            _service_bus_resources(
                AzureResourceType.SERVICE_BUS_QUEUE,
                receive=False,
            )
        )
        workload = _resource(inventory, "azurerm_linux_web_app.orders")
        facts = azure_facts(workload)

        self.assertEqual(
            facts.app_service_service_bus_protected_data_convergences,
            [],
        )
        self.assertEqual(
            facts.app_service_service_bus_protected_data_convergence_uncertainties,
            [],
        )

    def test_exact_key_and_runtime_identity_mismatches_do_not_converge(self) -> None:
        cases = (
            _azure_exact_key_mismatch_resources(),
            _azure_dual_identity_resources(),
        )
        for resources in cases:
            with self.subTest(resources=len(resources)):
                inventory = _normalize(resources)
                workload = _resource(
                    inventory,
                    "azurerm_linux_web_app.orders",
                )
                self.assertEqual(
                    azure_facts(workload).app_service_storage_protected_data_convergences,
                    [],
                )

    def test_conditional_access_and_ambiguous_dependency_remain_uncertain(self) -> None:
        conditional = _normalize(
            _azure_resources(
                storage_condition=(
                    "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'orders'"
                )
            )
        )
        ambiguous = _normalize(_azure_resources(ambiguous_dependency=True))

        for inventory in (conditional, ambiguous):
            workload = _resource(
                inventory,
                "azurerm_linux_web_app.orders",
            )
            facts = azure_facts(workload)
            self.assertEqual(
                facts.app_service_storage_protected_data_convergences,
                [],
            )
            self.assertTrue(facts.app_service_storage_protected_data_convergence_uncertainties)

    def test_convergence_stage_runs_after_all_three_evidence_inputs(self) -> None:
        names = [stage.name for stage in default_azure_decoration_stages()]
        convergence = names.index("model_app_service_key_vault_protected_data_convergence")
        for stage_name in (
            "resolve_azure_key_vault_encryption_dependencies",
            "model_app_service_key_vault_operation_paths",
            "model_app_service_storage_access_paths",
            "model_app_service_service_bus_access_paths",
        ):
            with self.subTest(stage_name=stage_name):
                self.assertLess(names.index(stage_name), convergence)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest
from pathlib import Path

from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import (
    NormalizedResource,
    ResourceCategory,
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
    TerraformResource,
)
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_decoration.symbolic_relationships import (
    ResolveAzureSymbolicRelationshipsStage,
)
from tfstride.providers.azure.resource_decorator import AzureResourceDecorator
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_FIRST_APPLY_FIXTURE = _REPOSITORY_ROOT / "fixtures/azure/sample_azure_first_apply_symbolic_plan.json"
_SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000000"
_RESOURCE_GROUP = "tfstride-demo"
_IDENTITY_ID = (
    f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/{_RESOURCE_GROUP}/providers/"
    "Microsoft.ManagedIdentity/userAssignedIdentities/runtime"
)
_IDENTITY_PRINCIPAL_ID = "11111111-1111-1111-1111-111111111111"
_STORAGE_ID = (
    f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/{_RESOURCE_GROUP}/providers/"
    "Microsoft.Storage/storageAccounts/orders"
)
_ROLE_DEFINITION_ID = (
    f"/subscriptions/{_SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/"
    "22222222-2222-2222-2222-222222222222"
)
_VAULT_ID = (
    f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/{_RESOURCE_GROUP}/providers/"
    "Microsoft.KeyVault/vaults/application"
)
_SERVICE_BUS_NAMESPACE_ID = (
    f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/{_RESOURCE_GROUP}/providers/"
    "Microsoft.ServiceBus/namespaces/orders"
)
_SERVICE_BUS_TOPIC_ID = f"{_SERVICE_BUS_NAMESPACE_ID}/topics/events"
_SERVICE_BUS_QUEUE_ID = f"{_SERVICE_BUS_NAMESPACE_ID}/queues/jobs"
_COSMOS_ACCOUNT_ID = (
    f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/{_RESOURCE_GROUP}/providers/"
    "Microsoft.DocumentDB/databaseAccounts/orders"
)
_COSMOS_OTHER_ACCOUNT_ID = (
    f"/subscriptions/{_SUBSCRIPTION_ID}/resourceGroups/{_RESOURCE_GROUP}/providers/"
    "Microsoft.DocumentDB/databaseAccounts/audit"
)
_COSMOS_DATABASE_ID = f"{_COSMOS_ACCOUNT_ID}/sqlDatabases/app"
_COSMOS_CONTAINER_ID = f"{_COSMOS_DATABASE_ID}/containers/events"
_COSMOS_ROLE_GUID = "33333333-3333-3333-3333-333333333333"
_COSMOS_ROLE_ID = f"{_COSMOS_ACCOUNT_ID}/sqlRoleDefinitions/{_COSMOS_ROLE_GUID}"


def _terraform_resource(
    address: str,
    resource_type: str,
    values: dict[str, object],
    *,
    unknown_values: dict[str, object] | None = None,
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = (),
) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values=unknown_values or {},
        reference_resolutions=reference_resolutions,
    )


def _symbolic_resolution(
    path: tuple[str | int, ...],
    target_address: str,
    target_suffix: str,
) -> TerraformReferenceResolution:
    reference = f"{target_address}{target_suffix}"
    return TerraformReferenceResolution(
        path=path,
        state=TerraformReferenceResolutionState.SYMBOLIC,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=(reference,),
        targets=(TerraformReferenceTarget(address=target_address, reference=reference),),
    )


def _identity(*, known_id: bool = True) -> TerraformResource:
    values: dict[str, object] = {
        "name": "runtime",
        "principal_id": _IDENTITY_PRINCIPAL_ID,
        "client_id": "44444444-4444-4444-4444-444444444444",
        "tenant_id": "55555555-5555-5555-5555-555555555555",
    }
    unknown_values: dict[str, object] = {}
    if known_id:
        values["id"] = _IDENTITY_ID
    else:
        unknown_values["id"] = True
    return _terraform_resource(
        "azurerm_user_assigned_identity.runtime",
        AzureResourceType.USER_ASSIGNED_IDENTITY,
        values,
        unknown_values=unknown_values,
    )


class AzureSymbolicRelationshipTests(unittest.TestCase):
    def test_authentic_first_apply_scope_targets_survive_normalization(self) -> None:
        inventory = AzureNormalizer().normalize(load_terraform_plan(_FIRST_APPLY_FIXTURE).resources)

        direct = inventory.get_by_address("azurerm_role_assignment.direct")
        module_assignment = inventory.get_by_address("module.passed.azurerm_role_assignment.this")
        ambiguous = inventory.get_by_address("azurerm_role_assignment.ambiguous")
        assert direct is not None
        assert module_assignment is not None
        assert ambiguous is not None

        self.assertEqual(
            direct.reference_resolution("scope").state,
            TerraformReferenceResolutionState.SYMBOLIC,
        )
        self.assertIsNone(azure_facts(direct).role_assignment_scope)
        self.assertEqual(
            azure_facts(direct).role_assignment_target_resource_address,
            "azurerm_storage_account.direct",
        )
        self.assertEqual(
            azure_facts(module_assignment).role_assignment_target_resource_address,
            "azurerm_storage_account.passed",
        )
        self.assertIsNone(azure_facts(ambiguous).role_assignment_target_resource_address)

    def test_app_service_resolves_user_identity_without_fabricating_arm_id(self) -> None:
        identity = _identity(known_id=False)
        workload = _terraform_resource(
            "azurerm_linux_web_app.api",
            AzureResourceType.LINUX_WEB_APP,
            {
                "name": "api",
                "identity": [{"type": "UserAssigned", "identity_ids": None}],
            },
            unknown_values={"id": True, "identity": [{"identity_ids": True}]},
            reference_resolutions=(
                _symbolic_resolution(
                    ("identity", 0, "identity_ids"),
                    identity.address,
                    ".id",
                ),
            ),
        )

        inventory = AzureNormalizer().normalize([identity, workload])
        normalized = inventory.get_by_address(workload.address)
        assert normalized is not None
        facts = azure_facts(normalized)

        self.assertEqual(
            facts.resolved_attached_identity_addresses,
            [identity.address],
        )
        self.assertEqual(facts.attached_identity_references, [])
        self.assertNotIn(identity.address, facts.attached_identity_references)

    def test_role_assignment_resolves_principal_role_and_arm_scope(self) -> None:
        identity = _identity()
        role = _terraform_resource(
            "azurerm_role_definition.reader",
            AzureResourceType.ROLE_DEFINITION,
            {
                "name": "tfstride-reader",
                "role_definition_resource_id": _ROLE_DEFINITION_ID,
                "scope": f"/subscriptions/{_SUBSCRIPTION_ID}",
                "assignable_scopes": [f"/subscriptions/{_SUBSCRIPTION_ID}"],
                "permissions": [{"actions": ["Microsoft.Storage/storageAccounts/read"]}],
            },
        )
        storage = _terraform_resource(
            "azurerm_storage_account.orders",
            AzureResourceType.STORAGE_ACCOUNT,
            {
                "id": _STORAGE_ID,
                "name": "orders",
                "public_network_access_enabled": False,
            },
        )
        assignment = _terraform_resource(
            "azurerm_role_assignment.reader",
            AzureResourceType.ROLE_ASSIGNMENT,
            {},
            unknown_values={
                "principal_id": True,
                "role_definition_id": True,
                "scope": True,
            },
            reference_resolutions=(
                _symbolic_resolution(("principal_id",), identity.address, ".principal_id"),
                _symbolic_resolution(
                    ("role_definition_id",),
                    role.address,
                    ".role_definition_resource_id",
                ),
                _symbolic_resolution(("scope",), storage.address, ".id"),
            ),
        )

        inventory = AzureNormalizer().normalize([identity, role, storage, assignment])
        normalized = inventory.get_by_address(assignment.address)
        assert normalized is not None
        facts = azure_facts(normalized)

        self.assertEqual(facts.principal_id, _IDENTITY_PRINCIPAL_ID)
        self.assertEqual(facts.resolved_managed_identity_address, identity.address)
        self.assertEqual(facts.role_definition_id, _ROLE_DEFINITION_ID)
        self.assertEqual(facts.resolved_role_definition_address, role.address)
        self.assertEqual(facts.role_assignment_scope, _STORAGE_ID)
        self.assertEqual(facts.role_assignment_target_resource_address, storage.address)
        assert facts.role_assignment_scope is not None
        assert facts.role_definition_id is not None
        self.assertFalse(facts.role_assignment_scope.startswith("azurerm_"))
        self.assertFalse(facts.role_definition_id.startswith("azurerm_"))

    def test_key_vault_key_resolves_exact_vault_parent(self) -> None:
        vault = _terraform_resource(
            "azurerm_key_vault.application",
            AzureResourceType.KEY_VAULT,
            {
                "id": _VAULT_ID,
                "name": "application",
                "vault_uri": "https://application.vault.azure.net",
            },
        )
        key = _terraform_resource(
            "azurerm_key_vault_key.signing",
            AzureResourceType.KEY_VAULT_KEY,
            {"name": "signing", "key_type": "RSA", "key_opts": ["sign", "verify"]},
            unknown_values={"id": True, "key_vault_id": True, "version": True},
            reference_resolutions=(_symbolic_resolution(("key_vault_id",), vault.address, ".id"),),
        )

        inventory = AzureNormalizer().normalize([vault, key])
        normalized = inventory.get_by_address(key.address)
        assert normalized is not None
        facts = azure_facts(normalized)

        self.assertEqual(facts.key_vault_reference, _VAULT_ID)
        self.assertEqual(facts.resolved_key_vault_address, vault.address)
        self.assertEqual(
            facts.key_vault_key_versionless_uri,
            "https://application.vault.azure.net/keys/signing",
        )
        self.assertEqual(
            facts.key_vault_key_versionless_resource_id,
            f"{_VAULT_ID}/keys/signing",
        )

    def test_service_bus_entities_resolve_namespace_and_topic_ancestry(self) -> None:
        namespace = _terraform_resource(
            "azurerm_servicebus_namespace.orders",
            AzureResourceType.SERVICE_BUS_NAMESPACE,
            {"id": _SERVICE_BUS_NAMESPACE_ID, "name": "orders", "sku": "Premium"},
        )
        queue = _terraform_resource(
            "azurerm_servicebus_queue.jobs",
            AzureResourceType.SERVICE_BUS_QUEUE,
            {"name": "jobs"},
            unknown_values={"id": True, "namespace_id": True},
            reference_resolutions=(_symbolic_resolution(("namespace_id",), namespace.address, ".id"),),
        )
        topic = _terraform_resource(
            "azurerm_servicebus_topic.events",
            AzureResourceType.SERVICE_BUS_TOPIC,
            {"id": _SERVICE_BUS_TOPIC_ID, "name": "events"},
            unknown_values={"namespace_id": True},
            reference_resolutions=(_symbolic_resolution(("namespace_id",), namespace.address, ".id"),),
        )
        subscription = _terraform_resource(
            "azurerm_servicebus_subscription.workers",
            AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
            {"name": "workers"},
            unknown_values={"id": True, "topic_id": True},
            reference_resolutions=(_symbolic_resolution(("topic_id",), topic.address, ".id"),),
        )

        inventory = AzureNormalizer().normalize([namespace, queue, topic, subscription])
        normalized_queue = inventory.get_by_address(queue.address)
        normalized_topic = inventory.get_by_address(topic.address)
        normalized_subscription = inventory.get_by_address(subscription.address)
        assert normalized_queue is not None
        assert normalized_topic is not None
        assert normalized_subscription is not None

        self.assertEqual(
            azure_facts(normalized_queue).service_bus_namespace_reference,
            _SERVICE_BUS_NAMESPACE_ID,
        )
        self.assertEqual(
            azure_facts(normalized_queue).resolved_service_bus_namespace_address,
            namespace.address,
        )
        self.assertEqual(
            azure_facts(normalized_topic).resolved_service_bus_namespace_address,
            namespace.address,
        )
        self.assertEqual(
            azure_facts(normalized_subscription).service_bus_topic_reference,
            _SERVICE_BUS_TOPIC_ID,
        )
        self.assertEqual(
            azure_facts(normalized_subscription).resolved_service_bus_topic_address,
            topic.address,
        )
        self.assertEqual(
            azure_facts(normalized_subscription).resolved_service_bus_namespace_address,
            namespace.address,
        )

    def test_cosmos_symbolic_resolution_is_independent_of_resource_order(self) -> None:
        account = _terraform_resource(
            "azurerm_cosmosdb_account.orders",
            AzureResourceType.COSMOSDB_ACCOUNT,
            {
                "id": _COSMOS_ACCOUNT_ID,
                "name": "orders",
                "resource_group_name": _RESOURCE_GROUP,
                "public_network_access_enabled": False,
            },
        )
        database = _terraform_resource(
            "azurerm_cosmosdb_sql_database.app",
            AzureResourceType.COSMOSDB_SQL_DATABASE,
            {"name": "app"},
            unknown_values={"id": True, "account_name": True, "resource_group_name": True},
            reference_resolutions=(_symbolic_resolution(("account_name",), account.address, ".name"),),
        )
        container = _terraform_resource(
            "azurerm_cosmosdb_sql_container.events",
            AzureResourceType.COSMOSDB_SQL_CONTAINER,
            {"name": "events"},
            unknown_values={
                "id": True,
                "account_name": True,
                "database_name": True,
                "resource_group_name": True,
            },
            reference_resolutions=(
                _symbolic_resolution(("account_name",), account.address, ".name"),
                _symbolic_resolution(("database_name",), database.address, ".name"),
            ),
        )
        role = _terraform_resource(
            "azurerm_cosmosdb_sql_role_definition.writer",
            AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION,
            {
                "id": _COSMOS_ROLE_ID,
                "role_definition_id": _COSMOS_ROLE_GUID,
                "name": "writer",
                "type": "CustomRole",
                "assignable_scopes": [_COSMOS_ACCOUNT_ID],
                "permissions": [
                    {"data_actions": ["Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/create"]}
                ],
            },
            unknown_values={"account_name": True, "resource_group_name": True},
            reference_resolutions=(_symbolic_resolution(("account_name",), account.address, ".name"),),
        )
        identity = _identity()
        assignment = _terraform_resource(
            "azurerm_cosmosdb_sql_role_assignment.writer",
            AzureResourceType.COSMOSDB_SQL_ROLE_ASSIGNMENT,
            {"name": "writer-assignment"},
            unknown_values={
                "account_name": True,
                "resource_group_name": True,
                "principal_id": True,
                "role_definition_id": True,
                "scope": True,
            },
            reference_resolutions=(
                _symbolic_resolution(("account_name",), account.address, ".name"),
                _symbolic_resolution(("principal_id",), identity.address, ".principal_id"),
                _symbolic_resolution(("role_definition_id",), role.address, ".id"),
                _symbolic_resolution(("scope",), account.address, ".id"),
            ),
        )

        inventory = AzureNormalizer().normalize([assignment, identity, role, container, database, account])
        normalized_database = inventory.get_by_address(database.address)
        normalized_container = inventory.get_by_address(container.address)
        normalized_role = inventory.get_by_address(role.address)
        normalized_assignment = inventory.get_by_address(assignment.address)
        assert normalized_database is not None
        assert normalized_container is not None
        assert normalized_role is not None
        assert normalized_assignment is not None

        self.assertEqual(
            azure_facts(normalized_database).resolved_cosmosdb_account_address,
            account.address,
        )
        self.assertEqual(
            azure_facts(normalized_container).resolved_cosmosdb_database_address,
            database.address,
        )
        self.assertEqual(
            azure_facts(normalized_role).resolved_cosmosdb_account_address,
            account.address,
        )
        assignment_facts = azure_facts(normalized_assignment)
        self.assertEqual(assignment_facts.cosmosdb_sql_principal_id, _IDENTITY_PRINCIPAL_ID)
        self.assertEqual(assignment_facts.resolved_managed_identity_address, identity.address)
        self.assertEqual(
            assignment_facts.cosmosdb_sql_role_definition_reference,
            _COSMOS_ROLE_ID,
        )
        self.assertEqual(
            assignment_facts.resolved_cosmosdb_sql_role_definition_address,
            role.address,
        )
        self.assertEqual(assignment_facts.cosmosdb_sql_role_assignment_scope, _COSMOS_ACCOUNT_ID)
        self.assertEqual(assignment_facts.cosmosdb_sql_role_assignment_scope_state, "resolved")
        self.assertEqual(
            assignment_facts.cosmosdb_sql_role_data_actions,
            ["Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/create"],
        )

    def test_role_assignment_to_service_bus_queue_uses_queue_id(self) -> None:
        namespace = _terraform_resource(
            "azurerm_servicebus_namespace.orders",
            AzureResourceType.SERVICE_BUS_NAMESPACE,
            {"id": _SERVICE_BUS_NAMESPACE_ID, "name": "orders", "sku": "Premium"},
        )
        queue = _terraform_resource(
            "azurerm_servicebus_queue.jobs",
            AzureResourceType.SERVICE_BUS_QUEUE,
            {
                "id": _SERVICE_BUS_QUEUE_ID,
                "name": "jobs",
                "namespace_id": _SERVICE_BUS_NAMESPACE_ID,
            },
        )
        assignment = _terraform_resource(
            "azurerm_role_assignment.queue_reader",
            AzureResourceType.ROLE_ASSIGNMENT,
            {
                "principal_id": _IDENTITY_PRINCIPAL_ID,
                "role_definition_name": "Azure Service Bus Data Receiver",
            },
            unknown_values={"scope": True},
            reference_resolutions=(_symbolic_resolution(("scope",), queue.address, ".id"),),
        )

        inventory = AzureNormalizer().normalize([assignment, queue, namespace])
        normalized = inventory.get_by_address(assignment.address)
        assert normalized is not None

        self.assertEqual(azure_facts(normalized).role_assignment_scope, _SERVICE_BUS_QUEUE_ID)
        self.assertNotEqual(azure_facts(normalized).role_assignment_scope, _SERVICE_BUS_NAMESPACE_ID)

    def test_role_assignment_to_cosmos_container_uses_container_id(self) -> None:
        container = NormalizedResource(
            address="azurerm_cosmosdb_sql_container.events",
            provider="azure",
            resource_type=AzureResourceType.COSMOSDB_SQL_CONTAINER,
            name="events",
            category=ResourceCategory.DATA,
            identifier=_COSMOS_CONTAINER_ID,
            metadata={
                AzureResourceMetadata.COSMOSDB_ACCOUNT_ID: _COSMOS_ACCOUNT_ID,
                AzureResourceMetadata.COSMOSDB_SQL_DATABASE_ID: _COSMOS_DATABASE_ID,
                AzureResourceMetadata.COSMOSDB_SQL_CONTAINER_ID: _COSMOS_CONTAINER_ID,
            },
        )
        assignment = NormalizedResource(
            address="azurerm_role_assignment.container_reader",
            provider="azure",
            resource_type=AzureResourceType.ROLE_ASSIGNMENT,
            name="container_reader",
            category=ResourceCategory.IAM,
            identifier="azurerm_role_assignment.container_reader",
            reference_resolutions=(_symbolic_resolution(("scope",), container.address, ".id"),),
        )
        AzureResourceDecorator(stages=(ResolveAzureSymbolicRelationshipsStage(),)).decorate([assignment, container])

        self.assertEqual(azure_facts(assignment).role_assignment_scope, _COSMOS_CONTAINER_ID)
        self.assertNotEqual(azure_facts(assignment).role_assignment_scope, _COSMOS_ACCOUNT_ID)

    def test_cosmos_container_rejects_database_from_different_account(self) -> None:
        account = _terraform_resource(
            "azurerm_cosmosdb_account.orders",
            AzureResourceType.COSMOSDB_ACCOUNT,
            {
                "id": _COSMOS_ACCOUNT_ID,
                "name": "orders",
                "resource_group_name": _RESOURCE_GROUP,
                "public_network_access_enabled": False,
            },
        )
        other_account = _terraform_resource(
            "azurerm_cosmosdb_account.audit",
            AzureResourceType.COSMOSDB_ACCOUNT,
            {
                "id": _COSMOS_OTHER_ACCOUNT_ID,
                "name": "audit",
                "resource_group_name": _RESOURCE_GROUP,
                "public_network_access_enabled": False,
            },
        )
        database = _terraform_resource(
            "azurerm_cosmosdb_sql_database.audit",
            AzureResourceType.COSMOSDB_SQL_DATABASE,
            {"name": "app"},
            unknown_values={"account_name": True, "resource_group_name": True},
            reference_resolutions=(_symbolic_resolution(("account_name",), other_account.address, ".name"),),
        )
        container = _terraform_resource(
            "azurerm_cosmosdb_sql_container.events",
            AzureResourceType.COSMOSDB_SQL_CONTAINER,
            {"name": "events"},
            unknown_values={
                "account_name": True,
                "database_name": True,
                "resource_group_name": True,
            },
            reference_resolutions=(
                _symbolic_resolution(("account_name",), account.address, ".name"),
                _symbolic_resolution(("database_name",), database.address, ".name"),
            ),
        )

        inventory = AzureNormalizer().normalize([container, database, other_account, account])
        normalized = inventory.get_by_address(container.address)
        assert normalized is not None
        facts = azure_facts(normalized)

        self.assertEqual(facts.resolved_cosmosdb_account_address, account.address)
        self.assertIsNone(facts.resolved_cosmosdb_database_address)
        self.assertTrue(
            any(
                "does not share the container's exact Cosmos DB account" in uncertainty
                for uncertainty in facts.cosmosdb_sql_rbac_uncertainties
            )
        )

    def test_cosmos_assignment_rejects_role_definition_from_different_account(self) -> None:
        account = _terraform_resource(
            "azurerm_cosmosdb_account.orders",
            AzureResourceType.COSMOSDB_ACCOUNT,
            {
                "id": _COSMOS_ACCOUNT_ID,
                "name": "orders",
                "resource_group_name": _RESOURCE_GROUP,
                "public_network_access_enabled": False,
            },
        )
        other_account = _terraform_resource(
            "azurerm_cosmosdb_account.audit",
            AzureResourceType.COSMOSDB_ACCOUNT,
            {
                "id": _COSMOS_OTHER_ACCOUNT_ID,
                "name": "audit",
                "resource_group_name": _RESOURCE_GROUP,
                "public_network_access_enabled": False,
            },
        )
        role = _terraform_resource(
            "azurerm_cosmosdb_sql_role_definition.audit_writer",
            AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION,
            {
                "id": f"{_COSMOS_OTHER_ACCOUNT_ID}/sqlRoleDefinitions/{_COSMOS_ROLE_GUID}",
                "role_definition_id": _COSMOS_ROLE_GUID,
                "name": "audit-writer",
                "type": "CustomRole",
                "assignable_scopes": [_COSMOS_OTHER_ACCOUNT_ID],
                "permissions": [
                    {"data_actions": ["Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/create"]}
                ],
            },
            unknown_values={"account_name": True, "resource_group_name": True},
            reference_resolutions=(_symbolic_resolution(("account_name",), other_account.address, ".name"),),
        )
        assignment = _terraform_resource(
            "azurerm_cosmosdb_sql_role_assignment.writer",
            AzureResourceType.COSMOSDB_SQL_ROLE_ASSIGNMENT,
            {
                "name": "writer",
                "principal_id": _IDENTITY_PRINCIPAL_ID,
                "scope": _COSMOS_ACCOUNT_ID,
            },
            unknown_values={
                "account_name": True,
                "resource_group_name": True,
                "role_definition_id": True,
            },
            reference_resolutions=(
                _symbolic_resolution(("account_name",), account.address, ".name"),
                _symbolic_resolution(("role_definition_id",), role.address, ".id"),
            ),
        )

        inventory = AzureNormalizer().normalize([assignment, role, other_account, account])
        normalized = inventory.get_by_address(assignment.address)
        assert normalized is not None
        facts = azure_facts(normalized)

        self.assertEqual(facts.resolved_cosmosdb_account_address, account.address)
        self.assertIsNone(facts.resolved_cosmosdb_sql_role_definition_address)
        self.assertEqual(facts.cosmosdb_sql_role_data_actions, [])
        self.assertTrue(
            any(
                "does not share the assignment's exact Cosmos DB account" in uncertainty
                for uncertainty in facts.cosmosdb_sql_rbac_uncertainties
            )
        )

    def test_cosmos_scope_cannot_override_a_different_symbolic_parent(self) -> None:
        account = _terraform_resource(
            "azurerm_cosmosdb_account.orders",
            AzureResourceType.COSMOSDB_ACCOUNT,
            {
                "id": _COSMOS_ACCOUNT_ID,
                "name": "orders",
                "resource_group_name": _RESOURCE_GROUP,
                "public_network_access_enabled": False,
            },
        )
        other_account = _terraform_resource(
            "azurerm_cosmosdb_account.audit",
            AzureResourceType.COSMOSDB_ACCOUNT,
            {
                "id": _COSMOS_OTHER_ACCOUNT_ID,
                "name": "audit",
                "resource_group_name": _RESOURCE_GROUP,
                "public_network_access_enabled": False,
            },
        )
        assignment = _terraform_resource(
            "azurerm_cosmosdb_sql_role_assignment.conflicting",
            AzureResourceType.COSMOSDB_SQL_ROLE_ASSIGNMENT,
            {
                "name": "conflicting",
                "principal_id": _IDENTITY_PRINCIPAL_ID,
                "role_definition_id": (f"{_COSMOS_ACCOUNT_ID}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"),
            },
            unknown_values={
                "account_name": True,
                "resource_group_name": True,
                "scope": True,
            },
            reference_resolutions=(
                _symbolic_resolution(("account_name",), account.address, ".name"),
                _symbolic_resolution(("scope",), other_account.address, ".id"),
            ),
        )

        inventory = AzureNormalizer().normalize([account, other_account, assignment])
        normalized = inventory.get_by_address(assignment.address)
        assert normalized is not None
        facts = azure_facts(normalized)

        self.assertEqual(facts.resolved_cosmosdb_account_address, account.address)
        self.assertIsNone(facts.cosmosdb_sql_role_assignment_scope)
        self.assertEqual(facts.cosmosdb_sql_role_assignment_scope_state, "unknown")
        self.assertEqual(facts.cosmosdb_sql_role_data_actions, [])
        self.assertTrue(
            any(
                "conflicts with the assignment's parent Cosmos DB account" in uncertainty
                for uncertainty in facts.cosmosdb_sql_rbac_uncertainties
            )
        )

    def test_wrong_target_attributes_do_not_establish_relationships(self) -> None:
        identity = _identity()
        vault = _terraform_resource(
            "azurerm_key_vault.application",
            AzureResourceType.KEY_VAULT,
            {"id": _VAULT_ID, "name": "application"},
        )
        workload = _terraform_resource(
            "azurerm_linux_web_app.api",
            AzureResourceType.LINUX_WEB_APP,
            {"name": "api", "identity": [{"type": "UserAssigned", "identity_ids": None}]},
            unknown_values={"identity": [{"identity_ids": True}]},
            reference_resolutions=(
                _symbolic_resolution(
                    ("identity", 0, "identity_ids"),
                    identity.address,
                    ".principal_id",
                ),
            ),
        )
        key = _terraform_resource(
            "azurerm_key_vault_key.signing",
            AzureResourceType.KEY_VAULT_KEY,
            {"name": "signing", "key_type": "RSA", "key_opts": ["sign"]},
            unknown_values={"key_vault_id": True},
            reference_resolutions=(_symbolic_resolution(("key_vault_id",), vault.address, ".name"),),
        )

        inventory = AzureNormalizer().normalize([identity, vault, workload, key])
        normalized_workload = inventory.get_by_address(workload.address)
        normalized_key = inventory.get_by_address(key.address)
        assert normalized_workload is not None
        assert normalized_key is not None

        self.assertEqual(azure_facts(normalized_workload).resolved_attached_identity_addresses, [])
        self.assertIsNone(azure_facts(normalized_key).resolved_key_vault_address)
        self.assertIsNone(azure_facts(normalized_key).key_vault_reference)


if __name__ == "__main__":
    unittest.main()

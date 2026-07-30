from __future__ import annotations

from collections.abc import Callable, Collection
from dataclasses import dataclass

from tfstride.models import (
    NormalizedResource,
    TerraformReferenceProvenance,
    TerraformReferenceResolutionState,
)
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AZURE_COMPUTE_RESOURCE_TYPES,
    AzureResourceType,
)

_WORKLOAD_IDENTITY_PATH = ("identity", 0, "identity_ids")
_COSMOS_ACCOUNT_CHILD_TYPES = frozenset(
    {
        AzureResourceType.COSMOSDB_SQL_DATABASE,
        AzureResourceType.COSMOSDB_SQL_CONTAINER,
        AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION,
        AzureResourceType.COSMOSDB_SQL_ROLE_ASSIGNMENT,
    }
)
_PRINCIPAL_TARGET_TYPES = frozenset(
    {
        AzureResourceType.USER_ASSIGNED_IDENTITY,
        *AZURE_APP_SERVICE_RESOURCE_TYPES,
        *AZURE_COMPUTE_RESOURCE_TYPES,
    }
)


@dataclass(frozen=True, slots=True)
class _SymbolicTarget:
    resource: NormalizedResource
    reference: str


class ResolveAzureSymbolicRelationshipsStage:
    """Adopt exact, field-specific Azure relationships from symbolic plan evidence."""

    name = "resolve_azure_symbolic_relationships"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        # Resolve account ancestry for every Cosmos child before relationships
        # that must prove both resources belong to the same account.
        for resource in resources:
            if resource.resource_type in AZURE_APP_SERVICE_RESOURCE_TYPES:
                self._resolve_workload_identity(resource, context)
            elif resource.resource_type == AzureResourceType.ROLE_ASSIGNMENT:
                self._resolve_role_assignment(resource, context)
            elif resource.resource_type == AzureResourceType.KEY_VAULT_KEY:
                self._resolve_key_vault_key_parent(resource, context)
            elif resource.resource_type in {
                AzureResourceType.SERVICE_BUS_QUEUE,
                AzureResourceType.SERVICE_BUS_TOPIC,
                AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
            }:
                self._resolve_service_bus_parent(resource, context)

            if resource.resource_type in _COSMOS_ACCOUNT_CHILD_TYPES:
                self._resolve_cosmos_account_parent(resource, context)

        for resource in resources:
            if resource.resource_type == AzureResourceType.COSMOSDB_SQL_CONTAINER:
                self._resolve_cosmos_database_parent(resource, context)

        for resource in resources:
            if resource.resource_type == AzureResourceType.COSMOSDB_SQL_ROLE_ASSIGNMENT:
                self._resolve_cosmos_assignment(resource, context)

    def _resolve_workload_identity(
        self,
        workload: NormalizedResource,
        context: AzureDecorationContext,
    ) -> None:
        facts = azure_facts(workload)
        if facts.attached_identity_references or facts.resolved_attached_identity_addresses:
            return
        match = _symbolic_target(
            workload,
            context,
            allowed_paths={_WORKLOAD_IDENTITY_PATH},
            expected_resource_types={AzureResourceType.USER_ASSIGNED_IDENTITY},
            expected_reference_suffixes=(".id",),
        )
        if match is None:
            return
        facts.add_resolved_attached_identity_address(match.resource.address)
        identity_id = _canonical_arm_id(match.resource)
        if identity_id is not None:
            facts.set(AzureResourceMetadata.ATTACHED_IDENTITY_REFERENCES, [identity_id])

    def _resolve_role_assignment(
        self,
        assignment: NormalizedResource,
        context: AzureDecorationContext,
    ) -> None:
        facts = azure_facts(assignment)
        if not facts.principal_id and not facts.resolved_managed_identity_address:
            principal = _symbolic_target(
                assignment,
                context,
                allowed_paths={("principal_id",)},
                expected_resource_types=_PRINCIPAL_TARGET_TYPES,
                expected_reference_suffixes=(".principal_id",),
            )
            if principal is not None:
                facts.set_resolved_managed_identity_address(principal.resource.address)
                principal_id = azure_facts(principal.resource).principal_id
                if principal_id is not None:
                    facts.set(AzureResourceMetadata.PRINCIPAL_ID, principal_id)

        if not facts.role_definition_id and not facts.resolved_role_definition_address:
            role_definition = _symbolic_target(
                assignment,
                context,
                allowed_paths={("role_definition_id",)},
                expected_resource_types={AzureResourceType.ROLE_DEFINITION},
                expected_reference_suffixes=(".id", ".role_definition_resource_id"),
            )
            if role_definition is not None:
                facts.set_resolved_role_definition_address(role_definition.resource.address)
                role_definition_id = _canonical_role_definition_id(role_definition.resource)
                if role_definition_id is not None:
                    facts.set(AzureResourceMetadata.ROLE_DEFINITION_ID, role_definition_id)

        if facts.role_assignment_scope or facts.role_assignment_target_resource_address:
            return
        scope_target = _symbolic_target(
            assignment,
            context,
            allowed_paths={("scope",)},
            expected_reference_suffixes=(".id", ".resource_versionless_id"),
            reference_validator=_valid_role_assignment_scope_reference,
        )
        if scope_target is None:
            return
        facts.set(AzureResourceMetadata.ROLE_ASSIGNMENT_TARGET_RESOURCE_ADDRESS, scope_target.resource.address)
        facts.set(AzureResourceMetadata.ROLE_ASSIGNMENT_TARGET_RESOURCE_TYPE, scope_target.resource.resource_type)
        scope = _canonical_role_assignment_scope(scope_target.resource)
        if scope is not None:
            facts.set(AzureResourceMetadata.ROLE_ASSIGNMENT_SCOPE, scope)

    def _resolve_key_vault_key_parent(
        self,
        key: NormalizedResource,
        context: AzureDecorationContext,
    ) -> None:
        facts = azure_facts(key)
        if facts.key_vault_reference or facts.resolved_key_vault_address:
            return
        vault = _symbolic_target(
            key,
            context,
            allowed_paths={("key_vault_id",)},
            expected_resource_types={AzureResourceType.KEY_VAULT},
            expected_reference_suffixes=(".id",),
        )
        if vault is None:
            return
        facts.set_resolved_key_vault_address(vault.resource.address)
        vault_id = azure_facts(vault.resource).key_vault_id
        if _is_arm_id(vault_id):
            facts.set(AzureResourceMetadata.KEY_VAULT_REFERENCE, vault_id)

    def _resolve_service_bus_parent(
        self,
        entity: NormalizedResource,
        context: AzureDecorationContext,
    ) -> None:
        facts = azure_facts(entity)
        if entity.resource_type == AzureResourceType.SERVICE_BUS_SUBSCRIPTION:
            if facts.service_bus_topic_reference or facts.resolved_service_bus_topic_address:
                return
            topic = _symbolic_target(
                entity,
                context,
                allowed_paths={("topic_id",)},
                expected_resource_types={AzureResourceType.SERVICE_BUS_TOPIC},
                expected_reference_suffixes=(".id",),
            )
            if topic is None:
                return
            facts.set_resolved_service_bus_topic_address(topic.resource.address)
            topic_id = azure_facts(topic.resource).service_bus_entity_id
            if _is_arm_id(topic_id):
                facts.set(AzureResourceMetadata.SERVICE_BUS_TOPIC_REFERENCE, topic_id)
            return

        if facts.service_bus_entity_namespace_reference or facts.resolved_service_bus_namespace_address:
            return
        namespace = _symbolic_target(
            entity,
            context,
            allowed_paths={("namespace_id",)},
            expected_resource_types={AzureResourceType.SERVICE_BUS_NAMESPACE},
            expected_reference_suffixes=(".id",),
        )
        if namespace is None:
            return
        facts.set_resolved_service_bus_namespace_address(namespace.resource.address)
        namespace_id = azure_facts(namespace.resource).service_bus_namespace_id
        if _is_arm_id(namespace_id):
            facts.set(AzureResourceMetadata.SERVICE_BUS_NAMESPACE_REFERENCE, namespace_id)

    def _resolve_cosmos_account_parent(
        self,
        resource: NormalizedResource,
        context: AzureDecorationContext,
    ) -> None:
        facts = azure_facts(resource)
        if facts.resolved_cosmosdb_account_address:
            return
        account = _symbolic_target(
            resource,
            context,
            allowed_paths={("account_name",)},
            expected_resource_types={AzureResourceType.COSMOSDB_ACCOUNT},
            expected_reference_suffixes=(".name",),
        )
        if account is None:
            return
        account_facts = azure_facts(account.resource)
        if _cosmos_account_identity_conflicts(resource, account.resource):
            facts.extend_cosmosdb_sql_rbac_uncertainties(
                [
                    f"{resource.address}: account_name resolves to {account.resource.address}, "
                    "which conflicts with the represented Cosmos DB account identity"
                ]
            )
            return
        facts.set_resolved_cosmosdb_account_address(account.resource.address)
        if facts.cosmosdb_account_name is None and account_facts.cosmosdb_account_name is not None:
            facts.set(AzureResourceMetadata.COSMOSDB_ACCOUNT_NAME, account_facts.cosmosdb_account_name)
        if facts.cosmosdb_resource_group_name is None and account_facts.cosmosdb_resource_group_name is not None:
            facts.set(
                AzureResourceMetadata.COSMOSDB_RESOURCE_GROUP_NAME,
                account_facts.cosmosdb_resource_group_name,
            )

    def _resolve_cosmos_database_parent(
        self,
        container: NormalizedResource,
        context: AzureDecorationContext,
    ) -> None:
        facts = azure_facts(container)
        if facts.resolved_cosmosdb_database_address:
            return
        database = _symbolic_target(
            container,
            context,
            allowed_paths={("database_name",)},
            expected_resource_types={AzureResourceType.COSMOSDB_SQL_DATABASE},
            expected_reference_suffixes=(".name",),
        )
        if database is None:
            return
        database_name = azure_facts(database.resource).cosmosdb_sql_database_name
        if (
            facts.cosmosdb_sql_database_name is not None
            and database_name is not None
            and facts.cosmosdb_sql_database_name != database_name
        ):
            facts.extend_cosmosdb_sql_rbac_uncertainties(
                [
                    f"{container.address}: database_name resolves to {database.resource.address}, "
                    "which conflicts with the represented Cosmos DB for NoSQL database name"
                ]
            )
            return
        if not _same_resolved_cosmos_account(container, database.resource):
            facts.extend_cosmosdb_sql_rbac_uncertainties(
                [
                    f"{container.address}: database_name resolves to {database.resource.address}, "
                    "which does not share the container's exact Cosmos DB account"
                ]
            )
            return
        facts.set_resolved_cosmosdb_database_address(database.resource.address)
        if facts.cosmosdb_sql_database_name is None and database_name is not None:
            facts.set(AzureResourceMetadata.COSMOSDB_SQL_DATABASE_NAME, database_name)

    def _resolve_cosmos_assignment(
        self,
        assignment: NormalizedResource,
        context: AzureDecorationContext,
    ) -> None:
        facts = azure_facts(assignment)
        if not facts.cosmosdb_sql_principal_id and not facts.resolved_managed_identity_address:
            principal = _symbolic_target(
                assignment,
                context,
                allowed_paths={("principal_id",)},
                expected_resource_types=_PRINCIPAL_TARGET_TYPES,
                expected_reference_suffixes=(".principal_id",),
            )
            if principal is not None:
                facts.set_resolved_managed_identity_address(principal.resource.address)
                principal_id = azure_facts(principal.resource).principal_id
                if principal_id is not None:
                    facts.set(AzureResourceMetadata.COSMOSDB_SQL_PRINCIPAL_ID, principal_id)

        if not facts.cosmosdb_sql_role_definition_reference and not facts.resolved_cosmosdb_sql_role_definition_address:
            role_definition = _symbolic_target(
                assignment,
                context,
                allowed_paths={("role_definition_id",)},
                expected_resource_types={AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION},
                expected_reference_suffixes=(".id",),
            )
            if role_definition is not None and not _same_resolved_cosmos_account(
                assignment,
                role_definition.resource,
            ):
                facts.extend_cosmosdb_sql_rbac_uncertainties(
                    [
                        f"{assignment.address}: role_definition_id resolves to "
                        f"{role_definition.resource.address}, which does not share the "
                        "assignment's exact Cosmos DB account"
                    ]
                )
                role_definition = None
            if role_definition is not None:
                facts.set(
                    AzureResourceMetadata.RESOLVED_COSMOSDB_SQL_ROLE_DEFINITION_ADDRESS,
                    role_definition.resource.address,
                )
                role_definition_id = azure_facts(role_definition.resource).cosmosdb_sql_role_definition_resource_id
                if _is_arm_id(role_definition_id):
                    facts.set(
                        AzureResourceMetadata.COSMOSDB_SQL_ROLE_DEFINITION_REFERENCE,
                        role_definition_id,
                    )

        if facts.cosmosdb_sql_role_assignment_scope:
            return
        scope = _symbolic_target(
            assignment,
            context,
            allowed_paths={("scope",)},
            expected_resource_types={AzureResourceType.COSMOSDB_ACCOUNT},
            expected_reference_suffixes=(".id",),
        )
        if scope is None:
            return
        if (
            facts.resolved_cosmosdb_account_address
            and facts.resolved_cosmosdb_account_address != scope.resource.address
        ) or _cosmos_account_identity_conflicts(assignment, scope.resource):
            facts.extend_cosmosdb_sql_rbac_uncertainties(
                [
                    f"{assignment.address}: native RBAC scope resolves to {scope.resource.address}, "
                    "which conflicts with the assignment's parent Cosmos DB account"
                ]
            )
            return
        facts.set_resolved_cosmosdb_account_address(scope.resource.address)
        account_id = azure_facts(scope.resource).cosmosdb_account_id
        if _is_arm_id(account_id):
            facts.set(AzureResourceMetadata.COSMOSDB_SQL_ROLE_ASSIGNMENT_SCOPE, account_id)


def _cosmos_account_identity_conflicts(
    resource: NormalizedResource,
    account: NormalizedResource,
) -> bool:
    facts = azure_facts(resource)
    account_facts = azure_facts(account)
    represented_name = facts.cosmosdb_account_name
    target_name = account_facts.cosmosdb_account_name
    if (
        represented_name is not None
        and target_name is not None
        and represented_name.casefold() != target_name.casefold()
    ):
        return True
    represented_group = facts.cosmosdb_resource_group_name
    target_group = account_facts.cosmosdb_resource_group_name
    return bool(
        represented_group is not None
        and target_group is not None
        and represented_group.casefold() != target_group.casefold()
    )


def _same_resolved_cosmos_account(
    left: NormalizedResource,
    right: NormalizedResource,
) -> bool:
    left_account = azure_facts(left).resolved_cosmosdb_account_address
    right_account = azure_facts(right).resolved_cosmosdb_account_address
    return bool(left_account and right_account and left_account == right_account)


def _symbolic_target(
    resource: NormalizedResource,
    context: AzureDecorationContext,
    *,
    allowed_paths: Collection[tuple[str | int, ...]],
    expected_reference_suffixes: Collection[str],
    expected_resource_types: Collection[str] | None = None,
    reference_validator: Callable[[NormalizedResource, str], bool] | None = None,
) -> _SymbolicTarget | None:
    matches: dict[str, _SymbolicTarget] = {}
    expected_types = set(expected_resource_types) if expected_resource_types is not None else None
    suffixes = tuple(suffix.casefold() for suffix in expected_reference_suffixes)
    for resolution in resource.reference_resolutions:
        if resolution.state != TerraformReferenceResolutionState.SYMBOLIC:
            continue
        if resolution.provenance != TerraformReferenceProvenance.CONFIGURATION_REFERENCE:
            continue
        if resolution.path not in allowed_paths or len(resolution.targets) != 1:
            continue
        target = resolution.targets[0]
        reference = target.reference.casefold()
        if not any(reference.endswith(suffix) for suffix in suffixes):
            continue
        candidate = context.index.resources_by_address.get(target.address)
        if candidate is None:
            continue
        if expected_types is not None and candidate.resource_type not in expected_types:
            continue
        if reference_validator is not None and not reference_validator(candidate, target.reference):
            continue
        matches[candidate.address] = _SymbolicTarget(candidate, target.reference)
    return next(iter(matches.values())) if len(matches) == 1 else None


def _valid_role_assignment_scope_reference(
    target: NormalizedResource,
    reference: str,
) -> bool:
    normalized = reference.casefold()
    if target.resource_type == AzureResourceType.KEY_VAULT_KEY:
        return normalized.endswith(".resource_versionless_id")
    return normalized.endswith(".id")


def _canonical_role_assignment_scope(target: NormalizedResource) -> str | None:
    if target.resource_type == AzureResourceType.KEY_VAULT_KEY:
        value = azure_facts(target).key_vault_key_versionless_resource_id
        return value if _is_arm_id(value) else None
    return _canonical_arm_id(target)


def _canonical_role_definition_id(role_definition: NormalizedResource) -> str | None:
    value = azure_facts(role_definition).role_definition_id
    if _is_arm_id(value):
        return value
    return _canonical_arm_id(role_definition)


def _canonical_arm_id(resource: NormalizedResource) -> str | None:
    facts = azure_facts(resource)
    if resource.resource_type in AZURE_APP_SERVICE_RESOURCE_TYPES:
        value = facts.app_service_id
    elif resource.resource_type == AzureResourceType.STORAGE_ACCOUNT:
        value = facts.storage_account_id
    elif resource.resource_type == AzureResourceType.KEY_VAULT:
        value = facts.key_vault_id
    elif resource.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        value = facts.service_bus_namespace_id
    elif resource.resource_type in {
        AzureResourceType.SERVICE_BUS_QUEUE,
        AzureResourceType.SERVICE_BUS_TOPIC,
        AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
    }:
        value = facts.service_bus_entity_id
    elif resource.resource_type == AzureResourceType.COSMOSDB_ACCOUNT:
        value = facts.cosmosdb_account_id
    elif resource.resource_type == AzureResourceType.COSMOSDB_SQL_DATABASE:
        value = facts.cosmosdb_sql_database_id
    elif resource.resource_type == AzureResourceType.COSMOSDB_SQL_CONTAINER:
        value = facts.cosmosdb_sql_container_id
    elif resource.resource_type == AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION:
        value = facts.cosmosdb_sql_role_definition_resource_id
    else:
        value = resource.identifier

    if _is_arm_id(value):
        return value
    return resource.identifier if _is_arm_id(resource.identifier) else None


def _is_arm_id(value: object) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip().casefold()
    return normalized.startswith("/subscriptions/") or normalized.startswith("/providers/")

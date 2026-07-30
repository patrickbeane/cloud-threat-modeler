from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.azure.cosmosdb_nosql_index import (
    AzureCosmosDbNoSqlIndex,
    AzureCosmosDbNoSqlIndexBuilder,
    CosmosDbNoSqlScopeResolution,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AzureResourceType

_READER_ROLE_ID = "00000000-0000-0000-0000-000000000001"
_CONTRIBUTOR_ROLE_ID = "00000000-0000-0000-0000-000000000002"
_READER_ACTIONS = (
    "Microsoft.DocumentDB/databaseAccounts/readMetadata",
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/read",
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/executeQuery",
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/readChangeFeed",
)
_CONTRIBUTOR_ACTIONS = (
    "Microsoft.DocumentDB/databaseAccounts/readMetadata",
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/*",
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/*",
)
_BUILT_IN_ROLES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    _READER_ROLE_ID: (
        "built_in_data_reader",
        "Cosmos DB Built-in Data Reader",
        _READER_ACTIONS,
    ),
    _CONTRIBUTOR_ROLE_ID: (
        "built_in_data_contributor",
        "Cosmos DB Built-in Data Contributor",
        _CONTRIBUTOR_ACTIONS,
    ),
}
_DETERMINISTIC_SCOPE_STATES = frozenset({"resolved", "external_or_unmodeled"})
_SCOPE_COMPATIBILITY_RESOLVED = "resolved"
_SCOPE_COMPATIBILITY_OUTSIDE = "outside_assignable_scope"
_SCOPE_COMPATIBILITY_UNKNOWN = "unknown"
_ENTITY_TYPES = frozenset(
    {
        AzureResourceType.COSMOSDB_SQL_DATABASE,
        AzureResourceType.COSMOSDB_SQL_CONTAINER,
    }
)


class DecorateCosmosDbNoSqlRelationshipsStage:
    name = "decorate_cosmosdb_nosql_relationships"

    def __init__(self, index_builder: AzureCosmosDbNoSqlIndexBuilder | None = None) -> None:
        self._index_builder = index_builder or AzureCosmosDbNoSqlIndexBuilder()

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        del context
        index = self._index_builder.build(resources)
        for resource in resources:
            if resource.resource_type in _ENTITY_TYPES:
                self._decorate_entity(resource, index)
        for resource in resources:
            if resource.resource_type == AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION:
                self._decorate_role_definition(resource, index)
        for resource in resources:
            if resource.resource_type == AzureResourceType.COSMOSDB_SQL_ROLE_ASSIGNMENT:
                self._decorate_role_assignment(resource, index)

    def _decorate_entity(
        self,
        resource: NormalizedResource,
        index: AzureCosmosDbNoSqlIndex,
    ) -> None:
        facts = azure_facts(resource)
        account = index.account_for(resource)
        if account is None:
            facts.extend_cosmosdb_sql_rbac_uncertainties(
                [f"{resource.address}: parent Azure Cosmos DB for NoSQL account is unresolved"]
            )
            return
        facts.set_resolved_cosmosdb_account_address(account.address)

        if resource.resource_type != AzureResourceType.COSMOSDB_SQL_CONTAINER:
            return
        database = index.database_for(resource)
        if database is None:
            facts.extend_cosmosdb_sql_rbac_uncertainties(
                [f"{resource.address}: parent Azure Cosmos DB for NoSQL database is unresolved"]
            )
            return
        facts.set_resolved_cosmosdb_database_address(database.address)

    def _decorate_role_definition(
        self,
        role_definition: NormalizedResource,
        index: AzureCosmosDbNoSqlIndex,
    ) -> None:
        facts = azure_facts(role_definition)
        account = index.account_for(role_definition)
        if account is None:
            facts.extend_cosmosdb_sql_rbac_uncertainties(
                [f"{role_definition.address}: parent Azure Cosmos DB for NoSQL account is unresolved"]
            )
            return
        facts.set_resolved_cosmosdb_account_address(account.address)
        self._materialize_role_definition_id(role_definition, account)

        role_kind = _role_definition_kind(role_definition)
        if role_kind is not None:
            facts.set_cosmosdb_sql_role_kind(role_kind)

        records: list[dict[str, Any]] = []
        uncertainties: list[str] = []
        for scope in facts.cosmosdb_sql_role_definition_assignable_scopes:
            resolution = index.resolve_assignable_scope(scope, account)
            records.append(_scope_record(scope, resolution))
            if resolution.resolution_state in {"unknown", "foreign_account"}:
                uncertainties.append(
                    f"{role_definition.address}: assignable scope {scope} is not a valid exact scope under "
                    f"{account.address}"
                )
        facts.set_cosmosdb_sql_assignable_scope_records(records)
        facts.extend_cosmosdb_sql_rbac_uncertainties(uncertainties)

    def _decorate_role_assignment(
        self,
        assignment: NormalizedResource,
        index: AzureCosmosDbNoSqlIndex,
    ) -> None:
        facts = azure_facts(assignment)
        account = index.account_for(assignment)
        if account is None:
            facts.extend_cosmosdb_sql_rbac_uncertainties(
                [f"{assignment.address}: parent Azure Cosmos DB for NoSQL account is unresolved"]
            )
            return

        scope_resolution = index.resolve_assignment_scope(
            facts.cosmosdb_sql_role_assignment_scope,
            account,
        )
        facts.set_cosmosdb_sql_assignable_scope_compatibility_state(_SCOPE_COMPATIBILITY_UNKNOWN)
        facts.set_cosmosdb_sql_scope_resolution(
            scope_kind=scope_resolution.scope_kind,
            scope_state=scope_resolution.resolution_state,
            account_address=account.address,
            database_address=scope_resolution.database_address,
            container_address=scope_resolution.container_address,
        )
        if scope_resolution.resolution_state != "resolved":
            facts.extend_cosmosdb_sql_rbac_uncertainties(
                [
                    f"{assignment.address}: data-plane scope "
                    f"{facts.cosmosdb_sql_role_assignment_scope or 'unknown'} "
                    f"is {scope_resolution.resolution_state.replace('_', ' ')}"
                ]
            )

        self._decorate_assignment_role(assignment, account, scope_resolution, index)

    def _decorate_assignment_role(
        self,
        assignment: NormalizedResource,
        account: NormalizedResource,
        scope_resolution: CosmosDbNoSqlScopeResolution,
        index: AzureCosmosDbNoSqlIndex,
    ) -> None:
        facts = azure_facts(assignment)
        reference = facts.cosmosdb_sql_role_definition_reference
        role_id = _last_resource_segment(reference)
        built_in = _BUILT_IN_ROLES.get(role_id or "")
        if built_in is not None:
            if not index.role_reference_matches_account(reference, account):
                facts.extend_cosmosdb_sql_rbac_uncertainties(
                    [f"{assignment.address}: built-in role definition reference is not scoped to {account.address}"]
                )
                return
            role_kind, role_name, data_actions = built_in
            facts.set_cosmosdb_sql_role_resolution(
                role_kind=role_kind,
                role_name=role_name,
                data_actions=[],
            )
            if scope_resolution.resolution_state not in _DETERMINISTIC_SCOPE_STATES:
                facts.extend_cosmosdb_sql_rbac_uncertainties(
                    [
                        f"{assignment.address}: assignment scope is unresolved, so built-in "
                        "role DataActions are not materialized"
                    ]
                )
                return
            facts.set_cosmosdb_sql_assignable_scope_compatibility_state(_SCOPE_COMPATIBILITY_RESOLVED)
            facts.set_cosmosdb_sql_role_data_actions(list(data_actions))
            return

        role_definition = index.resources_by_address.get(facts.resolved_cosmosdb_sql_role_definition_address or "")
        if (
            role_definition is None
            or role_definition.resource_type != AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION
            or index.account_address_by_resource.get(role_definition.address) != account.address
        ):
            role_definition = index.resolve_role_definition(reference, account)
        if role_definition is None:
            facts.extend_cosmosdb_sql_rbac_uncertainties(
                [f"{assignment.address}: custom native role definition {reference or 'unknown'} is unresolved"]
            )
            return
        role_facts = azure_facts(role_definition)
        role_kind = _role_definition_kind(role_definition)
        if role_kind != "custom":
            facts.extend_cosmosdb_sql_rbac_uncertainties(
                [
                    f"{assignment.address}: native role {role_definition.address} is not a "
                    "supported custom role definition"
                ]
            )
            return

        facts.set_cosmosdb_sql_role_resolution(
            role_kind="custom",
            role_name=(role_facts.cosmosdb_sql_role_definition_name or role_definition.address),
            data_actions=[],
            role_definition_address=role_definition.address,
        )
        if any("permissions" in value for value in role_facts.cosmosdb_sql_rbac_uncertainties):
            facts.extend_cosmosdb_sql_rbac_uncertainties(
                [f"{assignment.address}: custom native role {role_definition.address} permissions are unresolved"]
            )
            return

        compatibility = _assignable_scope_compatibility(
            role_definition,
            scope_resolution,
        )
        facts.set_cosmosdb_sql_assignable_scope_compatibility_state(compatibility)
        if compatibility == _SCOPE_COMPATIBILITY_RESOLVED:
            facts.set_cosmosdb_sql_role_data_actions(list(role_facts.cosmosdb_sql_role_definition_data_actions))
            return
        if compatibility == _SCOPE_COMPATIBILITY_OUTSIDE:
            facts.extend_cosmosdb_sql_rbac_uncertainties(
                [
                    f"{assignment.address}: assignment scope is outside the assignable "
                    f"scopes of {role_definition.address}"
                ]
            )
            return
        facts.extend_cosmosdb_sql_rbac_uncertainties(
            [f"{assignment.address}: assignable-scope compatibility with {role_definition.address} is unresolved"]
        )

    @staticmethod
    def _materialize_role_definition_id(
        role_definition: NormalizedResource,
        account: NormalizedResource,
    ) -> None:
        facts = azure_facts(role_definition)
        if facts.cosmosdb_sql_role_definition_resource_id:
            return
        account_id = azure_facts(account).cosmosdb_account_id
        role_guid = facts.cosmosdb_sql_role_definition_guid
        if account_id and role_guid:
            facts.set_cosmosdb_sql_role_definition_resource_id(
                f"{account_id.rstrip('/')}/sqlRoleDefinitions/{role_guid}"
            )


def _role_definition_kind(role_definition: NormalizedResource) -> str | None:
    facts = azure_facts(role_definition)
    role_id = facts.cosmosdb_sql_role_definition_guid
    built_in = _BUILT_IN_ROLES.get(role_id or "")
    if built_in is not None:
        return built_in[0]
    role_type = facts.cosmosdb_sql_role_definition_type
    if role_type is None:
        return None
    if role_type.casefold() == "customrole":
        return "custom"
    if role_type.casefold() == "builtinrole":
        return "built_in"
    return None


def _assignable_scope_compatibility(
    role_definition: NormalizedResource,
    assignment_scope: CosmosDbNoSqlScopeResolution,
) -> str:
    if assignment_scope.resolution_state not in _DETERMINISTIC_SCOPE_STATES:
        return _SCOPE_COMPATIBILITY_UNKNOWN

    records = azure_facts(role_definition).cosmosdb_sql_assignable_scope_records
    if not records:
        return _SCOPE_COMPATIBILITY_UNKNOWN

    has_unresolved_scope = False
    for record in records:
        resolution_state = _record_string(record, "resolution_state")
        if resolution_state not in _DETERMINISTIC_SCOPE_STATES:
            has_unresolved_scope = True
            continue
        if _assignable_scope_contains(record, assignment_scope):
            return _SCOPE_COMPATIBILITY_RESOLVED
    if has_unresolved_scope:
        return _SCOPE_COMPATIBILITY_UNKNOWN
    return _SCOPE_COMPATIBILITY_OUTSIDE


def _assignable_scope_contains(
    assignable_scope: dict[str, Any],
    assignment_scope: CosmosDbNoSqlScopeResolution,
) -> bool:
    if _record_string(assignable_scope, "account_address") != assignment_scope.account_address:
        return False

    assignable_kind = _record_string(assignable_scope, "scope_kind")
    if assignable_kind == "account":
        return True
    if assignable_kind == "database":
        return assignment_scope.scope_kind in {
            "database",
            "container",
        } and _same_data_plane_name(
            _record_string(assignable_scope, "database_name"),
            assignment_scope.database_name,
        )
    if assignable_kind == "container":
        return (
            assignment_scope.scope_kind == "container"
            and _same_data_plane_name(
                _record_string(assignable_scope, "database_name"),
                assignment_scope.database_name,
            )
            and _same_data_plane_name(
                _record_string(assignable_scope, "container_name"),
                assignment_scope.container_name,
            )
        )
    return False


def _record_string(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _same_data_plane_name(left: str | None, right: str | None) -> bool:
    return bool(left and right and left == right)


def _scope_record(
    raw_scope: str,
    resolution: CosmosDbNoSqlScopeResolution,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "scope": raw_scope,
        "scope_kind": resolution.scope_kind,
        "resolution_state": resolution.resolution_state,
        "canonical_scope": resolution.canonical_scope,
        "account_address": resolution.account_address,
    }
    if resolution.database_name:
        record["database_name"] = resolution.database_name
    if resolution.database_address:
        record["database_address"] = resolution.database_address
    if resolution.container_name:
        record["container_name"] = resolution.container_name
    if resolution.container_address:
        record["container_address"] = resolution.container_address
    return record


def _last_resource_segment(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip().rstrip("/").rsplit("/", 1)[-1].casefold() or None

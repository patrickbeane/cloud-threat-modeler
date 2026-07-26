from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TypeVar

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_COSMOS_ACCOUNT_ID_PATTERN = re.compile(
    r"^(?P<account>/subscriptions/[^/]+/resourcegroups/[^/]+/providers/"
    r"microsoft\.documentdb/databaseaccounts/[^/]+)(?P<tail>/.*)?$",
    re.IGNORECASE,
)
_ROLE_DEFINITION_SUFFIX = "/sqlroledefinitions/"
_Key = TypeVar("_Key")


@dataclass(frozen=True, slots=True)
class CosmosDbNoSqlScopeResolution:
    scope_kind: str | None
    resolution_state: str
    canonical_scope: str | None
    account_address: str | None
    database_address: str | None = None
    container_address: str | None = None
    database_name: str | None = None
    container_name: str | None = None

    @property
    def target_address(self) -> str | None:
        if self.scope_kind == "container":
            return self.container_address
        if self.scope_kind == "database":
            return self.database_address
        if self.scope_kind == "account":
            return self.account_address
        return None


@dataclass(frozen=True, slots=True)
class AzureCosmosDbNoSqlIndex:
    resources_by_address: Mapping[str, NormalizedResource]
    resources_by_exact_reference: Mapping[str, tuple[NormalizedResource, ...]]
    accounts_by_identity: Mapping[tuple[str, str], tuple[NormalizedResource, ...]]
    account_address_by_resource: Mapping[str, str]
    databases_by_identity: Mapping[tuple[str, str], tuple[NormalizedResource, ...]]
    database_address_by_container: Mapping[str, str]
    containers_by_identity: Mapping[tuple[str, str, str], tuple[NormalizedResource, ...]]
    role_definitions_by_reference: Mapping[str, tuple[NormalizedResource, ...]]

    def account_for(self, resource: NormalizedResource) -> NormalizedResource | None:
        if resource.resource_type == AzureResourceType.COSMOSDB_ACCOUNT:
            return resource
        return self.resources_by_address.get(self.account_address_by_resource.get(resource.address, ""))

    def database_for(self, container: NormalizedResource) -> NormalizedResource | None:
        return self.resources_by_address.get(self.database_address_by_container.get(container.address, ""))

    def resolve_role_definition(
        self,
        reference: str | None,
        account: NormalizedResource,
    ) -> NormalizedResource | None:
        candidates = self.role_definitions_by_reference.get(_reference_key(reference), ())
        matches = [
            candidate
            for candidate in candidates
            if self.account_address_by_resource.get(candidate.address) == account.address
        ]
        return matches[0] if len(matches) == 1 else None

    def role_reference_matches_account(
        self,
        reference: str | None,
        account: NormalizedResource,
    ) -> bool:
        value = _known_text(reference)
        if value is None:
            return False
        normalized = value.casefold()
        marker = normalized.rfind(_ROLE_DEFINITION_SUFFIX)
        if marker < 0:
            return False
        return _account_id_matches(account, value[:marker])

    def resolve_assignment_scope(
        self,
        scope: str | None,
        account: NormalizedResource,
    ) -> CosmosDbNoSqlScopeResolution:
        return self._resolve_scope(scope, account, allow_relative=True)

    def resolve_assignable_scope(
        self,
        scope: str | None,
        account: NormalizedResource,
    ) -> CosmosDbNoSqlScopeResolution:
        return self._resolve_scope(scope, account, allow_relative=False)

    def _resolve_scope(
        self,
        scope: str | None,
        account: NormalizedResource,
        *,
        allow_relative: bool,
    ) -> CosmosDbNoSqlScopeResolution:
        value = _known_text(scope)
        if value is None:
            return _unresolved_scope(None, "unknown", account)

        account_reference = self._exact_account_scope_reference(value)
        if account_reference is not None:
            if azure_facts(account).cosmosdb_account_id is None:
                return _unresolved_scope("account", "unknown", account)
            if account_reference.address != account.address:
                return _unresolved_scope("account", "foreign_account", account)
            return CosmosDbNoSqlScopeResolution(
                scope_kind="account",
                resolution_state="resolved",
                canonical_scope=_canonical_scope(account, None, None),
                account_address=account.address,
            )

        match = _COSMOS_ACCOUNT_ID_PATTERN.fullmatch(value.rstrip("/"))
        if match is not None:
            parsed_scope = _scope_path(match.group("tail") or "/")
            scope_kind = parsed_scope[0] if parsed_scope is not None else None
            account_match_state = _account_id_match_state(
                account,
                match.group("account"),
            )
            if account_match_state == "unknown":
                return _unresolved_scope(scope_kind, "unknown", account)
            if account_match_state == "mismatch":
                return _unresolved_scope(scope_kind, "foreign_account", account)
        elif value.casefold().startswith("/subscriptions/"):
            return _unresolved_scope(None, "unknown", account)
        elif allow_relative:
            parsed_scope = _scope_path(value)
        else:
            return _unresolved_scope(None, "unknown", account)

        if parsed_scope is None:
            return _unresolved_scope(None, "unknown", account)
        return self._resolution_for_scope_parts(account, *parsed_scope)

    def _exact_account_scope_reference(
        self,
        scope: str,
    ) -> NormalizedResource | None:
        if not _is_terraform_id_reference(scope):
            return None
        candidates = self.resources_by_exact_reference.get(_reference_key(scope), ())
        accounts = [
            candidate for candidate in candidates if candidate.resource_type == AzureResourceType.COSMOSDB_ACCOUNT
        ]
        return accounts[0] if len(accounts) == 1 else None

    def _resolution_for_scope_parts(
        self,
        account: NormalizedResource,
        scope_kind: str,
        database_name: str | None,
        container_name: str | None,
    ) -> CosmosDbNoSqlScopeResolution:
        canonical_scope = _canonical_scope(account, database_name, container_name)
        if scope_kind == "account":
            return CosmosDbNoSqlScopeResolution(
                scope_kind="account",
                resolution_state="resolved",
                canonical_scope=canonical_scope,
                account_address=account.address,
            )
        if database_name is None:
            return _unresolved_scope(
                scope_kind,
                "unknown",
                account,
                canonical_scope=canonical_scope,
            )

        database = _unique(
            self.databases_by_identity.get(
                (account.address, database_name),
                (),
            )
        )
        if scope_kind == "database":
            return CosmosDbNoSqlScopeResolution(
                scope_kind="database",
                resolution_state="resolved" if database else "external_or_unmodeled",
                canonical_scope=canonical_scope,
                account_address=account.address,
                database_address=database.address if database else None,
                database_name=database_name,
            )
        if container_name is None:
            return _unresolved_scope(
                scope_kind,
                "unknown",
                account,
                canonical_scope=canonical_scope,
            )

        container = _unique(
            self.containers_by_identity.get(
                (
                    account.address,
                    database_name,
                    container_name,
                ),
                (),
            )
        )
        return CosmosDbNoSqlScopeResolution(
            scope_kind="container",
            resolution_state="resolved" if container else "external_or_unmodeled",
            canonical_scope=canonical_scope,
            account_address=account.address,
            database_address=database.address if database else None,
            container_address=container.address if container else None,
            database_name=database_name,
            container_name=container_name,
        )


class AzureCosmosDbNoSqlIndexBuilder:
    def build(self, resources: Iterable[NormalizedResource]) -> AzureCosmosDbNoSqlIndex:
        resource_list = tuple(resources)
        resources_by_address = {resource.address: resource for resource in resource_list}
        exact_references = _references_index(resource_list)
        accounts_by_identity = _accounts_by_identity(resource_list)
        account_address_by_resource: dict[str, str] = {}

        for resource in resource_list:
            if resource.resource_type not in {
                AzureResourceType.COSMOSDB_SQL_DATABASE,
                AzureResourceType.COSMOSDB_SQL_CONTAINER,
                AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION,
                AzureResourceType.COSMOSDB_SQL_ROLE_ASSIGNMENT,
            }:
                continue
            account = _resolve_parent_account(resource, exact_references, accounts_by_identity)
            if account is not None:
                account_address_by_resource[resource.address] = account.address

        databases_by_identity: dict[tuple[str, str], list[NormalizedResource]] = {}
        for resource in resource_list:
            if resource.resource_type != AzureResourceType.COSMOSDB_SQL_DATABASE:
                continue
            account_address = account_address_by_resource.get(resource.address)
            database_name = azure_facts(resource).cosmosdb_sql_database_name
            if account_address and database_name:
                databases_by_identity.setdefault(
                    (account_address, database_name),
                    [],
                ).append(resource)

        database_address_by_container: dict[str, str] = {}
        containers_by_identity: dict[tuple[str, str, str], list[NormalizedResource]] = {}
        frozen_databases = _freeze_multi_map(databases_by_identity)
        for resource in resource_list:
            if resource.resource_type != AzureResourceType.COSMOSDB_SQL_CONTAINER:
                continue
            account_address = account_address_by_resource.get(resource.address)
            facts = azure_facts(resource)
            database_name = facts.cosmosdb_sql_database_name
            container_name = facts.cosmosdb_sql_container_name
            database = _resolve_parent_database(
                resource,
                account_address,
                account_address_by_resource,
                exact_references,
                frozen_databases,
            )
            if database is not None:
                database_address_by_container[resource.address] = database.address
            if account_address and database_name and container_name:
                key = (account_address, database_name, container_name)
                containers_by_identity.setdefault(key, []).append(resource)

        role_definitions_by_reference: dict[str, list[NormalizedResource]] = {}
        for resource in resource_list:
            if resource.resource_type != AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION:
                continue
            for reference in _exact_resource_references(resource):
                role_definitions_by_reference.setdefault(_reference_key(reference), []).append(resource)
            account = resources_by_address.get(account_address_by_resource.get(resource.address, ""))
            facts = azure_facts(resource)
            if account is not None and facts.cosmosdb_sql_role_definition_guid:
                account_id = azure_facts(account).cosmosdb_account_id
                if account_id:
                    canonical_id = (
                        f"{account_id.rstrip('/')}/sqlRoleDefinitions/{facts.cosmosdb_sql_role_definition_guid}"
                    )
                    role_definitions_by_reference.setdefault(_reference_key(canonical_id), []).append(resource)

        return AzureCosmosDbNoSqlIndex(
            resources_by_address=MappingProxyType(resources_by_address),
            resources_by_exact_reference=_freeze_multi_map(exact_references),
            accounts_by_identity=_freeze_multi_map(accounts_by_identity),
            account_address_by_resource=MappingProxyType(account_address_by_resource),
            databases_by_identity=frozen_databases,
            database_address_by_container=MappingProxyType(database_address_by_container),
            containers_by_identity=_freeze_multi_map(containers_by_identity),
            role_definitions_by_reference=_freeze_multi_map(role_definitions_by_reference),
        )


def _references_index(
    resources: Iterable[NormalizedResource],
) -> dict[str, list[NormalizedResource]]:
    index: dict[str, list[NormalizedResource]] = {}
    for resource in resources:
        for reference in _exact_resource_references(resource):
            index.setdefault(_reference_key(reference), []).append(resource)
    return index


def _exact_resource_references(resource: NormalizedResource) -> tuple[str, ...]:
    facts = azure_facts(resource)
    values: set[str | None] = {
        resource.address,
        f"{resource.address}.id",
        f"{resource.address}.resource_manager_id",
        resource.identifier,
        facts.cosmosdb_account_id,
        facts.cosmosdb_sql_database_id,
        facts.cosmosdb_sql_container_id,
        facts.cosmosdb_sql_role_definition_resource_id,
    }
    if resource.resource_type in {
        AzureResourceType.COSMOSDB_ACCOUNT,
        AzureResourceType.COSMOSDB_SQL_DATABASE,
        AzureResourceType.COSMOSDB_SQL_CONTAINER,
    }:
        values.add(f"{resource.address}.name")
    return tuple(sorted(value for value in values if value))


def _accounts_by_identity(
    resources: Iterable[NormalizedResource],
) -> dict[tuple[str, str], list[NormalizedResource]]:
    index: dict[tuple[str, str], list[NormalizedResource]] = {}
    for resource in resources:
        if resource.resource_type != AzureResourceType.COSMOSDB_ACCOUNT:
            continue
        facts = azure_facts(resource)
        if facts.cosmosdb_resource_group_name and facts.cosmosdb_account_name:
            key = (
                facts.cosmosdb_resource_group_name.casefold(),
                facts.cosmosdb_account_name.casefold(),
            )
            index.setdefault(key, []).append(resource)
    return index


def _resolve_parent_account(
    resource: NormalizedResource,
    exact_references: Mapping[str, list[NormalizedResource]],
    accounts_by_identity: Mapping[tuple[str, str], list[NormalizedResource]],
) -> NormalizedResource | None:
    facts = azure_facts(resource)
    account_reference = facts.cosmosdb_account_name
    reference_matches = [
        candidate
        for candidate in exact_references.get(_reference_key(account_reference), ())
        if candidate.resource_type == AzureResourceType.COSMOSDB_ACCOUNT
    ]
    account = _unique(reference_matches)
    if account is not None:
        return account
    if not facts.cosmosdb_resource_group_name or not account_reference:
        return None
    return _unique(
        accounts_by_identity.get(
            (
                facts.cosmosdb_resource_group_name.casefold(),
                account_reference.casefold(),
            ),
            (),
        )
    )


def _resolve_parent_database(
    container: NormalizedResource,
    account_address: str | None,
    account_address_by_resource: Mapping[str, str],
    exact_references: Mapping[str, list[NormalizedResource]],
    databases_by_identity: Mapping[tuple[str, str], tuple[NormalizedResource, ...]],
) -> NormalizedResource | None:
    database_reference = azure_facts(container).cosmosdb_sql_database_name
    reference_matches = [
        candidate
        for candidate in exact_references.get(_reference_key(database_reference), ())
        if candidate.resource_type == AzureResourceType.COSMOSDB_SQL_DATABASE
        and account_address is not None
        and account_address_by_resource.get(candidate.address) == account_address
    ]
    database = _unique(reference_matches)
    if database is not None:
        return database
    if account_address is None or database_reference is None:
        return None
    return _unique(
        databases_by_identity.get(
            (account_address, database_reference),
            (),
        )
    )


def _scope_path(
    scope: str,
) -> tuple[str, str | None, str | None] | None:
    value = scope.strip()
    if not value.startswith("/"):
        return None
    normalized = value.rstrip("/") or "/"
    segments = [segment for segment in normalized.split("/") if segment]
    if not segments:
        return "account", None, None
    if len(segments) == 2 and segments[0].casefold() == "dbs":
        return "database", segments[1], None
    if len(segments) == 4 and segments[0].casefold() == "dbs" and segments[2].casefold() == "colls":
        return "container", segments[1], segments[3]
    return None


def _account_id_matches(account: NormalizedResource, account_id: str) -> bool:
    return _account_id_match_state(account, account_id) == "match"


def _account_id_match_state(
    account: NormalizedResource,
    account_id: str,
) -> str:
    known_account_id = _known_text(azure_facts(account).cosmosdb_account_id)
    if known_account_id is None:
        return "unknown"
    if known_account_id.rstrip("/").casefold() == account_id.rstrip("/").casefold():
        return "match"
    return "mismatch"


def _is_terraform_id_reference(value: str) -> bool:
    text = value.strip()
    if text.startswith("${") and text.endswith("}"):
        text = text[2:-1].strip()
    normalized = text.casefold()
    return normalized.endswith((".id", ".resource_manager_id"))


def _canonical_scope(
    account: NormalizedResource,
    database_name: str | None,
    container_name: str | None,
) -> str:
    account_id = azure_facts(account).cosmosdb_account_id
    prefix = account_id.rstrip("/") if account_id else ""
    if database_name is None:
        return prefix or "/"
    suffix = f"/dbs/{database_name}"
    if container_name is not None:
        suffix += f"/colls/{container_name}"
    return f"{prefix}{suffix}" if prefix else suffix


def _unresolved_scope(
    scope_kind: str | None,
    state: str,
    account: NormalizedResource,
    *,
    canonical_scope: str | None = None,
) -> CosmosDbNoSqlScopeResolution:
    return CosmosDbNoSqlScopeResolution(
        scope_kind=scope_kind,
        resolution_state=state,
        canonical_scope=canonical_scope,
        account_address=account.address,
    )


def _reference_key(value: str | None) -> str:
    text = _known_text(value) or ""
    if text.startswith("${") and text.endswith("}"):
        text = text[2:-1].strip()
    return text.casefold()


def _known_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _unique(values: Iterable[NormalizedResource]) -> NormalizedResource | None:
    candidates = tuple(values)
    return candidates[0] if len(candidates) == 1 else None


def _freeze_multi_map(
    mapping: Mapping[_Key, list[NormalizedResource]],
) -> Mapping[_Key, tuple[NormalizedResource, ...]]:
    return MappingProxyType(
        {
            key: tuple(
                sorted(
                    {resource.address: resource for resource in values}.values(),
                    key=lambda resource: resource.address,
                )
            )
            for key, values in mapping.items()
        }
    )

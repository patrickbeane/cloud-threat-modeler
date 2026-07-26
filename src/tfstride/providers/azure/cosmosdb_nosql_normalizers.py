from __future__ import annotations

from collections.abc import Mapping

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_utils import (
    as_list,
    known_block_strings,
    known_string,
    known_string_list,
    unknown_block_at,
)

AZURE_PROVIDER = "azure"
_DEFAULT_ROLE_TYPE = "CustomRole"


def normalize_cosmosdb_sql_database(resource: TerraformResource) -> NormalizedResource:
    uncertainties: list[str] = []
    database_id = _required_string(resource, "id", uncertainties)
    database_name = _required_string(resource, "name", uncertainties)
    account_name = _required_string(resource, "account_name", uncertainties)
    resource_group_name = _required_string(resource, "resource_group_name", uncertainties)

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=database_id or resource.address,
        data_sensitivity="sensitive",
        metadata={
            AzureResourceMetadata.NAME: database_name or resource.name,
            AzureResourceMetadata.COSMOSDB_RESOURCE_GROUP_NAME: resource_group_name,
            AzureResourceMetadata.COSMOSDB_ACCOUNT_NAME: account_name,
            AzureResourceMetadata.COSMOSDB_SQL_DATABASE_ID: database_id,
            AzureResourceMetadata.COSMOSDB_SQL_DATABASE_NAME: database_name,
            AzureResourceMetadata.COSMOSDB_SQL_RBAC_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_cosmosdb_sql_container(resource: TerraformResource) -> NormalizedResource:
    uncertainties: list[str] = []
    container_id = _required_string(resource, "id", uncertainties)
    container_name = _required_string(resource, "name", uncertainties)
    database_name = _required_string(resource, "database_name", uncertainties)
    account_name = _required_string(resource, "account_name", uncertainties)
    resource_group_name = _required_string(resource, "resource_group_name", uncertainties)

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=container_id or resource.address,
        data_sensitivity="sensitive",
        metadata={
            AzureResourceMetadata.NAME: container_name or resource.name,
            AzureResourceMetadata.COSMOSDB_RESOURCE_GROUP_NAME: resource_group_name,
            AzureResourceMetadata.COSMOSDB_ACCOUNT_NAME: account_name,
            AzureResourceMetadata.COSMOSDB_SQL_DATABASE_NAME: database_name,
            AzureResourceMetadata.COSMOSDB_SQL_CONTAINER_ID: container_id,
            AzureResourceMetadata.COSMOSDB_SQL_CONTAINER_NAME: container_name,
            AzureResourceMetadata.COSMOSDB_SQL_RBAC_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_cosmosdb_sql_role_definition(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    resource_id = known_string(
        values,
        resource.unknown_values,
        "id",
        uncertainties,
        require_string=True,
    )
    raw_definition_id = known_string(
        values,
        resource.unknown_values,
        "role_definition_id",
        uncertainties,
        require_string=True,
    )
    if raw_definition_id and "/" in raw_definition_id:
        resource_id = resource_id or raw_definition_id
    definition_guid = _last_resource_segment(raw_definition_id or resource_id)
    role_name = _required_string(resource, "name", uncertainties)
    role_type = _role_type(resource, uncertainties)
    account_name = _required_string(resource, "account_name", uncertainties)
    resource_group_name = _required_string(resource, "resource_group_name", uncertainties)
    assignable_scopes = known_string_list(
        values,
        resource.unknown_values,
        "assignable_scopes",
        uncertainties,
    )
    if not assignable_scopes and not _has_uncertainty(uncertainties, "assignable_scopes"):
        uncertainties.append("assignable_scopes is not represented in planned values")
    data_actions = _role_definition_data_actions(resource, uncertainties)

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=resource_id or definition_guid or resource.address,
        metadata={
            AzureResourceMetadata.NAME: role_name or resource.name,
            AzureResourceMetadata.COSMOSDB_RESOURCE_GROUP_NAME: resource_group_name,
            AzureResourceMetadata.COSMOSDB_ACCOUNT_NAME: account_name,
            AzureResourceMetadata.COSMOSDB_SQL_ROLE_DEFINITION_RESOURCE_ID: resource_id,
            AzureResourceMetadata.COSMOSDB_SQL_ROLE_DEFINITION_GUID: definition_guid,
            AzureResourceMetadata.COSMOSDB_SQL_ROLE_DEFINITION_NAME: role_name,
            AzureResourceMetadata.COSMOSDB_SQL_ROLE_DEFINITION_TYPE: role_type,
            AzureResourceMetadata.COSMOSDB_SQL_ROLE_DEFINITION_ASSIGNABLE_SCOPES: assignable_scopes,
            AzureResourceMetadata.COSMOSDB_SQL_ROLE_DEFINITION_DATA_ACTIONS: data_actions,
            AzureResourceMetadata.COSMOSDB_SQL_RBAC_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_cosmosdb_sql_role_assignment(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    assignment_id = known_string(
        values,
        resource.unknown_values,
        "id",
        uncertainties,
        require_string=True,
    )
    assignment_name = known_string(
        values,
        resource.unknown_values,
        "name",
        uncertainties,
        require_string=True,
    )
    account_name = _required_string(resource, "account_name", uncertainties)
    resource_group_name = _required_string(resource, "resource_group_name", uncertainties)
    principal_id = _required_string(resource, "principal_id", uncertainties)
    role_definition_reference = _required_string(resource, "role_definition_id", uncertainties)
    scope = _required_string(resource, "scope", uncertainties)

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=assignment_id or assignment_name or resource.address,
        metadata={
            AzureResourceMetadata.NAME: assignment_name or resource.name,
            AzureResourceMetadata.COSMOSDB_RESOURCE_GROUP_NAME: resource_group_name,
            AzureResourceMetadata.COSMOSDB_ACCOUNT_NAME: account_name,
            AzureResourceMetadata.COSMOSDB_SQL_ROLE_ASSIGNMENT_ID: assignment_id,
            AzureResourceMetadata.COSMOSDB_SQL_PRINCIPAL_ID: principal_id,
            AzureResourceMetadata.COSMOSDB_SQL_ROLE_DEFINITION_REFERENCE: role_definition_reference,
            AzureResourceMetadata.COSMOSDB_SQL_ROLE_ASSIGNMENT_SCOPE: scope,
            AzureResourceMetadata.COSMOSDB_SQL_RBAC_UNCERTAINTIES: uncertainties,
        },
    )


def _role_definition_data_actions(
    resource: TerraformResource,
    uncertainties: list[str],
) -> list[str]:
    raw_permissions = resource.values.get("permissions")
    raw_unknown = resource.unknown_values.get("permissions")
    if raw_unknown is True:
        uncertainties.append("permissions is unknown after planning")
        return []
    if raw_permissions in (None, []):
        uncertainties.append("permissions is not represented in planned values")
        return []

    actions: list[str] = []
    for index, permission in enumerate(as_list(raw_permissions)):
        if not isinstance(permission, Mapping):
            uncertainties.append(f"permissions[{index}] has an unrecognized value shape")
            continue
        before = len(uncertainties)
        permission_actions = known_block_strings(
            permission,
            unknown_block_at(raw_unknown, index),
            "data_actions",
            uncertainties,
            path=f"permissions[{index}]",
        )
        if not permission_actions and len(uncertainties) == before:
            uncertainties.append(f"permissions[{index}].data_actions is not represented in planned values")
        actions.extend(permission_actions)
    return _dedupe_sorted(actions)


def _role_type(resource: TerraformResource, uncertainties: list[str]) -> str | None:
    before = len(uncertainties)
    value = known_string(
        resource.values,
        resource.unknown_values,
        "type",
        uncertainties,
        require_string=True,
    )
    if value is not None or len(uncertainties) > before:
        return value
    return _DEFAULT_ROLE_TYPE


def _required_string(
    resource: TerraformResource,
    key: str,
    uncertainties: list[str],
) -> str | None:
    before = len(uncertainties)
    value = known_string(
        resource.values,
        resource.unknown_values,
        key,
        uncertainties,
        require_string=True,
    )
    if value is None and len(uncertainties) == before:
        uncertainties.append(f"{key} is not represented in planned values")
    return value


def _last_resource_segment(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip().rstrip("/").rsplit("/", 1)[-1] or None


def _has_uncertainty(uncertainties: list[str], path: str) -> bool:
    return any(value.startswith(path) for value in uncertainties)


def _dedupe_sorted(values: list[str]) -> list[str]:
    by_key: dict[str, str] = {}
    for value in values:
        normalized = value.strip()
        if normalized:
            by_key.setdefault(normalized.casefold(), normalized)
    return [by_key[key] for key in sorted(by_key)]

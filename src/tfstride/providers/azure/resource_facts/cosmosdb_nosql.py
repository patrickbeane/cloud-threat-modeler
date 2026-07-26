from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_facts.base import AzureBaseFacts


class AzureCosmosDbNoSqlFacts(AzureBaseFacts):
    __slots__ = ()

    @property
    def cosmosdb_resource_group_name(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_RESOURCE_GROUP_NAME)

    @property
    def cosmosdb_account_name(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_ACCOUNT_NAME)

    @property
    def cosmosdb_sql_database_id(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_DATABASE_ID)

    @property
    def cosmosdb_sql_database_name(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_DATABASE_NAME)

    @property
    def cosmosdb_sql_container_id(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_CONTAINER_ID)

    @property
    def cosmosdb_sql_container_name(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_CONTAINER_NAME)

    @property
    def resolved_cosmosdb_account_address(self) -> str | None:
        return self.get(AzureResourceMetadata.RESOLVED_COSMOSDB_ACCOUNT_ADDRESS)

    @property
    def resolved_cosmosdb_database_address(self) -> str | None:
        return self.get(AzureResourceMetadata.RESOLVED_COSMOSDB_DATABASE_ADDRESS)

    @property
    def resolved_cosmosdb_container_address(self) -> str | None:
        return self.get(AzureResourceMetadata.RESOLVED_COSMOSDB_CONTAINER_ADDRESS)

    @property
    def cosmosdb_sql_role_definition_resource_id(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_ROLE_DEFINITION_RESOURCE_ID)

    @property
    def cosmosdb_sql_role_definition_guid(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_ROLE_DEFINITION_GUID)

    @property
    def cosmosdb_sql_role_definition_name(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_ROLE_DEFINITION_NAME)

    @property
    def cosmosdb_sql_role_definition_type(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_ROLE_DEFINITION_TYPE)

    @property
    def cosmosdb_sql_role_definition_assignable_scopes(self) -> list[str]:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_ROLE_DEFINITION_ASSIGNABLE_SCOPES)

    @property
    def cosmosdb_sql_role_definition_data_actions(self) -> list[str]:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_ROLE_DEFINITION_DATA_ACTIONS)

    @property
    def cosmosdb_sql_assignable_scope_records(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_ASSIGNABLE_SCOPE_RECORDS)

    @property
    def cosmosdb_sql_role_assignment_id(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_ROLE_ASSIGNMENT_ID)

    @property
    def cosmosdb_sql_role_assignment_scope(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_ROLE_ASSIGNMENT_SCOPE)

    @property
    def cosmosdb_sql_role_assignment_scope_kind(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_ROLE_ASSIGNMENT_SCOPE_KIND)

    @property
    def cosmosdb_sql_role_assignment_scope_state(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_ROLE_ASSIGNMENT_SCOPE_STATE)

    @property
    def cosmosdb_sql_assignable_scope_compatibility_state(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_ASSIGNABLE_SCOPE_COMPATIBILITY_STATE)

    @property
    def cosmosdb_sql_role_definition_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_ROLE_DEFINITION_REFERENCE)

    @property
    def resolved_cosmosdb_sql_role_definition_address(self) -> str | None:
        return self.get(AzureResourceMetadata.RESOLVED_COSMOSDB_SQL_ROLE_DEFINITION_ADDRESS)

    @property
    def cosmosdb_sql_role_kind(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_ROLE_KIND)

    @property
    def cosmosdb_sql_principal_id(self) -> str | None:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_PRINCIPAL_ID)

    @property
    def cosmosdb_sql_role_data_actions(self) -> list[str]:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_ROLE_DATA_ACTIONS)

    @property
    def cosmosdb_sql_rbac_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.COSMOSDB_SQL_RBAC_UNCERTAINTIES)

    def set_resolved_cosmosdb_account_address(self, address: str) -> None:
        self.set(AzureResourceMetadata.RESOLVED_COSMOSDB_ACCOUNT_ADDRESS, address)

    def set_resolved_cosmosdb_database_address(self, address: str) -> None:
        self.set(AzureResourceMetadata.RESOLVED_COSMOSDB_DATABASE_ADDRESS, address)

    def set_resolved_cosmosdb_container_address(self, address: str) -> None:
        self.set(AzureResourceMetadata.RESOLVED_COSMOSDB_CONTAINER_ADDRESS, address)

    def set_cosmosdb_sql_role_definition_resource_id(self, resource_id: str) -> None:
        self.set(AzureResourceMetadata.COSMOSDB_SQL_ROLE_DEFINITION_RESOURCE_ID, resource_id)

    def set_cosmosdb_sql_assignable_scope_records(self, records: list[dict[str, Any]]) -> None:
        self.set(AzureResourceMetadata.COSMOSDB_SQL_ASSIGNABLE_SCOPE_RECORDS, records)

    def set_cosmosdb_sql_scope_resolution(
        self,
        *,
        scope_kind: str | None,
        scope_state: str,
        account_address: str,
        database_address: str | None,
        container_address: str | None,
    ) -> None:
        self.set(AzureResourceMetadata.COSMOSDB_SQL_ROLE_ASSIGNMENT_SCOPE_KIND, scope_kind)
        self.set(AzureResourceMetadata.COSMOSDB_SQL_ROLE_ASSIGNMENT_SCOPE_STATE, scope_state)
        self.set(AzureResourceMetadata.RESOLVED_COSMOSDB_ACCOUNT_ADDRESS, account_address)
        self.set(AzureResourceMetadata.RESOLVED_COSMOSDB_DATABASE_ADDRESS, database_address)
        self.set(AzureResourceMetadata.RESOLVED_COSMOSDB_CONTAINER_ADDRESS, container_address)

    def set_cosmosdb_sql_assignable_scope_compatibility_state(
        self,
        state: str,
    ) -> None:
        self.set(
            AzureResourceMetadata.COSMOSDB_SQL_ASSIGNABLE_SCOPE_COMPATIBILITY_STATE,
            state,
        )

    def set_cosmosdb_sql_role_data_actions(self, data_actions: list[str]) -> None:
        self.set(AzureResourceMetadata.COSMOSDB_SQL_ROLE_DATA_ACTIONS, data_actions)

    def set_cosmosdb_sql_role_kind(self, role_kind: str) -> None:
        self.set(AzureResourceMetadata.COSMOSDB_SQL_ROLE_KIND, role_kind)

    def set_cosmosdb_sql_role_resolution(
        self,
        *,
        role_kind: str,
        role_name: str,
        data_actions: list[str],
        role_definition_address: str | None = None,
    ) -> None:
        self.set(AzureResourceMetadata.COSMOSDB_SQL_ROLE_KIND, role_kind)
        self.set(AzureResourceMetadata.COSMOSDB_SQL_ROLE_DEFINITION_NAME, role_name)
        self.set(AzureResourceMetadata.COSMOSDB_SQL_ROLE_DATA_ACTIONS, data_actions)
        self.set(
            AzureResourceMetadata.RESOLVED_COSMOSDB_SQL_ROLE_DEFINITION_ADDRESS,
            role_definition_address,
        )

    def extend_cosmosdb_sql_rbac_uncertainties(
        self,
        uncertainties: Sequence[str | None],
    ) -> None:
        self.extend(AzureResourceMetadata.COSMOSDB_SQL_RBAC_UNCERTAINTIES, uncertainties)

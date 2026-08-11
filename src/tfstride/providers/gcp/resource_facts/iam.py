from __future__ import annotations

from typing import Any

from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts.base import GcpBaseFacts


class GcpIamFacts(GcpBaseFacts):
    __slots__ = ()

    @property
    def policy_document(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.POLICY_DOCUMENT)

    @property
    def iam_policy_data_state(self) -> str | None:
        return self.get(GcpResourceMetadata.IAM_POLICY_DATA_STATE)

    @property
    def iam_scope_reference_state(self) -> str | None:
        return self.get(GcpResourceMetadata.IAM_SCOPE_REFERENCE_STATE)

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return self.get(GcpResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES)

    @property
    def bindings(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.IAM_BINDINGS)

    @property
    def custom_role_id(self) -> str | None:
        return self.get(GcpResourceMetadata.CUSTOM_ROLE_ID)

    @property
    def custom_role_permissions(self) -> list[str]:
        return self.get(GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS)

    @property
    def custom_role_permissions_state(self) -> str | None:
        return self.get(GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS_STATE)

    @property
    def custom_role_stage(self) -> str | None:
        return self.get(GcpResourceMetadata.CUSTOM_ROLE_STAGE)

    @property
    def custom_role_deleted(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.CUSTOM_ROLE_DELETED)

    @property
    def custom_role_deleted_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.CUSTOM_ROLE_DELETED_UNCERTAINTIES)

    @property
    def organization_id(self) -> str | None:
        return self.get(GcpResourceMetadata.ORGANIZATION_ID)

    @property
    def folder_id(self) -> str | None:
        return self.get(GcpResourceMetadata.FOLDER_ID)

    @property
    def org_policy_constraint(self) -> str | None:
        return self.get(GcpResourceMetadata.ORG_POLICY_CONSTRAINT)

    @property
    def org_policy_rules(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.ORG_POLICY_RULES)

    @property
    def org_policy_allowed_values(self) -> list[str]:
        return self.get(GcpResourceMetadata.ORG_POLICY_ALLOWED_VALUES)

    @property
    def org_policy_denied_values(self) -> list[str]:
        return self.get(GcpResourceMetadata.ORG_POLICY_DENIED_VALUES)

    @property
    def org_policy_enforced(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.ORG_POLICY_ENFORCED)

    @property
    def org_policy_inherit_from_parent(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.ORG_POLICY_INHERIT_FROM_PARENT)

    @property
    def org_policy_restore_default(self) -> bool:
        return self.get(GcpResourceMetadata.ORG_POLICY_RESTORE_DEFAULT)

    @property
    def org_policy_scope_type(self) -> str | None:
        return self.get(GcpResourceMetadata.ORG_POLICY_SCOPE_TYPE)

    @property
    def org_policy_scope(self) -> str | None:
        return self.get(GcpResourceMetadata.ORG_POLICY_SCOPE)

    @property
    def role(self) -> str | None:
        return self.get(GcpResourceMetadata.IAM_ROLE)

    @property
    def member(self) -> str | None:
        return self.get(GcpResourceMetadata.IAM_MEMBER)

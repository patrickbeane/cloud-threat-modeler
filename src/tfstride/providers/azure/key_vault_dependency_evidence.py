from __future__ import annotations

from typing import Literal, TypedDict

AzureKeyVaultDependencyResolutionState = Literal[
    "resolved",
    "ambiguous",
    "unresolved",
    "unsupported",
]
AzureKeyVaultDependencyReferenceProvenance = Literal[
    "planned_value",
    "configuration_reference",
]
AzureKeyVaultDependencyReferenceKind = Literal[
    "versioned_uri",
    "versionless_uri",
    "versioned_resource_id",
    "versionless_resource_id",
    "terraform_reference",
]
AzureKeyVaultDependencyTargetKind = Literal["key", "key_version"]


class AzureKeyVaultEncryptionDependency(TypedDict):
    dependent_address: str
    dependent_resource_type: str
    dependency_source_address: str
    dependency_source_type: str
    configuration_path: tuple[str | int, ...]
    configured_key_reference: str | None
    reference_provenance: AzureKeyVaultDependencyReferenceProvenance | None
    reference_kind: AzureKeyVaultDependencyReferenceKind | None
    resolution_state: AzureKeyVaultDependencyResolutionState
    customer_managed_key_state: str | None
    candidate_key_addresses: list[str]
    target_kind: AzureKeyVaultDependencyTargetKind | None
    key_address: str | None
    key_vault_address: str | None
    key_vault_id: str | None
    key_vault_uri: str | None
    key_name: str | None
    key_version: str | None
    key_uri: str | None
    key_versionless_uri: str | None
    key_resource_id: str | None
    key_versionless_resource_id: str | None
    posture_uncertainties: list[str]

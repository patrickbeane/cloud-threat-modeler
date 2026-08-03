from __future__ import annotations

from typing import Literal, TypedDict

GcpKmsDependencyResolutionState = Literal[
    "resolved",
    "ambiguous",
    "unresolved",
    "unsupported",
]
GcpKmsDependencyReferenceProvenance = Literal[
    "planned_value",
    "configuration_reference",
]
GcpKmsDependencyReferenceKind = Literal[
    "crypto_key_resource_name",
    "crypto_key_version_resource_name",
    "terraform_reference",
]
GcpKmsDependencyTargetKind = Literal["crypto_key", "crypto_key_version"]


class GcpKmsDependencyCandidate(TypedDict):
    address: str
    target_kind: GcpKmsDependencyTargetKind


class GcpKmsEncryptionDependency(TypedDict):
    dependent_address: str
    dependent_resource_type: str
    dependency_source_address: str
    dependency_source_type: str
    configuration_path: tuple[str | int, ...]
    configured_key_reference: str | None
    reference_provenance: GcpKmsDependencyReferenceProvenance | None
    reference_kind: GcpKmsDependencyReferenceKind | None
    resolution_state: GcpKmsDependencyResolutionState
    customer_managed_encryption_state: str | None
    candidate_targets: list[GcpKmsDependencyCandidate]
    key_address: str | None
    key_resource_name: str | None
    key_project: str | None
    key_location: str | None
    key_ring: str | None
    key_purpose: str | None
    key_version_address: str | None
    key_version_resource_name: str | None
    version_reference_is_explicit: bool
    posture_uncertainties: list[str]

from __future__ import annotations

from typing import Literal, TypedDict

AwsKmsDependencyResolutionState = Literal[
    "resolved",
    "ambiguous",
    "unresolved",
    "unsupported",
]
AwsKmsDependencyReferenceProvenance = Literal[
    "planned_value",
    "configuration_reference",
]
AwsKmsDependencyReferenceKind = Literal[
    "key_arn",
    "key_id",
    "alias_arn",
    "alias_name",
    "terraform_reference",
]
AwsKmsDependencyTargetKind = Literal["key", "alias"]


class AwsKmsDependencyCandidate(TypedDict):
    address: str
    target_kind: AwsKmsDependencyTargetKind


class AwsKmsEncryptionDependency(TypedDict):
    dependent_address: str
    dependent_resource_type: str
    dependency_source_address: str
    dependency_source_type: str
    configuration_path: list[str | int]
    configured_key_reference: str | None
    reference_provenance: AwsKmsDependencyReferenceProvenance | None
    reference_kind: AwsKmsDependencyReferenceKind | None
    resolution_state: AwsKmsDependencyResolutionState
    encryption_ownership_state: str | None
    candidate_targets: list[AwsKmsDependencyCandidate]
    key_address: str | None
    key_arn: str | None
    key_id: str | None
    alias_address: str | None
    alias_name: str | None
    alias_arn: str | None
    key_origin: str | None
    multi_region_state: str | None
    posture_uncertainties: list[str]

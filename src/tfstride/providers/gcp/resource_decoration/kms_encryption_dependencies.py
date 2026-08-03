from __future__ import annotations

import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass

from tfstride.models import (
    NormalizedResource,
    TerraformExpressionPath,
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
)
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
)
from tfstride.providers.gcp.kms_dependency_evidence import (
    GcpKmsDependencyCandidate,
    GcpKmsDependencyReferenceKind,
    GcpKmsDependencyReferenceProvenance,
    GcpKmsDependencyResolutionState,
    GcpKmsEncryptionDependency,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.resource_reference_index import (
    ResourceReferenceIndex,
    build_resource_reference_index,
)

_KMS_KEY = GcpResourceType.KMS_CRYPTO_KEY
_KMS_KEY_VERSION = GcpResourceType.KMS_CRYPTO_KEY_VERSION
_SUPPORTED_DEPENDENT_TYPES = frozenset(
    {
        GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY,
        GcpResourceType.FIRESTORE_DATABASE,
        GcpResourceType.PUBSUB_TOPIC,
        GcpResourceType.SECRET_MANAGER_SECRET,
        GcpResourceType.STORAGE_BUCKET,
    }
)
_KEY_REFERENCE_SUFFIXES = frozenset({".id"})
_KEY_PATH_PATTERN = re.compile(
    r"^projects/(?P<project>[^/]+)/locations/(?P<location>[^/]+)/"
    r"keyRings/(?P<key_ring>[^/]+)/cryptoKeys/(?P<key>[^/]+)$"
)
_KEY_VERSION_PATH_PATTERN = re.compile(
    r"^(?P<key_path>projects/[^/]+/locations/[^/]+/keyRings/[^/]+/"
    r"cryptoKeys/[^/]+)/cryptoKeyVersions/(?P<version>[^/]+)$"
)
_KEY_RING_PATH_PATTERN = re.compile(r"^projects/[^/]+/locations/[^/]+/keyRings/[^/]+$")
_SECRET_AUTO_UNCERTAINTY_PATTERN = re.compile(
    r"^replication\.auto\.customer_managed_encryption\[(?P<key_index>\d+)\]"
    r"\.kms_key_name\b"
)
_SECRET_REPLICA_UNCERTAINTY_PATTERN = re.compile(
    r"^replication\.user_managed\.replicas\[(?P<replica_index>\d+)\]"
    r"\.customer_managed_encryption\[(?P<key_index>\d+)\]\.kms_key_name\b"
)


@dataclass(frozen=True, slots=True)
class _DependencyInput:
    dependent: NormalizedResource
    source: NormalizedResource
    configuration_path: TerraformExpressionPath
    resolution_paths: tuple[TerraformExpressionPath, ...]
    configured_reference: str | None
    ownership_state: str | None
    source_uncertainties: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ResolutionEvidence:
    state: GcpKmsDependencyResolutionState
    provenance: GcpKmsDependencyReferenceProvenance | None
    reference_kind: GcpKmsDependencyReferenceKind | None
    configured_reference: str | None
    candidates: tuple[NormalizedResource, ...]
    selected_key: NormalizedResource | None
    uncertainties: tuple[str, ...]
    version_reference_is_explicit: bool


class ResolveGcpKmsEncryptionDependenciesStage:
    name = "resolve_gcp_kms_encryption_dependencies"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        _ = context
        targets = tuple(resource for resource in resources if resource.resource_type in {_KMS_KEY, _KMS_KEY_VERSION})
        native_index = build_resource_reference_index(
            targets,
            references_for_resource=_native_kms_references,
        )
        exact_resources_by_address = {resource.address: resource for resource in resources}
        dependencies_by_address: dict[str, list[GcpKmsEncryptionDependency]] = {
            resource.address: []
            for resource in resources
            if resource.resource_type in _SUPPORTED_DEPENDENT_TYPES or resource.resource_type == _KMS_KEY
        }
        uncertainties_by_address: dict[str, list[str]] = {address: [] for address in dependencies_by_address}

        for dependent in resources:
            if dependent.resource_type not in _SUPPORTED_DEPENDENT_TYPES:
                continue
            inputs, uncovered_uncertainties = _dependency_inputs(dependent)
            uncertainties_by_address[dependent.address].extend(
                f"{dependent.address}: {uncertainty}" for uncertainty in uncovered_uncertainties
            )
            for dependency_input in inputs:
                record = _dependency_record(
                    dependency_input,
                    native_index=native_index,
                    resources_by_address=exact_resources_by_address,
                )
                dependencies_by_address[dependent.address].append(record)
                uncertainties_by_address[dependent.address].extend(
                    f"{dependent.address}: {uncertainty}" for uncertainty in record["posture_uncertainties"]
                )
                if record["resolution_state"] != "resolved":
                    continue
                key_address = record["key_address"]
                if key_address is not None:
                    dependencies_by_address.setdefault(key_address, []).append(record)

        for address, dependencies in dependencies_by_address.items():
            resource = exact_resources_by_address.get(address)
            if resource is None:
                continue
            gcp_facts(resource).set_kms_encryption_dependency_posture(
                dependencies=sorted(
                    dependencies,
                    key=_dependency_sort_key,
                ),
                uncertainties=_dedupe(uncertainties_by_address.get(address, [])),
            )


def _dependency_inputs(
    dependent: NormalizedResource,
) -> tuple[list[_DependencyInput], list[str]]:
    facts = gcp_facts(dependent)
    if dependent.resource_type == GcpResourceType.STORAGE_BUCKET:
        paths = (("encryption", 0, "default_kms_key_name"),)
        encryption = dependent.get_metadata_field(GcpResourceMetadata.GCS_ENCRYPTION_CONFIGURATION)
        unresolved_key_field = facts.default_kms_key_name is None and "default_kms_key_name" in encryption
        state = (
            STATE_UNKNOWN
            if unresolved_key_field
            else _state_from_optional_bool(
                facts.customer_managed_encryption,
                has_symbolic_reference=_has_matching_resolution(
                    dependent,
                    paths,
                ),
            )
        )
        source_uncertainties = (
            ("encryption.default_kms_key_name is unknown after planning",) if unresolved_key_field else ()
        )
        dependency = _input_if_relevant(
            dependent=dependent,
            configuration_path=paths[0],
            resolution_paths=paths,
            configured_reference=facts.default_kms_key_name,
            ownership_state=state,
            source_uncertainties=source_uncertainties,
        )
        return ([dependency] if dependency is not None else []), []

    if dependent.resource_type == GcpResourceType.PUBSUB_TOPIC:
        uncertainties = _matching_uncertainties(
            facts.pubsub_posture_uncertainties,
            ("kms_key_name",),
        )
        return _single_dependency_inputs(
            dependent=dependent,
            configuration_path=("kms_key_name",),
            configured_reference=facts.pubsub_topic_kms_key_name,
            ownership_state=facts.pubsub_topic_cmek_state,
            uncertainties=uncertainties,
        )

    if dependent.resource_type == GcpResourceType.FIRESTORE_DATABASE:
        uncertainties = _matching_path_uncertainties(
            facts.firestore_posture_uncertainties,
            "cmek_config",
        )
        return _single_dependency_inputs(
            dependent=dependent,
            configuration_path=("cmek_config", 0, "kms_key_name"),
            configured_reference=facts.firestore_cmek_key_name,
            ownership_state=facts.firestore_cmek_state,
            uncertainties=uncertainties,
        )

    if dependent.resource_type == GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY:
        uncertainties = _matching_uncertainties(
            facts.artifact_registry_posture_uncertainties,
            ("kms_key_name",),
        )
        return _single_dependency_inputs(
            dependent=dependent,
            configuration_path=("kms_key_name",),
            configured_reference=facts.artifact_registry_kms_key_name,
            ownership_state=facts.artifact_registry_encryption_state,
            uncertainties=uncertainties,
        )

    if dependent.resource_type == GcpResourceType.SECRET_MANAGER_SECRET:
        return _secret_manager_dependency_inputs(dependent)

    return [], []


def _single_dependency_inputs(
    *,
    dependent: NormalizedResource,
    configuration_path: TerraformExpressionPath,
    configured_reference: str | None,
    ownership_state: str | None,
    uncertainties: Sequence[str],
) -> tuple[list[_DependencyInput], list[str]]:
    dependency = _input_if_relevant(
        dependent=dependent,
        configuration_path=configuration_path,
        resolution_paths=(configuration_path,),
        configured_reference=configured_reference,
        ownership_state=ownership_state,
        source_uncertainties=uncertainties,
    )
    if dependency is None:
        return [], list(uncertainties)
    return [dependency], [
        uncertainty for uncertainty in uncertainties if uncertainty not in dependency.source_uncertainties
    ]


def _secret_manager_dependency_inputs(
    dependent: NormalizedResource,
) -> tuple[list[_DependencyInput], list[str]]:
    facts = gcp_facts(dependent)
    replication = facts.secret_manager_replication
    uncertainties = facts.secret_manager_posture_uncertainties
    inputs: list[_DependencyInput] = []

    if facts.secret_manager_replication_mode == "automatic":
        key_names = _record_string_list(replication, "kms_key_names")
        resolution_indexes = {
            resolution.path[5]
            for resolution in dependent.reference_resolutions
            if len(resolution.path) == 7
            and resolution.path[:5]
            == (
                "replication",
                0,
                "auto",
                0,
                "customer_managed_encryption",
            )
            and isinstance(resolution.path[5], int)
            and resolution.path[6] == "kms_key_name"
        }
        uncertainty_indexes = {
            int(match.group("key_index"))
            for uncertainty in uncertainties
            if (match := _SECRET_AUTO_UNCERTAINTY_PATTERN.match(uncertainty))
        }
        for index in sorted(set(range(len(key_names))) | resolution_indexes | uncertainty_indexes):
            path = (
                "replication",
                0,
                "auto",
                0,
                "customer_managed_encryption",
                index,
                "kms_key_name",
            )
            normalized_path = f"replication.auto.customer_managed_encryption[{index}].kms_key_name"
            source_uncertainties = _matching_path_uncertainties(
                uncertainties,
                normalized_path,
            )
            dependency = _input_if_relevant(
                dependent=dependent,
                configuration_path=path,
                resolution_paths=(path,),
                configured_reference=(key_names[index] if index < len(key_names) else None),
                ownership_state=(STATE_CONFIGURED if index < len(key_names) else STATE_UNKNOWN),
                source_uncertainties=source_uncertainties,
            )
            if dependency is not None:
                inputs.append(dependency)

    elif facts.secret_manager_replication_mode == "user_managed":
        replicas = _record_mapping_list(replication, "replicas")
        resolution_indexes = {
            (resolution.path[5], resolution.path[7])
            for resolution in dependent.reference_resolutions
            if len(resolution.path) == 9
            and resolution.path[:5]
            == (
                "replication",
                0,
                "user_managed",
                0,
                "replicas",
            )
            and isinstance(resolution.path[5], int)
            and resolution.path[6] == "customer_managed_encryption"
            and isinstance(resolution.path[7], int)
            and resolution.path[8] == "kms_key_name"
        }
        uncertainty_indexes = {
            (
                int(match.group("replica_index")),
                int(match.group("key_index")),
            )
            for uncertainty in uncertainties
            if (match := _SECRET_REPLICA_UNCERTAINTY_PATTERN.match(uncertainty))
        }
        configured_indexes = {
            (replica_index, key_index)
            for replica_index, replica in enumerate(replicas)
            for key_index, _ in enumerate(_record_string_list(replica, "kms_key_names"))
        }
        for replica_index, key_index in sorted(configured_indexes | resolution_indexes | uncertainty_indexes):
            replica = replicas[replica_index] if replica_index < len(replicas) else {}
            key_names = _record_string_list(replica, "kms_key_names")
            path = (
                "replication",
                0,
                "user_managed",
                0,
                "replicas",
                replica_index,
                "customer_managed_encryption",
                key_index,
                "kms_key_name",
            )
            normalized_path = (
                "replication.user_managed.replicas"
                f"[{replica_index}].customer_managed_encryption"
                f"[{key_index}].kms_key_name"
            )
            source_uncertainties = _matching_path_uncertainties(
                uncertainties,
                normalized_path,
            )
            dependency = _input_if_relevant(
                dependent=dependent,
                configuration_path=path,
                resolution_paths=(path,),
                configured_reference=(key_names[key_index] if key_index < len(key_names) else None),
                ownership_state=(STATE_CONFIGURED if key_index < len(key_names) else STATE_UNKNOWN),
                source_uncertainties=source_uncertainties,
            )
            if dependency is not None:
                inputs.append(dependency)

    covered = {uncertainty for dependency_input in inputs for uncertainty in dependency_input.source_uncertainties}
    uncovered = [
        uncertainty
        for uncertainty in uncertainties
        if "replication" in uncertainty.casefold() and uncertainty not in covered
    ]
    return inputs, uncovered


def _input_if_relevant(
    *,
    dependent: NormalizedResource,
    configuration_path: TerraformExpressionPath,
    resolution_paths: tuple[TerraformExpressionPath, ...],
    configured_reference: str | None,
    ownership_state: str | None,
    source_uncertainties: Sequence[str],
) -> _DependencyInput | None:
    has_resolution = _has_matching_resolution(
        dependent,
        resolution_paths,
    )
    if (
        configured_reference is None
        and not has_resolution
        and not source_uncertainties
        and ownership_state != STATE_UNKNOWN
    ):
        return None
    return _DependencyInput(
        dependent=dependent,
        source=dependent,
        configuration_path=configuration_path,
        resolution_paths=resolution_paths,
        configured_reference=configured_reference,
        ownership_state=ownership_state,
        source_uncertainties=tuple(source_uncertainties),
    )


def _dependency_record(
    dependency_input: _DependencyInput,
    *,
    native_index: ResourceReferenceIndex,
    resources_by_address: Mapping[str, NormalizedResource],
) -> GcpKmsEncryptionDependency:
    evidence = _resolve_dependency(
        dependency_input,
        native_index=native_index,
        resources_by_address=resources_by_address,
    )
    selected_key = evidence.selected_key
    key_resource_name = _key_resource_name(selected_key) if selected_key is not None else None
    key_match = _KEY_PATH_PATTERN.fullmatch(key_resource_name) if key_resource_name is not None else None
    key_facts = gcp_facts(selected_key) if selected_key is not None else None
    resolutions = _matching_resolutions(
        dependency_input.source,
        dependency_input.resolution_paths,
    )
    configuration_path = resolutions[0].path if len(resolutions) == 1 else dependency_input.configuration_path
    return {
        "dependent_address": dependency_input.dependent.address,
        "dependent_resource_type": dependency_input.dependent.resource_type,
        "dependency_source_address": dependency_input.source.address,
        "dependency_source_type": dependency_input.source.resource_type,
        "configuration_path": list(configuration_path),
        "configured_key_reference": evidence.configured_reference,
        "reference_provenance": evidence.provenance,
        "reference_kind": evidence.reference_kind,
        "resolution_state": evidence.state,
        "customer_managed_encryption_state": (dependency_input.ownership_state),
        "candidate_targets": [_dependency_candidate(candidate) for candidate in evidence.candidates],
        "key_address": (selected_key.address if selected_key is not None else None),
        "key_resource_name": key_resource_name,
        "key_project": (key_match.group("project") if key_match is not None else None),
        "key_location": (key_match.group("location") if key_match is not None else None),
        "key_ring": (key_resource_name.rsplit("/cryptoKeys/", 1)[0] if key_resource_name is not None else None),
        "key_purpose": (key_facts.kms_purpose if key_facts is not None else None),
        "key_version_address": None,
        "key_version_resource_name": None,
        "version_reference_is_explicit": (evidence.version_reference_is_explicit),
        "posture_uncertainties": list(evidence.uncertainties),
    }


def _resolve_dependency(
    dependency_input: _DependencyInput,
    *,
    native_index: ResourceReferenceIndex,
    resources_by_address: Mapping[str, NormalizedResource],
) -> _ResolutionEvidence:
    resolutions = _matching_resolutions(
        dependency_input.source,
        dependency_input.resolution_paths,
    )
    configured_reference = dependency_input.configured_reference
    if configured_reference and not _is_symbolic_placeholder(
        configured_reference,
        resolutions,
    ):
        return _resolve_native_reference(
            configured_reference,
            dependency_input,
            native_index=native_index,
        )
    if resolutions:
        return _resolve_configuration_references(
            resolutions,
            dependency_input,
            resources_by_address=resources_by_address,
        )
    if configured_reference:
        return _resolve_native_reference(
            configured_reference,
            dependency_input,
            native_index=native_index,
        )
    return _unresolved_evidence(
        state="unresolved",
        provenance=None,
        reference_kind=None,
        configured_reference=None,
        candidates=(),
        uncertainties=(*(dependency_input.source_uncertainties or ("Cloud KMS key reference is unresolved",)),),
        version_reference_is_explicit=False,
    )


def _resolve_native_reference(
    reference: str,
    dependency_input: _DependencyInput,
    *,
    native_index: ResourceReferenceIndex,
) -> _ResolutionEvidence:
    normalized = reference.strip()
    reference_kind = _native_reference_kind(normalized)
    candidates = tuple(
        candidate
        for candidate in native_index.candidates(normalized)
        if candidate.resource_type in {_KMS_KEY, _KMS_KEY_VERSION}
    )
    version_reference = reference_kind == "crypto_key_version_resource_name"
    if reference_kind != "crypto_key_resource_name":
        return _unresolved_evidence(
            state="unsupported",
            provenance="planned_value",
            reference_kind=reference_kind,
            configured_reference=normalized,
            candidates=candidates,
            uncertainties=(
                f"Cloud KMS reference {normalized} is not an exact "
                "CryptoKey resource name supported by "
                f"{dependency_input.source.resource_type}",
                *dependency_input.source_uncertainties,
            ),
            version_reference_is_explicit=version_reference,
        )
    if len(candidates) > 1:
        return _unresolved_evidence(
            state="ambiguous",
            provenance="planned_value",
            reference_kind=reference_kind,
            configured_reference=normalized,
            candidates=candidates,
            uncertainties=(
                f"Cloud KMS reference {normalized} matches multiple modeled CryptoKeys",
                *dependency_input.source_uncertainties,
            ),
            version_reference_is_explicit=False,
        )
    if not candidates:
        return _unresolved_evidence(
            state="unresolved",
            provenance="planned_value",
            reference_kind=reference_kind,
            configured_reference=normalized,
            candidates=(),
            uncertainties=(
                f"Cloud KMS reference {normalized} does not resolve to a modeled CryptoKey",
                *dependency_input.source_uncertainties,
            ),
            version_reference_is_explicit=False,
        )
    candidate = candidates[0]
    if candidate.resource_type != _KMS_KEY:
        return _unresolved_evidence(
            state="unsupported",
            provenance="planned_value",
            reference_kind=reference_kind,
            configured_reference=normalized,
            candidates=candidates,
            uncertainties=(
                f"Cloud KMS reference {normalized} identifies a CryptoKeyVersion where a CryptoKey is required",
                *dependency_input.source_uncertainties,
            ),
            version_reference_is_explicit=True,
        )
    return _select_key_candidate(
        candidate,
        candidates=candidates,
        configured_reference=normalized,
        provenance="planned_value",
        reference_kind=reference_kind,
        dependency_input=dependency_input,
    )


def _resolve_configuration_references(
    resolutions: tuple[TerraformReferenceResolution, ...],
    dependency_input: _DependencyInput,
    *,
    resources_by_address: Mapping[str, NormalizedResource],
) -> _ResolutionEvidence:
    candidates: dict[str, NormalizedResource] = {}
    target_references: dict[str, str] = {}
    reasons: list[str] = []
    ambiguous = False
    unsupported = False
    unresolved = False
    version_reference = False

    for resolution in resolutions:
        if resolution.state == TerraformReferenceResolutionState.AMBIGUOUS:
            ambiguous = True
        elif resolution.state == TerraformReferenceResolutionState.UNSUPPORTED:
            unsupported = True
        elif resolution.state == TerraformReferenceResolutionState.UNRESOLVED:
            unresolved = True
        elif resolution.state != TerraformReferenceResolutionState.SYMBOLIC:
            unsupported = True
        if resolution.reason:
            reasons.append(resolution.reason)

        for target in resolution.targets:
            candidate = resources_by_address.get(target.address)
            if candidate is None or candidate.resource_type not in {
                _KMS_KEY,
                _KMS_KEY_VERSION,
            }:
                unsupported = True
                reasons.append(
                    f"Terraform target {target.address} is not a modeled Cloud KMS CryptoKey or CryptoKeyVersion"
                )
                continue
            candidates.setdefault(candidate.address, candidate)
            target_references.setdefault(
                candidate.address,
                target.reference,
            )
            if candidate.resource_type == _KMS_KEY_VERSION:
                version_reference = True
                unsupported = True
                reasons.append(
                    f"Terraform target {target.reference} identifies a CryptoKeyVersion where a CryptoKey is required"
                )
            elif not _reference_has_suffix(
                target.reference,
                _KEY_REFERENCE_SUFFIXES,
            ):
                unsupported = True
                reasons.append(
                    f"Terraform target reference {target.reference} "
                    f"is unsupported for "
                    f"{dependency_input.source.resource_type}"
                )

    ordered_candidates = tuple(
        sorted(
            candidates.values(),
            key=lambda candidate: candidate.address,
        )
    )
    configured_reference = target_references[ordered_candidates[0].address] if len(ordered_candidates) == 1 else None
    if ambiguous or len(ordered_candidates) > 1:
        return _unresolved_evidence(
            state="ambiguous",
            provenance="configuration_reference",
            reference_kind="terraform_reference",
            configured_reference=configured_reference,
            candidates=ordered_candidates,
            uncertainties=(
                "Terraform configuration reference has multiple modeled Cloud KMS targets",
                *reasons,
                *dependency_input.source_uncertainties,
            ),
            version_reference_is_explicit=version_reference,
        )
    if unsupported:
        return _unresolved_evidence(
            state="unsupported",
            provenance="configuration_reference",
            reference_kind="terraform_reference",
            configured_reference=configured_reference,
            candidates=ordered_candidates,
            uncertainties=(
                *(reasons or ["Terraform configuration reference uses unsupported Cloud KMS relationship evidence"]),
                *dependency_input.source_uncertainties,
            ),
            version_reference_is_explicit=version_reference,
        )
    if unresolved or len(ordered_candidates) != 1:
        return _unresolved_evidence(
            state="unresolved",
            provenance="configuration_reference",
            reference_kind="terraform_reference",
            configured_reference=configured_reference,
            candidates=ordered_candidates,
            uncertainties=(
                *(reasons or ["Terraform configuration reference does not resolve to a modeled Cloud KMS CryptoKey"]),
                *dependency_input.source_uncertainties,
            ),
            version_reference_is_explicit=version_reference,
        )

    candidate = ordered_candidates[0]
    return _select_key_candidate(
        candidate,
        candidates=ordered_candidates,
        configured_reference=target_references[candidate.address],
        provenance="configuration_reference",
        reference_kind="terraform_reference",
        dependency_input=dependency_input,
    )


def _select_key_candidate(
    candidate: NormalizedResource,
    *,
    candidates: tuple[NormalizedResource, ...],
    configured_reference: str,
    provenance: GcpKmsDependencyReferenceProvenance,
    reference_kind: GcpKmsDependencyReferenceKind,
    dependency_input: _DependencyInput,
) -> _ResolutionEvidence:
    key_resource_name = _key_resource_name(candidate)
    if key_resource_name is None:
        return _unresolved_evidence(
            state="unresolved",
            provenance=provenance,
            reference_kind=reference_kind,
            configured_reference=configured_reference,
            candidates=candidates,
            uncertainties=(
                f"{candidate.address} does not retain an exact provider-native CryptoKey resource name",
                *dependency_input.source_uncertainties,
            ),
            version_reference_is_explicit=False,
        )
    return _ResolutionEvidence(
        state="resolved",
        provenance=provenance,
        reference_kind=reference_kind,
        configured_reference=configured_reference,
        candidates=candidates,
        selected_key=candidate,
        uncertainties=_applicability_uncertainties(dependency_input),
        version_reference_is_explicit=False,
    )


def _native_kms_references(
    resource: NormalizedResource,
) -> tuple[str | None, ...]:
    if resource.resource_type == _KMS_KEY:
        return (_key_resource_name(resource),)
    if resource.resource_type == _KMS_KEY_VERSION:
        return (_key_version_resource_name(resource),)
    return ()


def _key_resource_name(
    resource: NormalizedResource | None,
) -> str | None:
    if resource is None or resource.resource_type != _KMS_KEY:
        return None
    facts = gcp_facts(resource)
    for value in (
        facts.kms_crypto_key_reference,
        resource.identifier,
    ):
        if isinstance(value, str) and _KEY_PATH_PATTERN.fullmatch(value.strip()) is not None:
            return value.strip()

    key_ring = facts.kms_key_ring
    key_name = resource.get_metadata_field(GcpResourceMetadata.NAME)
    if (
        isinstance(key_ring, str)
        and _KEY_RING_PATH_PATTERN.fullmatch(key_ring.strip()) is not None
        and isinstance(key_name, str)
        and key_name
        and "/" not in key_name
    ):
        candidate = f"{key_ring.strip()}/cryptoKeys/{key_name}"
        if _KEY_PATH_PATTERN.fullmatch(candidate) is not None:
            return candidate
    return None


def _key_version_resource_name(
    resource: NormalizedResource | None,
) -> str | None:
    if resource is None or resource.resource_type != _KMS_KEY_VERSION:
        return None
    facts = gcp_facts(resource)
    for value in (
        facts.kms_crypto_key_version_reference,
        facts.kms_crypto_key_version_name,
        resource.identifier,
    ):
        if isinstance(value, str) and _KEY_VERSION_PATH_PATTERN.fullmatch(value.strip()) is not None:
            return value.strip()
    return None


def _native_reference_kind(
    reference: str,
) -> GcpKmsDependencyReferenceKind | None:
    if _KEY_PATH_PATTERN.fullmatch(reference) is not None:
        return "crypto_key_resource_name"
    if _KEY_VERSION_PATH_PATTERN.fullmatch(reference) is not None:
        return "crypto_key_version_resource_name"
    if reference.startswith("google_kms_") and "." in reference:
        return "terraform_reference"
    return None


def _is_symbolic_placeholder(
    value: str,
    resolutions: Sequence[TerraformReferenceResolution],
) -> bool:
    normalized = value.strip()
    return any(
        normalized
        in {
            target.address,
            target.reference,
            f"${{{target.reference}}}",
        }
        for resolution in resolutions
        for target in resolution.targets
    )


def _matching_resolutions(
    resource: NormalizedResource,
    paths: Collection[TerraformExpressionPath],
) -> tuple[TerraformReferenceResolution, ...]:
    allowed_paths = set(paths)
    return tuple(
        resolution
        for resolution in resource.reference_resolutions
        if resolution.path in allowed_paths
        and resolution.provenance == TerraformReferenceProvenance.CONFIGURATION_REFERENCE
    )


def _has_matching_resolution(
    resource: NormalizedResource,
    paths: Collection[TerraformExpressionPath],
) -> bool:
    return bool(_matching_resolutions(resource, paths))


def _reference_has_suffix(
    reference: str,
    suffixes: Collection[str],
) -> bool:
    return any(reference.endswith(suffix) for suffix in suffixes)


def _dependency_candidate(
    resource: NormalizedResource,
) -> GcpKmsDependencyCandidate:
    return {
        "address": resource.address,
        "target_kind": ("crypto_key_version" if resource.resource_type == _KMS_KEY_VERSION else "crypto_key"),
    }


def _unresolved_evidence(
    *,
    state: GcpKmsDependencyResolutionState,
    provenance: GcpKmsDependencyReferenceProvenance | None,
    reference_kind: GcpKmsDependencyReferenceKind | None,
    configured_reference: str | None,
    candidates: tuple[NormalizedResource, ...],
    uncertainties: Sequence[str],
    version_reference_is_explicit: bool,
) -> _ResolutionEvidence:
    return _ResolutionEvidence(
        state=state,
        provenance=provenance,
        reference_kind=reference_kind,
        configured_reference=configured_reference,
        candidates=candidates,
        selected_key=None,
        uncertainties=tuple(_dedupe(uncertainties)),
        version_reference_is_explicit=version_reference_is_explicit,
    )


def _applicability_uncertainties(
    dependency_input: _DependencyInput,
) -> tuple[str, ...]:
    terminal = dependency_input.configuration_path[-1]
    if not isinstance(terminal, str):
        return dependency_input.source_uncertainties
    return tuple(
        uncertainty
        for uncertainty in dependency_input.source_uncertainties
        if not (terminal.casefold() in uncertainty.casefold() and "unknown after planning" in uncertainty.casefold())
    )


def _state_from_optional_bool(
    value: bool | None,
    *,
    has_symbolic_reference: bool,
) -> str:
    if has_symbolic_reference:
        return STATE_UNKNOWN
    if value is True:
        return STATE_CONFIGURED
    if value is False:
        return STATE_NOT_CONFIGURED
    return STATE_UNKNOWN


def _matching_path_uncertainties(
    uncertainties: Sequence[str],
    path: str,
) -> list[str]:
    normalized_path = path.casefold()
    path_prefixes = (
        f"{normalized_path}.",
        f"{normalized_path}[",
        f"{normalized_path} ",
        f"{normalized_path}:",
    )
    return [
        uncertainty
        for uncertainty in uncertainties
        if (normalized := uncertainty.strip().casefold()) == normalized_path or normalized.startswith(path_prefixes)
    ]


def _matching_uncertainties(
    uncertainties: Sequence[str],
    terms: Collection[str],
) -> list[str]:
    normalized_terms = tuple(term.casefold() for term in terms)
    return [
        uncertainty for uncertainty in uncertainties if any(term in uncertainty.casefold() for term in normalized_terms)
    ]


def _record_string_list(
    record: Mapping[str, object],
    key: str,
) -> list[str]:
    value = record.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _record_mapping_list(
    record: Mapping[str, object],
    key: str,
) -> list[Mapping[str, object]]:
    value = record.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _dependency_sort_key(
    dependency: GcpKmsEncryptionDependency,
) -> tuple[str, str, str, str]:
    return (
        dependency["dependent_address"],
        dependency["dependency_source_address"],
        repr(dependency["configuration_path"]),
        dependency["configured_key_reference"] or "",
    )


def _dedupe(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))

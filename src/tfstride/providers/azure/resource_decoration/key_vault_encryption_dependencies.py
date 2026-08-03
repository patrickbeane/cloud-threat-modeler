from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from tfstride.models import (
    NormalizedResource,
    TerraformExpressionPath,
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
)
from tfstride.providers.azure.key_vault_dependency_evidence import (
    AzureKeyVaultDependencyReferenceKind,
    AzureKeyVaultDependencyReferenceProvenance,
    AzureKeyVaultDependencyResolutionState,
    AzureKeyVaultDependencyTargetKind,
    AzureKeyVaultEncryptionDependency,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.resource_utils import azure_reference_key
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
)
from tfstride.providers.resource_reference_index import (
    ResourceReferenceIndex,
    build_resource_reference_index,
)

_KEY = AzureResourceType.KEY_VAULT_KEY
_SUPPORTED_DEPENDENT_TYPES = frozenset(
    {
        AzureResourceType.CONTAINER_REGISTRY,
        AzureResourceType.COSMOSDB_ACCOUNT,
        AzureResourceType.KUBERNETES_CLUSTER,
        AzureResourceType.SERVICE_BUS_NAMESPACE,
        AzureResourceType.STORAGE_ACCOUNT,
    }
)
_URI_REFERENCE_KINDS: frozenset[AzureKeyVaultDependencyReferenceKind] = frozenset(
    {
        "versioned_uri",
        "versionless_uri",
    }
)
_VERSIONLESS_URI_REFERENCE_KINDS: frozenset[AzureKeyVaultDependencyReferenceKind] = frozenset(
    {
        "versionless_uri",
    }
)
_URI_REFERENCE_SUFFIXES = frozenset({".id", ".versionless_id"})
_VERSIONLESS_URI_REFERENCE_SUFFIXES = frozenset({".versionless_id"})
_KEY_VAULT_DNS_SUFFIXES = (
    ".vault.azure.net",
    ".vault.azure.cn",
    ".vault.usgovcloudapi.net",
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
    allowed_reference_kinds: frozenset[AzureKeyVaultDependencyReferenceKind]
    allowed_reference_suffixes: frozenset[str]
    source_evidence_ambiguous: bool = False


@dataclass(frozen=True, slots=True)
class _ResolutionEvidence:
    state: AzureKeyVaultDependencyResolutionState
    provenance: AzureKeyVaultDependencyReferenceProvenance | None
    reference_kind: AzureKeyVaultDependencyReferenceKind | None
    configured_reference: str | None
    candidates: tuple[NormalizedResource, ...]
    target_kind: AzureKeyVaultDependencyTargetKind | None
    selected_key: NormalizedResource | None
    uncertainties: tuple[str, ...]


class ResolveAzureKeyVaultEncryptionDependenciesStage:
    name = "resolve_azure_key_vault_encryption_dependencies"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        _ = context
        keys = tuple(resource for resource in resources if resource.resource_type == _KEY)
        native_index = build_resource_reference_index(
            keys,
            references_for_resource=_native_key_references,
            reference_key=azure_reference_key,
        )
        resources_by_address = {resource.address: resource for resource in resources}
        dependencies_by_address: dict[str, list[AzureKeyVaultEncryptionDependency]] = {
            resource.address: []
            for resource in resources
            if resource.resource_type in _SUPPORTED_DEPENDENT_TYPES or resource.resource_type == _KEY
        }
        uncertainties_by_address: dict[str, list[str]] = {address: [] for address in dependencies_by_address}

        for dependent in resources:
            if dependent.resource_type not in _SUPPORTED_DEPENDENT_TYPES:
                continue
            inputs, uncovered_uncertainties = _dependency_inputs(
                dependent,
                resources_by_address=resources_by_address,
            )
            uncertainties_by_address[dependent.address].extend(
                f"{dependent.address}: {uncertainty}" for uncertainty in uncovered_uncertainties
            )
            for dependency_input in inputs:
                record = _dependency_record(
                    dependency_input,
                    native_index=native_index,
                    resources_by_address=resources_by_address,
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
            resource = resources_by_address.get(address)
            if resource is None:
                continue
            azure_facts(resource).set_key_vault_encryption_dependency_posture(
                dependencies=sorted(dependencies, key=_dependency_sort_key),
                uncertainties=_dedupe(uncertainties_by_address.get(address, [])),
            )


def _dependency_inputs(
    dependent: NormalizedResource,
    *,
    resources_by_address: Mapping[str, NormalizedResource],
) -> tuple[list[_DependencyInput], list[str]]:
    facts = azure_facts(dependent)
    if dependent.resource_type == AzureResourceType.STORAGE_ACCOUNT:
        paths = (
            ("customer_managed_key", 0, "key_vault_key_id"),
            ("customer_managed_key", 0, "key_vault_key_uri"),
        )
        uncertainties = _matching_uncertainties(
            facts.storage_posture_uncertainties,
            ("customer_managed_key",),
        )
        return _alternate_dependency_inputs(
            dependent=dependent,
            source=dependent,
            fields=(
                (
                    ("customer_managed_key", 0, "key_vault_key_id"),
                    facts.storage_customer_managed_key_id_reference,
                ),
                (
                    ("customer_managed_key", 0, "key_vault_key_uri"),
                    facts.storage_customer_managed_key_uri_reference,
                ),
            ),
            ownership_state=_ownership_state(
                facts.storage_customer_managed_key_id,
                dependent,
                paths,
                uncertainties,
            ),
            uncertainties=uncertainties,
            allowed_reference_kinds=_URI_REFERENCE_KINDS,
            allowed_reference_suffixes=_URI_REFERENCE_SUFFIXES,
        )

    if dependent.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        source_address = facts.service_bus_customer_managed_key_source_address
        source = resources_by_address.get(source_address) if source_address is not None else dependent
        if source is None:
            return [], [f"customer-managed key source {source_address} is not a modeled Azure resource"]
        source_facts = azure_facts(source)
        if source.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE_CUSTOMER_MANAGED_KEY:
            paths = (("key_vault_key_id",),)
            uncertainties = _matching_path_uncertainties(
                source_facts.service_bus_posture_uncertainties,
                paths[0],
            )
            return _single_dependency_inputs(
                dependent=dependent,
                source=source,
                configuration_path=paths[0],
                resolution_paths=paths,
                configured_reference=source_facts.service_bus_key_vault_key_id_reference,
                ownership_state=facts.service_bus_customer_managed_key_state,
                uncertainties=uncertainties,
                allowed_reference_kinds=_URI_REFERENCE_KINDS,
                allowed_reference_suffixes=_URI_REFERENCE_SUFFIXES,
            )
        if source.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
            return _alternate_dependency_inputs(
                dependent=dependent,
                source=source,
                fields=(
                    (
                        ("customer_managed_key", 0, "key_vault_key_id"),
                        source_facts.service_bus_key_vault_key_id_reference,
                    ),
                    (
                        ("customer_managed_key", 0, "key_vault_key_uri"),
                        source_facts.service_bus_key_vault_key_uri_reference,
                    ),
                ),
                ownership_state=facts.service_bus_customer_managed_key_state,
                uncertainties=source_facts.service_bus_posture_uncertainties,
                allowed_reference_kinds=_URI_REFERENCE_KINDS,
                allowed_reference_suffixes=_URI_REFERENCE_SUFFIXES,
            )
        return [], [f"customer-managed key source {source.address} has unsupported type {source.resource_type}"]

    if dependent.resource_type == AzureResourceType.COSMOSDB_ACCOUNT:
        paths = (("key_vault_key_id",),)
        uncertainties = _matching_uncertainties(
            facts.cosmosdb_posture_uncertainties,
            ("key_vault_key_id",),
        )
        return _single_dependency_inputs(
            dependent=dependent,
            source=dependent,
            configuration_path=paths[0],
            resolution_paths=paths,
            configured_reference=facts.cosmosdb_key_vault_key_id,
            ownership_state=facts.cosmosdb_customer_managed_key_state,
            uncertainties=uncertainties,
            allowed_reference_kinds=_VERSIONLESS_URI_REFERENCE_KINDS,
            allowed_reference_suffixes=_VERSIONLESS_URI_REFERENCE_SUFFIXES,
        )

    if dependent.resource_type == AzureResourceType.CONTAINER_REGISTRY:
        paths = (("encryption", 0, "key_vault_key_id"),)
        uncertainties = _matching_uncertainties(
            facts.container_registry_posture_uncertainties,
            ("encryption", "key_vault_key_id"),
        )
        return _single_dependency_inputs(
            dependent=dependent,
            source=dependent,
            configuration_path=paths[0],
            resolution_paths=paths,
            configured_reference=facts.container_registry_key_vault_key_id,
            ownership_state=facts.container_registry_customer_managed_key_state,
            uncertainties=uncertainties,
            allowed_reference_kinds=_URI_REFERENCE_KINDS,
            allowed_reference_suffixes=_URI_REFERENCE_SUFFIXES,
        )

    if dependent.resource_type == AzureResourceType.KUBERNETES_CLUSTER:
        paths = (("key_management_service", 0, "key_vault_key_id"),)
        uncertainties = _matching_uncertainties(
            facts.aks_posture_uncertainties,
            ("key_management_service", "key_vault_key_id"),
        )
        return _single_dependency_inputs(
            dependent=dependent,
            source=dependent,
            configuration_path=paths[0],
            resolution_paths=paths,
            configured_reference=facts.aks_kms_key_vault_key_id,
            ownership_state=facts.aks_kms_state,
            uncertainties=uncertainties,
            allowed_reference_kinds=_URI_REFERENCE_KINDS,
            allowed_reference_suffixes=_URI_REFERENCE_SUFFIXES,
        )

    return [], []


def _single_dependency_inputs(
    *,
    dependent: NormalizedResource,
    source: NormalizedResource,
    configuration_path: TerraformExpressionPath,
    resolution_paths: tuple[TerraformExpressionPath, ...],
    configured_reference: str | None,
    ownership_state: str | None,
    uncertainties: Sequence[str],
    allowed_reference_kinds: frozenset[AzureKeyVaultDependencyReferenceKind],
    allowed_reference_suffixes: frozenset[str],
) -> tuple[list[_DependencyInput], list[str]]:
    dependency = _input_if_relevant(
        dependent=dependent,
        source=source,
        configuration_path=configuration_path,
        resolution_paths=resolution_paths,
        configured_reference=configured_reference,
        ownership_state=ownership_state,
        source_uncertainties=uncertainties,
        allowed_reference_kinds=allowed_reference_kinds,
        allowed_reference_suffixes=allowed_reference_suffixes,
    )
    if dependency is None:
        return [], list(uncertainties)
    return [dependency], [
        uncertainty for uncertainty in uncertainties if uncertainty not in dependency.source_uncertainties
    ]


def _alternate_dependency_inputs(
    *,
    dependent: NormalizedResource,
    source: NormalizedResource,
    fields: tuple[
        tuple[TerraformExpressionPath, str | None],
        tuple[TerraformExpressionPath, str | None],
    ],
    ownership_state: str | None,
    uncertainties: Sequence[str],
    allowed_reference_kinds: frozenset[AzureKeyVaultDependencyReferenceKind],
    allowed_reference_suffixes: frozenset[str],
) -> tuple[list[_DependencyInput], list[str]]:
    inputs: list[_DependencyInput] = []
    consumed_uncertainties: set[str] = set()
    for path, configured_reference in fields:
        path_uncertainties = _matching_path_uncertainties(uncertainties, path)
        dependency = _input_if_relevant(
            dependent=dependent,
            source=source,
            configuration_path=path,
            resolution_paths=(path,),
            configured_reference=configured_reference,
            ownership_state=ownership_state,
            source_uncertainties=path_uncertainties,
            allowed_reference_kinds=allowed_reference_kinds,
            allowed_reference_suffixes=allowed_reference_suffixes,
            unknown_ownership_establishes_relevance=False,
        )
        if dependency is None:
            continue
        inputs.append(dependency)
        consumed_uncertainties.update(path_uncertainties)

    if len(inputs) > 1:
        inputs = [replace(dependency, source_evidence_ambiguous=True) for dependency in inputs]
    return inputs, [uncertainty for uncertainty in uncertainties if uncertainty not in consumed_uncertainties]


def _input_if_relevant(
    *,
    dependent: NormalizedResource,
    source: NormalizedResource,
    configuration_path: TerraformExpressionPath,
    resolution_paths: tuple[TerraformExpressionPath, ...],
    configured_reference: str | None,
    ownership_state: str | None,
    source_uncertainties: Sequence[str],
    allowed_reference_kinds: frozenset[AzureKeyVaultDependencyReferenceKind],
    allowed_reference_suffixes: frozenset[str],
    unknown_ownership_establishes_relevance: bool = True,
) -> _DependencyInput | None:
    if (
        configured_reference is None
        and not _has_matching_resolution(source, resolution_paths)
        and not source_uncertainties
        and (ownership_state != STATE_UNKNOWN or not unknown_ownership_establishes_relevance)
    ):
        return None
    return _DependencyInput(
        dependent=dependent,
        source=source,
        configuration_path=configuration_path,
        resolution_paths=resolution_paths,
        configured_reference=configured_reference,
        ownership_state=ownership_state,
        source_uncertainties=tuple(source_uncertainties),
        allowed_reference_kinds=allowed_reference_kinds,
        allowed_reference_suffixes=allowed_reference_suffixes,
    )


def _dependency_record(
    dependency_input: _DependencyInput,
    *,
    native_index: ResourceReferenceIndex,
    resources_by_address: Mapping[str, NormalizedResource],
) -> AzureKeyVaultEncryptionDependency:
    evidence = _resolve_dependency(
        dependency_input,
        native_index=native_index,
        resources_by_address=resources_by_address,
    )
    selected_key = evidence.selected_key
    key_facts = azure_facts(selected_key) if selected_key is not None else None
    resolutions = _matching_resolutions(
        dependency_input.source,
        dependency_input.resolution_paths,
    )
    configuration_path = resolutions[0].path if len(resolutions) == 1 else dependency_input.configuration_path
    key_vault_address = key_facts.resolved_key_vault_address if key_facts is not None else None
    vault = resources_by_address.get(key_vault_address) if key_vault_address is not None else None
    vault_facts = azure_facts(vault) if vault is not None else None
    key_versionless_uri = key_facts.key_vault_key_versionless_uri if key_facts is not None else None
    key_versionless_resource_id = key_facts.key_vault_key_versionless_resource_id if key_facts is not None else None
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
        "customer_managed_key_state": dependency_input.ownership_state,
        "candidate_key_addresses": [candidate.address for candidate in evidence.candidates],
        "target_kind": evidence.target_kind,
        "key_address": selected_key.address if selected_key is not None else None,
        "key_vault_address": key_vault_address,
        "key_vault_id": (
            (vault_facts.key_vault_id if vault_facts is not None else None)
            or _vault_id_from_key_resource_id(key_versionless_resource_id)
        ),
        "key_vault_uri": (
            (vault_facts.key_vault_uri if vault_facts is not None else None)
            or _vault_uri_from_key_uri(key_versionless_uri)
        ),
        "key_name": (key_facts.key_vault_key_name if key_facts is not None else None),
        "key_version": (key_facts.key_vault_key_version if key_facts is not None else None),
        "key_uri": (key_facts.key_vault_key_uri if key_facts is not None else None),
        "key_versionless_uri": key_versionless_uri,
        "key_resource_id": (key_facts.key_vault_key_resource_id if key_facts is not None else None),
        "key_versionless_resource_id": key_versionless_resource_id,
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
    concrete_reference = configured_reference is not None and not _is_symbolic_placeholder(
        configured_reference, resolutions
    )
    if concrete_reference:
        assert configured_reference is not None
        native_evidence = _resolve_native_reference(
            configured_reference,
            dependency_input,
            native_index=native_index,
        )
        if resolutions and native_evidence.state == "resolved":
            symbolic_evidence = _resolve_configuration_references(
                resolutions,
                dependency_input,
                resources_by_address=resources_by_address,
            )
            evidence = _reconcile_concrete_and_symbolic(
                native_evidence,
                symbolic_evidence,
                dependency_input,
            )
        else:
            evidence = native_evidence
    elif resolutions:
        evidence = _resolve_configuration_references(
            resolutions,
            dependency_input,
            resources_by_address=resources_by_address,
        )
    elif configured_reference:
        evidence = _resolve_native_reference(
            configured_reference,
            dependency_input,
            native_index=native_index,
        )
    else:
        evidence = _unresolved_evidence(
            state="unresolved",
            provenance=None,
            reference_kind=None,
            configured_reference=None,
            candidates=(),
            target_kind=None,
            uncertainties=(*(dependency_input.source_uncertainties or ("Key Vault key reference is unresolved",)),),
        )
    return _apply_source_evidence_ambiguity(evidence, dependency_input)


def _reconcile_concrete_and_symbolic(
    concrete: _ResolutionEvidence,
    symbolic: _ResolutionEvidence,
    dependency_input: _DependencyInput,
) -> _ResolutionEvidence:
    concrete_key = concrete.selected_key
    symbolic_key = symbolic.selected_key
    if symbolic.state != "resolved" or symbolic_key is None:
        return concrete
    if (
        concrete_key is not None
        and concrete_key.address == symbolic_key.address
        and concrete.target_kind == symbolic.target_kind
    ):
        return concrete
    candidates = tuple(
        sorted(
            {candidate.address: candidate for candidate in (*concrete.candidates, *symbolic.candidates)}.values(),
            key=lambda candidate: candidate.address,
        )
    )
    return _unresolved_evidence(
        state="ambiguous",
        provenance="planned_value",
        reference_kind=concrete.reference_kind,
        configured_reference=concrete.configured_reference,
        candidates=candidates,
        target_kind=None,
        uncertainties=(
            "Concrete Key Vault key identity conflicts with symbolic "
            f"configuration evidence at {list(dependency_input.configuration_path)}",
            *concrete.uncertainties,
            *symbolic.uncertainties,
        ),
    )


def _apply_source_evidence_ambiguity(
    evidence: _ResolutionEvidence,
    dependency_input: _DependencyInput,
) -> _ResolutionEvidence:
    if not dependency_input.source_evidence_ambiguous:
        return evidence
    return _unresolved_evidence(
        state="ambiguous",
        provenance=evidence.provenance,
        reference_kind=evidence.reference_kind,
        configured_reference=evidence.configured_reference,
        candidates=evidence.candidates,
        target_kind=evidence.target_kind,
        uncertainties=(
            "Multiple alternate Key Vault key fields contain relationship "
            "evidence; no exact source field is authoritative",
            *evidence.uncertainties,
        ),
    )


def _is_symbolic_placeholder(
    configured_reference: str,
    resolutions: Sequence[TerraformReferenceResolution],
) -> bool:
    normalized = configured_reference.strip()
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


def _resolve_native_reference(
    reference: str,
    dependency_input: _DependencyInput,
    *,
    native_index: ResourceReferenceIndex,
) -> _ResolutionEvidence:
    normalized = reference.strip()
    reference_kind = _native_reference_kind(normalized)
    candidates = tuple(
        candidate for candidate in native_index.candidates(normalized) if candidate.resource_type == _KEY
    )
    target_kind = _target_kind_for_reference_kind(reference_kind)
    if reference_kind is None or reference_kind not in dependency_input.allowed_reference_kinds:
        return _unresolved_evidence(
            state="unsupported",
            provenance="planned_value",
            reference_kind=reference_kind,
            configured_reference=normalized,
            candidates=candidates,
            target_kind=target_kind,
            uncertainties=(
                f"Key Vault key reference {normalized} has an unsupported identity "
                f"shape for {dependency_input.source.resource_type}",
                *dependency_input.source_uncertainties,
            ),
        )
    if len(candidates) > 1:
        return _unresolved_evidence(
            state="ambiguous",
            provenance="planned_value",
            reference_kind=reference_kind,
            configured_reference=normalized,
            candidates=candidates,
            target_kind=target_kind,
            uncertainties=(
                f"Key Vault key reference {normalized} matches multiple modeled keys",
                *dependency_input.source_uncertainties,
            ),
        )
    if not candidates:
        return _unresolved_evidence(
            state="unresolved",
            provenance="planned_value",
            reference_kind=reference_kind,
            configured_reference=normalized,
            candidates=(),
            target_kind=target_kind,
            uncertainties=(
                f"Key Vault key reference {normalized} does not resolve to a modeled key",
                *dependency_input.source_uncertainties,
            ),
        )
    return _select_key_candidate(
        candidates[0],
        candidates=candidates,
        configured_reference=normalized,
        provenance="planned_value",
        reference_kind=reference_kind,
        target_kind=target_kind,
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
    target_kinds: set[AzureKeyVaultDependencyTargetKind] = set()
    reasons: list[str] = []
    ambiguous = False
    unsupported = False
    unresolved = False

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
            if candidate is None or candidate.resource_type != _KEY:
                unsupported = True
                reasons.append(f"Terraform target {target.address} is not a modeled Key Vault key")
                continue
            candidates.setdefault(candidate.address, candidate)
            target_references.setdefault(candidate.address, target.reference)
            target_kind = _target_kind_for_reference_suffix(target.reference)
            if target_kind is not None:
                target_kinds.add(target_kind)
            if not _reference_has_suffix(
                target.reference,
                dependency_input.allowed_reference_suffixes,
            ):
                unsupported = True
                reasons.append(
                    f"Terraform target reference {target.reference} is unsupported "
                    f"for {dependency_input.source.resource_type}"
                )

    ordered_candidates = tuple(sorted(candidates.values(), key=lambda candidate: candidate.address))
    target_kind = next(iter(target_kinds)) if len(target_kinds) == 1 else None
    configured_reference = target_references[ordered_candidates[0].address] if len(ordered_candidates) == 1 else None
    if ambiguous or len(ordered_candidates) > 1:
        return _unresolved_evidence(
            state="ambiguous",
            provenance="configuration_reference",
            reference_kind="terraform_reference",
            configured_reference=configured_reference,
            candidates=ordered_candidates,
            target_kind=target_kind,
            uncertainties=(
                "Terraform configuration reference has multiple modeled Key Vault key targets",
                *reasons,
                *dependency_input.source_uncertainties,
            ),
        )
    if unsupported or len(target_kinds) > 1:
        return _unresolved_evidence(
            state="unsupported",
            provenance="configuration_reference",
            reference_kind="terraform_reference",
            configured_reference=configured_reference,
            candidates=ordered_candidates,
            target_kind=target_kind,
            uncertainties=(
                *(
                    reasons
                    or ["Terraform configuration reference uses unsupported Key Vault key relationship evidence"]
                ),
                *dependency_input.source_uncertainties,
            ),
        )
    if unresolved or len(ordered_candidates) != 1 or target_kind is None:
        return _unresolved_evidence(
            state="unresolved",
            provenance="configuration_reference",
            reference_kind="terraform_reference",
            configured_reference=configured_reference,
            candidates=ordered_candidates,
            target_kind=target_kind,
            uncertainties=(
                *(reasons or ["Terraform configuration reference does not resolve to a modeled Key Vault key"]),
                *dependency_input.source_uncertainties,
            ),
        )

    candidate = ordered_candidates[0]
    return _select_key_candidate(
        candidate,
        candidates=ordered_candidates,
        configured_reference=target_references[candidate.address],
        provenance="configuration_reference",
        reference_kind="terraform_reference",
        target_kind=target_kind,
        dependency_input=dependency_input,
    )


def _select_key_candidate(
    candidate: NormalizedResource,
    *,
    candidates: tuple[NormalizedResource, ...],
    configured_reference: str,
    provenance: AzureKeyVaultDependencyReferenceProvenance,
    reference_kind: AzureKeyVaultDependencyReferenceKind,
    target_kind: AzureKeyVaultDependencyTargetKind | None,
    dependency_input: _DependencyInput,
) -> _ResolutionEvidence:
    facts = azure_facts(candidate)
    if facts.key_vault_key_identity_state != "resolved" or not _identity_for_target_kind(candidate, target_kind):
        return _unresolved_evidence(
            state="unresolved",
            provenance=provenance,
            reference_kind=reference_kind,
            configured_reference=configured_reference,
            candidates=candidates,
            target_kind=target_kind,
            uncertainties=(
                f"{candidate.address} does not retain the exact provider-native "
                f"{_target_kind_label(target_kind)} identity required by the dependency",
                *dependency_input.source_uncertainties,
            ),
        )
    return _ResolutionEvidence(
        state="resolved",
        provenance=provenance,
        reference_kind=reference_kind,
        configured_reference=configured_reference,
        candidates=candidates,
        target_kind=target_kind,
        selected_key=candidate,
        uncertainties=_applicability_uncertainties(dependency_input),
    )


def _native_key_references(
    resource: NormalizedResource,
) -> tuple[str | None, ...]:
    if resource.resource_type != _KEY:
        return ()
    facts = azure_facts(resource)
    if facts.key_vault_key_identity_state != "resolved":
        return ()
    return (
        facts.key_vault_key_uri,
        facts.key_vault_key_versionless_uri,
        facts.key_vault_key_resource_id,
        facts.key_vault_key_versionless_resource_id,
    )


def _native_reference_kind(
    reference: str,
) -> AzureKeyVaultDependencyReferenceKind | None:
    parsed_uri = _parse_key_uri(reference)
    if parsed_uri is not None:
        return "versioned_uri" if parsed_uri else "versionless_uri"
    parsed_resource_id = _parse_key_resource_id(reference)
    if parsed_resource_id is not None:
        return "versioned_resource_id" if parsed_resource_id else "versionless_resource_id"
    if reference.casefold().startswith("azurerm_key_vault_key."):
        return "terraform_reference"
    return None


def _parse_key_uri(reference: str) -> bool | None:
    parsed = urlsplit(reference.strip())
    host = parsed.hostname
    segments = [segment for segment in parsed.path.split("/") if segment]
    if (
        parsed.scheme.casefold() != "https"
        or host is None
        or parsed.netloc.casefold() != host.casefold()
        or parsed.query
        or parsed.fragment
        or len(segments) not in {2, 3}
        or segments[0].casefold() != "keys"
        or not all(_valid_path_segment(segment) for segment in segments[1:])
        or not _is_key_vault_host(host)
    ):
        return None
    return len(segments) == 3


def _parse_key_resource_id(reference: str) -> bool | None:
    segments = [segment for segment in reference.strip().split("/") if segment]
    if (
        len(segments) not in {10, 11}
        or segments[0].casefold() != "subscriptions"
        or segments[2].casefold() != "resourcegroups"
        or segments[4].casefold() != "providers"
        or segments[5].casefold() != "microsoft.keyvault"
        or segments[6].casefold() != "vaults"
        or segments[8].casefold() != "keys"
        or not all(segments[index] for index in (1, 3, 7, 9))
        or not _valid_path_segment(segments[9])
        or (len(segments) == 11 and not _valid_path_segment(segments[10]))
    ):
        return None
    return len(segments) == 11


def _is_key_vault_host(host: str) -> bool:
    normalized = host.casefold().rstrip(".")
    return any(
        normalized.endswith(suffix) and bool(normalized[: -len(suffix)]) and "." not in normalized[: -len(suffix)]
        for suffix in _KEY_VAULT_DNS_SUFFIXES
    )


def _valid_path_segment(value: str) -> bool:
    return bool(value) and all(character.isalnum() or character == "-" for character in value)


def _identity_for_target_kind(
    key: NormalizedResource,
    target_kind: AzureKeyVaultDependencyTargetKind | None,
) -> str | None:
    facts = azure_facts(key)
    if target_kind == "key_version":
        return facts.key_vault_key_uri
    if target_kind == "key":
        return facts.key_vault_key_versionless_uri
    return None


def _target_kind_for_reference_kind(
    reference_kind: AzureKeyVaultDependencyReferenceKind | None,
) -> AzureKeyVaultDependencyTargetKind | None:
    if reference_kind in {"versioned_uri", "versioned_resource_id"}:
        return "key_version"
    if reference_kind in {"versionless_uri", "versionless_resource_id"}:
        return "key"
    return None


def _target_kind_for_reference_suffix(
    reference: str,
) -> AzureKeyVaultDependencyTargetKind | None:
    if reference.endswith((".versionless_id", ".resource_versionless_id")):
        return "key"
    if reference.endswith((".id", ".resource_id")):
        return "key_version"
    return None


def _target_kind_label(
    target_kind: AzureKeyVaultDependencyTargetKind | None,
) -> str:
    if target_kind == "key_version":
        return "versioned Key Vault key"
    if target_kind == "key":
        return "versionless Key Vault key"
    return "Key Vault key"


def _vault_id_from_key_resource_id(reference: str | None) -> str | None:
    if reference is None:
        return None
    return reference.rsplit("/keys/", 1)[0]


def _vault_uri_from_key_uri(reference: str | None) -> str | None:
    if reference is None:
        return None
    return reference.rsplit("/keys/", 1)[0]


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


def _unresolved_evidence(
    *,
    state: AzureKeyVaultDependencyResolutionState,
    provenance: AzureKeyVaultDependencyReferenceProvenance | None,
    reference_kind: AzureKeyVaultDependencyReferenceKind | None,
    configured_reference: str | None,
    candidates: tuple[NormalizedResource, ...],
    target_kind: AzureKeyVaultDependencyTargetKind | None,
    uncertainties: Sequence[str],
) -> _ResolutionEvidence:
    return _ResolutionEvidence(
        state=state,
        provenance=provenance,
        reference_kind=reference_kind,
        configured_reference=configured_reference,
        candidates=candidates,
        target_kind=target_kind,
        selected_key=None,
        uncertainties=tuple(_dedupe(uncertainties)),
    )


def _ownership_state(
    configured_reference: str | None,
    source: NormalizedResource,
    paths: Collection[TerraformExpressionPath],
    uncertainties: Sequence[str],
) -> str:
    if configured_reference is not None:
        return STATE_CONFIGURED
    if _has_matching_resolution(source, paths) or uncertainties:
        return STATE_UNKNOWN
    return STATE_NOT_CONFIGURED


def _applicability_uncertainties(
    dependency_input: _DependencyInput,
) -> tuple[str, ...]:
    terminals = {
        path[-1].casefold() for path in dependency_input.resolution_paths if path and isinstance(path[-1], str)
    }
    return tuple(
        uncertainty
        for uncertainty in dependency_input.source_uncertainties
        if not (
            any(terminal in uncertainty.casefold() for terminal in terminals)
            and "unknown after planning" in uncertainty.casefold()
        )
    )


def _matching_path_uncertainties(
    uncertainties: Sequence[str],
    path: TerraformExpressionPath,
) -> list[str]:
    path_label = ".".join(segment for segment in path if isinstance(segment, str)).casefold()
    return [uncertainty for uncertainty in uncertainties if uncertainty.casefold().startswith(path_label)]


def _matching_uncertainties(
    uncertainties: Sequence[str],
    terms: Collection[str],
) -> list[str]:
    normalized_terms = tuple(term.casefold() for term in terms)
    return [
        uncertainty for uncertainty in uncertainties if any(term in uncertainty.casefold() for term in normalized_terms)
    ]


def _dependency_sort_key(
    dependency: AzureKeyVaultEncryptionDependency,
) -> tuple[str, str, str, str]:
    return (
        dependency["dependent_address"],
        dependency["dependency_source_address"],
        repr(dependency["configuration_path"]),
        dependency["configured_key_reference"] or "",
    )


def _dedupe(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))

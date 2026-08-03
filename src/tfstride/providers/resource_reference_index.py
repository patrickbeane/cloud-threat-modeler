from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from tfstride.models import NormalizedResource

ResourceReferences = Callable[[NormalizedResource], Iterable[str | None]]
ResourceReferenceKey = Callable[[str], str]


def _identity_reference_key(reference: str) -> str:
    return reference


@dataclass(frozen=True, slots=True)
class ResourceReferenceIndex:
    """Preserve every modeled candidate for provider-owned reference resolution."""

    resources_by_reference: Mapping[str, tuple[NormalizedResource, ...]]
    reference_key: ResourceReferenceKey

    def candidates(self, reference: str | None) -> tuple[NormalizedResource, ...]:
        if not reference:
            return ()
        key = self.reference_key(reference)
        if not key:
            return ()
        return self.resources_by_reference.get(key, ())

    def unique_candidate(self, reference: str | None) -> NormalizedResource | None:
        candidates = self.candidates(reference)
        return candidates[0] if len(candidates) == 1 else None


def build_resource_reference_index(
    resources: Iterable[NormalizedResource],
    *,
    references_for_resource: ResourceReferences,
    reference_key: ResourceReferenceKey = _identity_reference_key,
) -> ResourceReferenceIndex:
    grouped: dict[str, dict[str, NormalizedResource]] = {}
    for resource in resources:
        for reference in references_for_resource(resource):
            if not reference:
                continue
            key = reference_key(reference)
            if not key:
                continue
            grouped.setdefault(key, {}).setdefault(resource.address, resource)

    frozen = {
        reference: tuple(sorted(candidates.values(), key=lambda candidate: candidate.address))
        for reference, candidates in grouped.items()
    }
    return ResourceReferenceIndex(
        resources_by_reference=MappingProxyType(frozen),
        reference_key=reference_key,
    )

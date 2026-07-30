from __future__ import annotations

from collections.abc import Collection, Iterable

from tfstride.models import (
    NormalizedResource,
    TerraformExpressionPath,
    TerraformReferenceProvenance,
    TerraformReferenceResolutionState,
)
from tfstride.providers.aws.resource_index import AwsResourceIndex


def symbolic_reference_target(
    resource: NormalizedResource,
    index: AwsResourceIndex,
    *path: str | int,
    expected_resource_types: Collection[str],
    expected_reference_suffixes: Collection[str],
) -> NormalizedResource | None:
    matches = symbolic_reference_targets(
        resource,
        index,
        paths=(tuple(path),),
        expected_resource_types=expected_resource_types,
        expected_reference_suffixes=expected_reference_suffixes,
    )
    return matches[0] if len(matches) == 1 else None


def symbolic_reference_targets(
    resource: NormalizedResource,
    index: AwsResourceIndex,
    *,
    paths: Iterable[TerraformExpressionPath] | None = None,
    path_prefix: TerraformExpressionPath = (),
    terminal_segments: Collection[str] = (),
    expected_resource_types: Collection[str],
    expected_reference_suffixes: Collection[str],
) -> list[NormalizedResource]:
    return [
        candidate
        for _, candidate in symbolic_reference_target_records(
            resource,
            index,
            paths=paths,
            path_prefix=path_prefix,
            terminal_segments=terminal_segments,
            expected_resource_types=expected_resource_types,
            expected_reference_suffixes=expected_reference_suffixes,
        )
    ]


def symbolic_reference_target_records(
    resource: NormalizedResource,
    index: AwsResourceIndex,
    *,
    paths: Iterable[TerraformExpressionPath] | None = None,
    path_prefix: TerraformExpressionPath = (),
    terminal_segments: Collection[str] = (),
    expected_resource_types: Collection[str],
    expected_reference_suffixes: Collection[str],
) -> list[tuple[TerraformExpressionPath, NormalizedResource]]:
    allowed_paths = {tuple(path) for path in paths} if paths is not None else None
    expected_types = set(expected_resource_types)
    reference_suffixes = tuple(expected_reference_suffixes)
    matches: list[tuple[TerraformExpressionPath, NormalizedResource]] = []
    seen: set[tuple[TerraformExpressionPath, str]] = set()

    for resolution in resource.reference_resolutions:
        if resolution.state != TerraformReferenceResolutionState.SYMBOLIC:
            continue
        if resolution.provenance != TerraformReferenceProvenance.CONFIGURATION_REFERENCE:
            continue
        if allowed_paths is not None and resolution.path not in allowed_paths:
            continue
        if path_prefix and resolution.path[: len(path_prefix)] != path_prefix:
            continue
        if terminal_segments and (
            not resolution.path
            or not isinstance(resolution.path[-1], str)
            or resolution.path[-1] not in terminal_segments
        ):
            continue
        if len(resolution.targets) != 1:
            continue

        target = resolution.targets[0]
        if not any(target.reference.endswith(suffix) for suffix in reference_suffixes):
            continue
        candidate = index.resources_by_address.get(target.address)
        if candidate is None or candidate.resource_type not in expected_types:
            continue
        key = (resolution.path, candidate.address)
        if key in seen:
            continue
        seen.add(key)
        matches.append((resolution.path, candidate))

    return matches


def resource_reference_value(resource: NormalizedResource) -> str:
    # A symbolic fallback is an exact Terraform resource relationship, not a
    # substitute ARN or provider-generated identifier.
    return resource.address

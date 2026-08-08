from __future__ import annotations

import re
from collections.abc import Mapping

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.coercion import value_is_unknown
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_mutations import gcp_mutations

_VERSION_PATH_PATTERN = re.compile(r"^(?P<secret>projects/[^/]+/secrets/[^/]+)/versions/(?P<version>[^/]+)$")
_SECRET_PATH_PATTERN = re.compile(r"^projects/(?P<project>[^/]+)/secrets/[^/]+$")


def normalize_secret_manager_secret_version(
    resource: TerraformResource,
) -> NormalizedResource:
    """Normalize SecretVersion identity and lifecycle without retaining payload data."""

    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    version_name = _known_string(values, unknown_values, "name", uncertainties)
    version_id = _known_string(values, unknown_values, "id", uncertainties)
    version_reference = _exact_version_path(version_name) or _exact_version_path(version_id)
    if version_reference is None:
        uncertainties.append("exact Secret Manager version resource name is unresolved")

    secret_reference = _known_string(values, unknown_values, "secret", uncertainties)
    parent_path = _parent_secret_path(version_reference) or _exact_secret_path(secret_reference)
    project = _known_string(values, unknown_values, "project", uncertainties)
    if project is None:
        project = _project_from_secret_path(parent_path)

    version_number = _known_string(values, unknown_values, "version", uncertainties)
    if version_number is None and version_reference is not None:
        match = _VERSION_PATH_PATTERN.fullmatch(version_reference)
        version_number = match.group("version") if match is not None else None
    if version_number is None:
        uncertainties.append("Secret Manager version number is unresolved")

    lifecycle_state = _version_lifecycle_state(
        values,
        unknown_values,
        uncertainties,
    )
    deletion_policy = _known_string(
        values,
        unknown_values,
        "deletion_policy",
        uncertainties,
    )
    if deletion_policy is None and not value_is_unknown(unknown_values.get("deletion_policy")):
        deletion_policy = "DELETE"

    normalized = NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=version_reference or resource.address,
        data_sensitivity="sensitive",
        metadata={
            GcpResourceMetadata.NAME: version_reference,
            GcpResourceMetadata.PROJECT: project,
            GcpResourceMetadata.SECRET_MANAGER_VERSION_REFERENCE: version_reference,
            GcpResourceMetadata.SECRET_MANAGER_VERSION_NUMBER: version_number,
            GcpResourceMetadata.SECRET_MANAGER_VERSION_SECRET_REFERENCE: (secret_reference or parent_path),
            GcpResourceMetadata.SECRET_MANAGER_VERSION_LIFECYCLE_STATE: (lifecycle_state),
            GcpResourceMetadata.SECRET_MANAGER_VERSION_DELETION_POLICY: (deletion_policy),
            GcpResourceMetadata.SECRET_MANAGER_VERSION_POSTURE_UNCERTAINTIES: (_dedupe(uncertainties)),
        },
    )
    gcp_mutations(normalized).set_storage_encrypted(True)
    return normalized


def _version_lifecycle_state(
    values: Mapping[str, object],
    unknown_values: Mapping[str, object],
    uncertainties: list[str],
) -> str:
    if value_is_unknown(unknown_values.get("state")):
        uncertainties.append("state is unknown after planning")
        return "unknown"
    state = _text(values.get("state"))
    if state is not None:
        normalized = state.upper()
        if normalized in {"ENABLED", "DISABLED", "DESTROYED"}:
            return normalized.lower()
        uncertainties.append(f"state {state} is not recognized")
        return "unknown"

    if value_is_unknown(unknown_values.get("destroy_time")):
        uncertainties.append("destroy_time is unknown after planning")
        return "unknown"
    if _text(values.get("destroy_time")) is not None:
        return "destroyed"

    if value_is_unknown(unknown_values.get("enabled")):
        uncertainties.append("enabled is unknown after planning")
        return "unknown"
    enabled = values.get("enabled")
    if enabled is None:
        return "enabled"
    if isinstance(enabled, bool):
        return "enabled" if enabled else "disabled"
    uncertainties.append("enabled is malformed")
    return "unknown"


def _known_string(
    values: Mapping[str, object],
    unknown_values: Mapping[str, object],
    key: str,
    uncertainties: list[str],
) -> str | None:
    if value_is_unknown(unknown_values.get(key)):
        uncertainties.append(f"{key} is unknown after planning")
        return None
    return _text(values.get(key))


def _exact_version_path(value: object) -> str | None:
    text = _text(value)
    if text is None:
        return None
    normalized = text.rstrip("/")
    return normalized if _VERSION_PATH_PATTERN.fullmatch(normalized) is not None else None


def _parent_secret_path(version_path: str | None) -> str | None:
    if version_path is None:
        return None
    match = _VERSION_PATH_PATTERN.fullmatch(version_path)
    return match.group("secret") if match is not None else None


def _exact_secret_path(value: object) -> str | None:
    text = _text(value)
    if text is None:
        return None
    normalized = text.rstrip("/")
    return normalized if _SECRET_PATH_PATTERN.fullmatch(normalized) else None


def _project_from_secret_path(value: str | None) -> str | None:
    if value is None:
        return None
    match = _SECRET_PATH_PATTERN.fullmatch(value)
    return match.group("project") if match is not None else None


def _text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.attributes import GcpAttr, GcpAttribute, GcpValues
from tfstride.providers.gcp.coercion import as_bool, first_item
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer_common import GCP_PROVIDER
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_identifier, resource_name
from tfstride.resource_metadata import MetadataField

_GcsSoftDeleteState = Literal["enabled", "disabled", "unknown", "not_observed"]


def normalize_storage_bucket(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    versioning_values = _first_block(values, GcpAttr.VERSIONING)
    encryption_values = _first_block(values, GcpAttr.ENCRYPTION)
    retention_policy_values = _first_block(values, GcpAttr.RETENTION_POLICY)
    soft_delete_policy_values = _first_block(values, GcpAttr.SOFT_DELETE_POLICY)
    encryption = GcpValues(encryption_values)
    retention_policy = GcpValues(retention_policy_values)
    soft_delete_policy = GcpValues(soft_delete_policy_values)
    default_kms_key_name = first_non_empty(encryption.get(GcpAttr.DEFAULT_KMS_KEY_NAME))
    retention_period_seconds = retention_policy.get(GcpAttr.RETENTION_PERIOD)
    retention_policy_locked = _optional_raw_bool(
        retention_policy_values,
        GcpAttr.IS_LOCKED.key,
    )
    versioning_enabled, versioning_uncertainties = _gcs_versioning_posture(
        versioning_values,
        resource.unknown_values,
    )
    soft_delete_duration, soft_delete_state, soft_delete_uncertainties = _gcs_soft_delete_posture(
        soft_delete_policy,
        resource.unknown_values,
        observed=values.has(GcpAttr.SOFT_DELETE_POLICY),
    )
    metadata: dict[str | MetadataField[Any], Any] = {
        GcpResourceMetadata.NAME: resource_name(resource),
        GcpResourceMetadata.BUCKET_NAME: resource_name(resource),
        GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
        GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
        GcpResourceMetadata.LABELS: values.get(GcpAttr.LABELS),
        GcpResourceMetadata.UNIFORM_BUCKET_LEVEL_ACCESS: as_bool(values.get(GcpAttr.UNIFORM_BUCKET_LEVEL_ACCESS)),
        GcpResourceMetadata.PUBLIC_ACCESS_PREVENTION: values.get(GcpAttr.PUBLIC_ACCESS_PREVENTION),
        GcpResourceMetadata.GCS_VERSIONING_ENABLED: versioning_enabled,
        GcpResourceMetadata.GCS_VERSIONING_CONFIGURATION: versioning_values,
        GcpResourceMetadata.GCS_VERSIONING_UNCERTAINTIES: versioning_uncertainties,
        GcpResourceMetadata.GCS_SOFT_DELETE_RETENTION_DURATION_SECONDS: (soft_delete_duration),
        GcpResourceMetadata.GCS_SOFT_DELETE_STATE: soft_delete_state,
        GcpResourceMetadata.GCS_SOFT_DELETE_POLICY_UNCERTAINTIES: (soft_delete_uncertainties),
        GcpResourceMetadata.GCS_DEFAULT_KMS_KEY_NAME: default_kms_key_name,
        GcpResourceMetadata.GCS_ENCRYPTION_CONFIGURATION: encryption_values,
        GcpResourceMetadata.GCS_RETENTION_PERIOD_SECONDS: retention_period_seconds,
        GcpResourceMetadata.GCS_RETENTION_POLICY_LOCKED: retention_policy_locked,
        GcpResourceMetadata.GCS_RETENTION_POLICY_CONFIGURATION: (retention_policy_values),
        GcpResourceMetadata.GCS_RETENTION_POLICY_UNCERTAINTIES: (
            _retention_policy_uncertainties(resource.unknown_values)
        ),
        "location": values.get(GcpAttr.LOCATION),
        "storage_class": values.get(GcpAttr.STORAGE_CLASS),
        "force_destroy": as_bool(values.get(GcpAttr.FORCE_DESTROY)),
        GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION: bool(default_kms_key_name),
    }
    normalized = NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=resource_identifier(resource),
        data_sensitivity="sensitive",
        metadata=metadata,
    )
    gcp_mutations(normalized).set_storage_encrypted(True)
    return normalized


def _first_block(
    values: GcpValues,
    attribute: GcpAttribute[Any],
) -> dict[str, Any]:
    return first_item(values.get(attribute)) or {}


def _optional_raw_bool(values: Mapping[str, Any], key: str) -> bool | None:
    if key not in values:
        return None
    return as_bool(values.get(key))


def _gcs_versioning_posture(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
) -> tuple[bool | None, list[str]]:
    unknown = unknown_values.get(GcpAttr.VERSIONING.key)
    unknown_block = first_item(unknown)
    if unknown is True or (isinstance(unknown_block, Mapping) and unknown_block.get(GcpAttr.ENABLED.key) is True):
        return None, ["versioning.enabled is unknown after planning"]
    if not values:
        return False, []
    enabled = values.get(GcpAttr.ENABLED.key)
    if isinstance(enabled, bool):
        return enabled, []
    return None, ["versioning.enabled is unresolved after planning"]


def _gcs_soft_delete_posture(
    values: GcpValues,
    unknown_values: Mapping[str, Any],
    *,
    observed: bool,
) -> tuple[int | None, _GcsSoftDeleteState, list[str]]:
    unknown = unknown_values.get(GcpAttr.SOFT_DELETE_POLICY.key)
    unknown_block = first_item(unknown)
    if unknown is True or (
        isinstance(unknown_block, Mapping) and unknown_block.get(GcpAttr.RETENTION_DURATION_SECONDS.key) is True
    ):
        return (
            None,
            "unknown",
            ["soft_delete_policy.retention_duration_seconds is unknown after planning"],
        )
    if not observed:
        return None, "not_observed", []

    duration = values.get(GcpAttr.RETENTION_DURATION_SECONDS)
    if duration is None or duration < 0:
        return (
            None,
            "unknown",
            ["soft_delete_policy.retention_duration_seconds is unresolved after planning"],
        )
    return duration, "enabled" if duration > 0 else "disabled", []


def _retention_policy_uncertainties(
    unknown_values: Mapping[str, Any],
) -> list[str]:
    retention_unknown = unknown_values.get(GcpAttr.RETENTION_POLICY.key)
    if retention_unknown is True:
        return ["retention_policy is unknown after planning"]
    retention_block = first_item(retention_unknown)
    if not isinstance(retention_block, Mapping):
        return []

    uncertainties: list[str] = []
    for field_name in (GcpAttr.RETENTION_PERIOD.key, GcpAttr.IS_LOCKED.key):
        if retention_block.get(field_name) is True:
            uncertainties.append(f"retention_policy.{field_name} is unknown after planning")
    return uncertainties

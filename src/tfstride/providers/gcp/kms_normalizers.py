from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.coercion import STATE_UNKNOWN, value_is_unknown
from tfstride.providers.gcp.attributes import GcpAttr, GcpAttribute, GcpValues
from tfstride.providers.gcp.coercion import as_bool, first_item
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_utils import first_non_empty


def normalize_kms_crypto_key(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    key_ring = first_non_empty(values.get(GcpAttr.KEY_RING))
    name = first_non_empty(values.get(GcpAttr.NAME), resource.name)
    identifier = first_non_empty(values.get(GcpAttr.ID), values.get(GcpAttr.SELF_LINK), name, resource.address)
    rotation_period, posture_uncertainties = _kms_rotation_period(values, resource.unknown_values)
    purpose = values.get(GcpAttr.PURPOSE)
    if value_is_unknown(resource.unknown_values.get(GcpAttr.PURPOSE.key)):
        purpose = None
        posture_uncertainties.append("purpose is unknown after planning")
    destroy_scheduled_duration = _kms_destroy_scheduled_duration(
        values,
        resource.unknown_values,
        posture_uncertainties,
    )
    return _with_storage_encrypted(
        NormalizedResource(
            address=resource.address,
            provider=GCP_PROVIDER,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=identifier,
            data_sensitivity="sensitive",
            metadata={
                GcpResourceMetadata.NAME: name,
                GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
                GcpResourceMetadata.PROJECT: first_non_empty(
                    values.get(GcpAttr.PROJECT),
                    _project_from_resource_path(key_ring),
                ),
                GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE: identifier,
                GcpResourceMetadata.KMS_KEY_RING: key_ring,
                GcpResourceMetadata.KMS_PURPOSE: purpose,
                GcpResourceMetadata.KMS_ROTATION_PERIOD: rotation_period,
                GcpResourceMetadata.KMS_DESTROY_SCHEDULED_DURATION: destroy_scheduled_duration,
                GcpResourceMetadata.KMS_POSTURE_UNCERTAINTIES: posture_uncertainties,
                GcpResourceMetadata.LABELS: values.get(GcpAttr.LABELS),
                "import_only": as_bool(values.get(GcpAttr.IMPORT_ONLY)),
                "skip_initial_version_creation": as_bool(values.get(GcpAttr.SKIP_INITIAL_VERSION_CREATION)),
            },
        )
    )


def normalize_kms_crypto_key_version(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    uncertainties: list[str] = []
    crypto_key_reference = _known_kms_version_string(
        values,
        resource.unknown_values,
        GcpAttr.CRYPTO_KEY,
        uncertainties,
    )
    version_name = _known_kms_version_string(
        values,
        resource.unknown_values,
        GcpAttr.NAME,
        uncertainties,
    )
    version_id = _known_kms_version_string(
        values,
        resource.unknown_values,
        GcpAttr.ID,
        uncertainties,
    )
    version_reference = first_non_empty(version_name, version_id)
    key_path = _kms_key_path_from_version(version_reference) or _kms_key_path(crypto_key_reference)
    key_ring = _kms_key_ring_from_key_path(key_path)
    version_number = _kms_version_number(version_reference)
    state = _known_kms_version_string(values, resource.unknown_values, GcpAttr.STATE, uncertainties)
    algorithm = _known_kms_version_string(
        values,
        resource.unknown_values,
        GcpAttr.CRYPTO_KEY_VERSION_ALGORITHM,
        uncertainties,
    )
    protection_level = _known_kms_version_string(
        values,
        resource.unknown_values,
        GcpAttr.CRYPTO_KEY_VERSION_PROTECTION_LEVEL,
        uncertainties,
    )
    generate_time = _known_kms_version_string(
        values,
        resource.unknown_values,
        GcpAttr.CRYPTO_KEY_VERSION_GENERATE_TIME,
        uncertainties,
    )
    external_options = _kms_version_external_options(values, resource.unknown_values, uncertainties)
    deletion_policy = _known_kms_version_string(
        values,
        resource.unknown_values,
        GcpAttr.DELETION_POLICY,
        uncertainties,
    )
    if deletion_policy is None and not value_is_unknown(resource.unknown_values.get(GcpAttr.DELETION_POLICY.key)):
        deletion_policy = "DELETE"
    deletion_policy_state = _kms_version_deletion_policy_state(deletion_policy)
    import_posture = _kms_version_import_posture(
        state=state,
        protection_level=protection_level,
        generate_time=generate_time,
        external_options=external_options,
        uncertainties=uncertainties,
    )
    return _with_storage_encrypted(
        NormalizedResource(
            address=resource.address,
            provider=GCP_PROVIDER,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=version_reference or resource.address,
            data_sensitivity="sensitive",
            metadata={
                GcpResourceMetadata.NAME: version_name,
                GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
                GcpResourceMetadata.PROJECT: _project_from_resource_path(key_path),
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_REFERENCE: version_reference,
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_NAME: version_name,
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_NUMBER: version_number,
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_CRYPTO_KEY_REFERENCE: crypto_key_reference,
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_CRYPTO_KEY_PATH: key_path,
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_KEY_RING: key_ring,
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_PURPOSE: None,
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_ALGORITHM: algorithm,
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_PROTECTION_LEVEL: protection_level,
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_STATE: state,
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_IMPORT_POSTURE: import_posture,
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_GENERATE_TIME: generate_time,
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_EXTERNAL_KEY_URI: first_non_empty(
                    external_options.get("external_key_uri")
                ),
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_EKM_CONNECTION_KEY_PATH: first_non_empty(
                    external_options.get("ekm_connection_key_path")
                ),
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_EXTERNAL_PROTECTION_LEVEL_OPTIONS: external_options,
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_ROTATION_PERIOD: None,
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_DESTROY_SCHEDULED_DURATION: None,
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_DELETION_POLICY: deletion_policy,
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_DELETION_POLICY_STATE: deletion_policy_state,
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_POSTURE_UNCERTAINTIES: uncertainties,
            },
        )
    )


def _kms_rotation_period(values: GcpValues, unknown_values: Mapping[str, Any]) -> tuple[str | None, list[str]]:
    if value_is_unknown(unknown_values.get(GcpAttr.ROTATION_PERIOD.key)):
        return None, ["rotation_period is unknown after planning"]
    return values.get(GcpAttr.ROTATION_PERIOD), []


def _kms_destroy_scheduled_duration(
    values: GcpValues,
    unknown_values: Mapping[str, Any],
    uncertainties: list[str],
) -> str | None:
    if value_is_unknown(unknown_values.get(GcpAttr.DESTROY_SCHEDULED_DURATION.key)):
        uncertainties.append("destroy_scheduled_duration is unknown after planning")
        return None
    value = values.raw(GcpAttr.DESTROY_SCHEDULED_DURATION)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _known_kms_version_string(
    values: GcpValues,
    unknown_values: Mapping[str, Any],
    attribute: GcpAttribute[str | None],
    uncertainties: list[str],
) -> str | None:
    if value_is_unknown(unknown_values.get(attribute.key)):
        uncertainties.append(f"{attribute.key} is unknown after planning")
        return None
    return values.get(attribute)


def _kms_key_path(value: str | None) -> str | None:
    if not value:
        return None
    parts = value.strip("/").split("/")
    if len(parts) != 8 or parts[0] != "projects" or parts[2] != "locations":
        return None
    if parts[4] != "keyRings" or parts[6] != "cryptoKeys" or not all(parts[1::2]):
        return None
    return "/".join(parts)


def _kms_key_path_from_version(value: str | None) -> str | None:
    if not value:
        return None
    parts = value.strip("/").split("/")
    if len(parts) != 10 or parts[0] != "projects" or parts[2] != "locations":
        return None
    if parts[4] != "keyRings" or parts[6] != "cryptoKeys" or parts[8] != "cryptoKeyVersions":
        return None
    if not all(parts[1::2]):
        return None
    return "/".join(parts[:8])


def _kms_key_ring_from_key_path(value: str | None) -> str | None:
    if not value:
        return None
    marker = "/cryptoKeys/"
    return value.rsplit(marker, 1)[0] if marker in value else None


def _kms_version_number(value: str | None) -> str | None:
    if not value:
        return None
    marker = "/cryptoKeyVersions/"
    if marker in value:
        suffix = value.rsplit(marker, 1)[1]
        return suffix if suffix and "/" not in suffix else None
    return value if value.isdigit() else None


def _kms_version_external_options(
    values: GcpValues,
    unknown_values: Mapping[str, Any],
    uncertainties: list[str],
) -> dict[str, Any]:
    attribute = GcpAttr.EXTERNAL_PROTECTION_LEVEL_OPTIONS
    unknown_blocks = unknown_values.get(attribute.key)
    if unknown_blocks is True:
        uncertainties.append(f"{attribute.key} is unknown after planning")
        return {}
    raw = values.raw(attribute)
    if raw in (None, [], {}):
        return {}
    blocks = raw if isinstance(raw, list) else [raw]
    block = next((item for item in blocks if isinstance(item, Mapping)), None)
    if block is None:
        uncertainties.append(f"{attribute.key} has an unrecognized value shape")
        return {}
    normalized = dict(cast(Mapping[str, Any], block))
    unknown_block = first_item(unknown_blocks)
    if isinstance(unknown_block, Mapping):
        for field in ("external_key_uri", "ekm_connection_key_path"):
            if value_is_unknown(unknown_block.get(field)):
                uncertainties.append(f"{attribute.key}.{field} is unknown after planning")
                normalized.pop(field, None)
    external_key_uri = first_non_empty(normalized.get("external_key_uri"))
    ekm_connection_key_path = first_non_empty(normalized.get("ekm_connection_key_path"))
    if external_key_uri and ekm_connection_key_path:
        uncertainties.append(f"{attribute.key} configures both external_key_uri and ekm_connection_key_path")
    return normalized


def _kms_version_import_posture(
    *,
    state: str | None,
    protection_level: str | None,
    generate_time: str | None,
    external_options: Mapping[str, Any],
    uncertainties: list[str],
) -> str:
    normalized_state = str(state or "").strip().upper()
    if any("state is unknown after planning" in uncertainty for uncertainty in uncertainties):
        return STATE_UNKNOWN
    if normalized_state == "PENDING_IMPORT":
        return "import_pending"
    if normalized_state == "IMPORT_FAILED":
        return "import_failed"
    if any(
        "protection_level is unknown after planning" in uncertainty
        or "external_protection_level_options" in uncertainty
        for uncertainty in uncertainties
    ):
        return STATE_UNKNOWN
    if external_options or str(protection_level or "").strip().upper() in {"EXTERNAL", "EXTERNAL_VPC"}:
        return "external_protection"
    if any("generate_time is unknown after planning" in uncertainty for uncertainty in uncertainties):
        return STATE_UNKNOWN
    if generate_time:
        return "generated"
    return STATE_UNKNOWN


def _kms_version_deletion_policy_state(policy: str | None) -> str:
    normalized = str(policy or "").strip().upper()
    if normalized == "PREVENT":
        return "prevent"
    if normalized == "ABANDON":
        return "abandon"
    if normalized == "DELETE":
        return "delete"
    return STATE_UNKNOWN


def _with_storage_encrypted(resource: NormalizedResource) -> NormalizedResource:
    gcp_mutations(resource).set_storage_encrypted(True)
    return resource


def _project_from_resource_path(value: object) -> str | None:
    text = first_non_empty(value)
    if text is None:
        return None
    parts = text.split("/")
    try:
        project_index = parts.index("projects") + 1
    except ValueError:
        return None
    if project_index >= len(parts):
        return None
    return first_non_empty(parts[project_index])

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
    first_non_empty,
    known_string,
    value_is_unknown,
)
from tfstride.providers.gcp.attributes import GcpAttr, GcpValues
from tfstride.providers.gcp.coercion import first_item
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.resource_metadata import MetadataField


def normalize_firestore_database(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    uncertainties: list[str] = []
    database_name = known_string(
        resource.values,
        resource.unknown_values,
        GcpAttr.NAME.key,
        uncertainties,
        require_string=True,
    )
    database_id = known_string(
        resource.values,
        resource.unknown_values,
        GcpAttr.ID.key,
        uncertainties,
        require_string=True,
    )
    database_type = known_string(
        resource.values,
        resource.unknown_values,
        GcpAttr.TYPE.key,
        uncertainties,
        require_string=True,
    )
    location = known_string(
        resource.values,
        resource.unknown_values,
        GcpAttr.LOCATION_ID.key,
        uncertainties,
        require_string=True,
    )
    project = known_string(
        resource.values,
        resource.unknown_values,
        GcpAttr.PROJECT.key,
        uncertainties,
        require_string=True,
    )
    cmek_config, cmek_key_name, cmek_state = _cmek_posture(resource, values, uncertainties)
    pitr_enablement, pitr_state = _enum_posture(
        resource.values,
        resource.unknown_values,
        GcpAttr.POINT_IN_TIME_RECOVERY_ENABLEMENT,
        enabled_values={"POINT_IN_TIME_RECOVERY_ENABLED"},
        disabled_values={"POINT_IN_TIME_RECOVERY_DISABLED"},
        uncertainties=uncertainties,
    )
    delete_protection_state, delete_protection_enablement = _enum_posture(
        resource.values,
        resource.unknown_values,
        GcpAttr.DELETE_PROTECTION_STATE,
        enabled_values={"DELETE_PROTECTION_ENABLED"},
        disabled_values={"DELETE_PROTECTION_DISABLED"},
        not_configured_values={"DELETE_PROTECTION_STATE_UNSPECIFIED"},
        uncertainties=uncertainties,
    )
    terraform_deletion_policy, terraform_deletion_policy_state = _configured_value(
        resource.values,
        resource.unknown_values,
        GcpAttr.DELETION_POLICY,
        uncertainties,
    )
    identifier = first_non_empty(database_id, database_name, resource.address) or resource.address
    metadata: dict[str | MetadataField[Any], Any] = {
        GcpResourceMetadata.NAME: database_name or resource.name,
        GcpResourceMetadata.PROJECT: project,
        GcpResourceMetadata.FIRESTORE_DATABASE_TYPE: database_type,
        GcpResourceMetadata.FIRESTORE_LOCATION: location,
        GcpResourceMetadata.FIRESTORE_CMEK_KEY_NAME: cmek_key_name,
        GcpResourceMetadata.FIRESTORE_CMEK_STATE: cmek_state,
        GcpResourceMetadata.FIRESTORE_CMEK_CONFIG: cmek_config,
        GcpResourceMetadata.FIRESTORE_PITR_ENABLEMENT: pitr_enablement,
        GcpResourceMetadata.FIRESTORE_PITR_STATE: pitr_state,
        GcpResourceMetadata.FIRESTORE_DELETE_PROTECTION_STATE: delete_protection_state,
        GcpResourceMetadata.FIRESTORE_DELETE_PROTECTION_ENABLEMENT: delete_protection_enablement,
        GcpResourceMetadata.FIRESTORE_TERRAFORM_DELETION_POLICY: terraform_deletion_policy,
        GcpResourceMetadata.FIRESTORE_TERRAFORM_DELETION_POLICY_STATE: terraform_deletion_policy_state,
        GcpResourceMetadata.FIRESTORE_POSTURE_UNCERTAINTIES: uncertainties,
    }
    if cmek_state in {STATE_CONFIGURED, STATE_NOT_CONFIGURED}:
        metadata[GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION] = cmek_state == STATE_CONFIGURED
    normalized = NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=identifier,
        data_sensitivity="sensitive",
        metadata=metadata,
    )
    gcp_mutations(normalized).set_storage_encrypted(True)
    return normalized


def _cmek_posture(
    resource: TerraformResource,
    values: GcpValues,
    uncertainties: list[str],
) -> tuple[dict[str, Any], str | None, str]:
    raw_config = resource.values.get(GcpAttr.CMEK_CONFIG.key)
    unknown_config = resource.unknown_values.get(GcpAttr.CMEK_CONFIG.key)
    config = first_item(values.get(GcpAttr.CMEK_CONFIG))
    if unknown_config is True:
        uncertainties.append("cmek_config is unknown after planning")
        return config or {}, None, STATE_UNKNOWN
    if config is None:
        if value_is_unknown(unknown_config):
            uncertainties.append("cmek_config is unknown after planning")
            return {}, None, STATE_UNKNOWN
        if raw_config not in (None, [], {}):
            uncertainties.append("cmek_config has an unrecognized value shape")
            return {}, None, STATE_UNKNOWN
        return {}, None, STATE_NOT_CONFIGURED

    unknown_block = _first_unknown_mapping(unknown_config)
    if value_is_unknown(_unknown_child(unknown_block, GcpAttr.KMS_KEY_NAME.key)):
        uncertainties.append("cmek_config.kms_key_name is unknown after planning")
        return config, None, STATE_UNKNOWN
    raw_key_name = config.get(GcpAttr.KMS_KEY_NAME.key)
    if raw_key_name is None:
        uncertainties.append("cmek_config.kms_key_name is not represented in the Terraform plan")
        return config, None, STATE_UNKNOWN
    if not isinstance(raw_key_name, str):
        uncertainties.append("cmek_config.kms_key_name has an unrecognized value shape")
        return config, None, STATE_UNKNOWN
    key_name = raw_key_name.strip()
    if not key_name:
        uncertainties.append("cmek_config.kms_key_name is not represented in the Terraform plan")
        return config, None, STATE_UNKNOWN
    return config, key_name, STATE_CONFIGURED


def _enum_posture(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    attribute: Any,
    *,
    enabled_values: set[str],
    disabled_values: set[str],
    not_configured_values: set[str] | None = None,
    uncertainties: list[str],
) -> tuple[str | None, str]:
    if value_is_unknown(unknown_values.get(attribute.key)):
        uncertainties.append(f"{attribute.key} is unknown after planning")
        return None, STATE_UNKNOWN
    if attribute.key not in values or values[attribute.key] is None:
        return None, STATE_NOT_CONFIGURED
    raw_value = values[attribute.key]
    if not isinstance(raw_value, str):
        uncertainties.append(f"{attribute.key} has an unrecognized value shape")
        return None, STATE_UNKNOWN
    value = raw_value.strip()
    if not value:
        return None, STATE_NOT_CONFIGURED
    if value in enabled_values:
        return value, STATE_ENABLED
    if value in disabled_values:
        return value, STATE_DISABLED
    if not_configured_values and value in not_configured_values:
        return value, STATE_NOT_CONFIGURED
    uncertainties.append(f"{attribute.key} has an unrecognized value {value}")
    return value, STATE_UNKNOWN


def _configured_value(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    attribute: Any,
    uncertainties: list[str],
) -> tuple[str | None, str]:
    if value_is_unknown(unknown_values.get(attribute.key)):
        uncertainties.append(f"{attribute.key} is unknown after planning")
        return None, STATE_UNKNOWN
    if attribute.key not in values or values[attribute.key] is None:
        return None, STATE_NOT_CONFIGURED
    raw_value = values[attribute.key]
    if not isinstance(raw_value, str):
        uncertainties.append(f"{attribute.key} has an unrecognized value shape")
        return None, STATE_UNKNOWN
    value = raw_value.strip()
    if not value:
        return None, STATE_NOT_CONFIGURED
    return value, STATE_CONFIGURED


def _first_unknown_mapping(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, list) and value and isinstance(value[0], Mapping):
        return value[0]
    return None


def _unknown_child(value: Mapping[str, Any] | None, key: str) -> Any:
    return value.get(key) if value is not None else None

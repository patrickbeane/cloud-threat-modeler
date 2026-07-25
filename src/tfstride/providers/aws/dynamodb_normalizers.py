from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.network_normalizers import AWS_PROVIDER
from tfstride.providers.aws.resource_mutations import aws_mutations
from tfstride.providers.coercion import (
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
    as_list,
    attribute_unknown,
    first_mapping,
    known_block_bool,
    known_block_int,
    known_block_string,
    known_bool,
    known_string,
)


def normalize_dynamodb_table(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    table_name = known_string(values, unknown_values, "name", uncertainties, require_string=True)
    table_id = known_string(values, unknown_values, "id", uncertainties, require_string=True)
    table_arn = known_string(values, unknown_values, "arn", uncertainties, require_string=True)
    encryption = _server_side_encryption_posture(values, unknown_values, uncertainties)
    pitr_state, pitr_recovery_period_days = _point_in_time_recovery_posture(
        values,
        unknown_values,
        uncertainties,
    )
    deletion_protection_state = _top_level_bool_state(
        values,
        unknown_values,
        "deletion_protection_enabled",
        uncertainties,
    )

    normalized = NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=table_name or table_id or resource.address,
        arn=table_arn,
        data_sensitivity="sensitive",
        metadata={
            AwsResourceMetadata.NAME: table_name or resource.name,
            AwsResourceMetadata.DYNAMODB_TABLE_ARN: table_arn,
            AwsResourceMetadata.DYNAMODB_KMS_KEY_ARN: encryption["kms_key_arn"],
            AwsResourceMetadata.DYNAMODB_ENCRYPTION_OWNERSHIP_STATE: encryption["ownership_state"],
            AwsResourceMetadata.DYNAMODB_ENCRYPTION_CONFIGURATION_STATE: encryption["encryption_configuration_state"],
            AwsResourceMetadata.DYNAMODB_PITR_STATE: pitr_state,
            AwsResourceMetadata.DYNAMODB_PITR_RECOVERY_PERIOD_DAYS: pitr_recovery_period_days,
            AwsResourceMetadata.DYNAMODB_DELETION_PROTECTION_STATE: deletion_protection_state,
            AwsResourceMetadata.DYNAMODB_REPLICAS: _replicas(
                values.get("replica"),
                unknown_values.get("replica"),
                uncertainties,
            ),
            AwsResourceMetadata.DYNAMODB_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )
    # DynamoDB is encrypted at rest by default, including when the table uses an AWS-owned key.
    aws_mutations(normalized).set_storage_encrypted(True)
    return normalized


def _server_side_encryption_posture(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    uncertainties: list[str],
) -> dict[str, str | None]:
    raw_block = values.get("server_side_encryption")
    unknown_block_value = unknown_values.get("server_side_encryption")
    if unknown_block_value is True:
        uncertainties.append("server_side_encryption is unknown after planning")
        return {
            "kms_key_arn": None,
            "ownership_state": STATE_UNKNOWN,
            "encryption_configuration_state": STATE_UNKNOWN,
        }

    block = first_mapping(raw_block, scan_all=True)
    unknown_block = first_mapping(unknown_block_value, scan_all=True)
    if block is None:
        if unknown_block is not None or unknown_block_value not in (None, [], {}):
            uncertainties.append("server_side_encryption is unknown after planning")
            return {
                "kms_key_arn": None,
                "ownership_state": STATE_UNKNOWN,
                "encryption_configuration_state": STATE_UNKNOWN,
            }
        if raw_block not in (None, [], {}):
            uncertainties.append("server_side_encryption has an unrecognized value shape")
            return {
                "kms_key_arn": None,
                "ownership_state": STATE_UNKNOWN,
                "encryption_configuration_state": STATE_UNKNOWN,
            }
        # DynamoDB uses an AWS-owned key when the optional configuration is omitted.
        return {
            "kms_key_arn": None,
            "ownership_state": "aws_owned",
            "encryption_configuration_state": STATE_NOT_CONFIGURED,
        }

    enabled = known_block_bool(
        block,
        unknown_block,
        "enabled",
        uncertainties,
        path="server_side_encryption",
    )
    kms_key_arn = known_block_string(
        block,
        unknown_block,
        "kms_key_arn",
        uncertainties,
        path="server_side_encryption",
    )
    if enabled is None:
        if "enabled" not in block and not attribute_unknown(unknown_block, "enabled"):
            uncertainties.append("server_side_encryption.enabled is not represented in the Terraform plan")
        return {
            "kms_key_arn": kms_key_arn,
            "ownership_state": STATE_UNKNOWN,
            "encryption_configuration_state": STATE_UNKNOWN,
        }
    if enabled is False:
        if kms_key_arn:
            uncertainties.append("server_side_encryption.kms_key_arn is present while enabled is false")
            ownership_state = STATE_UNKNOWN
        else:
            ownership_state = "aws_owned"
        return {
            "kms_key_arn": kms_key_arn,
            "ownership_state": ownership_state,
            "encryption_configuration_state": STATE_DISABLED,
        }
    if kms_key_arn:
        ownership_state = "customer_managed"
    elif attribute_unknown(unknown_block, "kms_key_arn"):
        ownership_state = STATE_UNKNOWN
    else:
        ownership_state = "aws_managed_kms"
    return {
        "kms_key_arn": kms_key_arn,
        "ownership_state": ownership_state,
        "encryption_configuration_state": STATE_ENABLED,
    }


def _point_in_time_recovery_posture(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    uncertainties: list[str],
) -> tuple[str, int | None]:
    raw_block = values.get("point_in_time_recovery")
    unknown_block_value = unknown_values.get("point_in_time_recovery")
    if unknown_block_value is True:
        uncertainties.append("point_in_time_recovery is unknown after planning")
        return STATE_UNKNOWN, None

    block = first_mapping(raw_block, scan_all=True)
    unknown_block = first_mapping(unknown_block_value, scan_all=True)
    if block is None:
        if unknown_block is not None or unknown_block_value not in (None, [], {}):
            uncertainties.append("point_in_time_recovery is unknown after planning")
            return STATE_UNKNOWN, None
        if raw_block not in (None, [], {}):
            uncertainties.append("point_in_time_recovery has an unrecognized value shape")
            return STATE_UNKNOWN, None
        return STATE_NOT_CONFIGURED, None

    enabled = known_block_bool(
        block,
        unknown_block,
        "enabled",
        uncertainties,
        path="point_in_time_recovery",
    )
    recovery_period_days = known_block_int(
        block,
        unknown_block,
        "recovery_period_in_days",
        uncertainties,
        path="point_in_time_recovery",
    )
    if enabled is None:
        if "enabled" not in block and not attribute_unknown(unknown_block, "enabled"):
            uncertainties.append("point_in_time_recovery.enabled is not represented in the Terraform plan")
        return STATE_UNKNOWN, recovery_period_days
    if enabled:
        if (
            recovery_period_days is None
            and block.get("recovery_period_in_days") is None
            and not attribute_unknown(unknown_block, "recovery_period_in_days")
        ):
            recovery_period_days = 35
        return STATE_ENABLED, recovery_period_days
    return STATE_DISABLED, None


def _top_level_bool_state(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    key: str,
    uncertainties: list[str],
) -> str:
    if key not in values and not attribute_unknown(unknown_values, key):
        return STATE_NOT_CONFIGURED
    uncertainty_count = len(uncertainties)
    value = known_bool(values, unknown_values, key, uncertainties, allow_string=False)
    if value is True:
        return STATE_ENABLED
    if value is False:
        return STATE_DISABLED
    return STATE_UNKNOWN if len(uncertainties) > uncertainty_count else STATE_NOT_CONFIGURED


def _replicas(
    value: Any,
    unknown_value: Any,
    uncertainties: list[str],
) -> list[dict[str, Any]]:
    if unknown_value is True:
        uncertainties.append("replica is unknown after planning")
        return []

    replica_blocks = as_list(value)
    unknown_blocks = as_list(unknown_value)
    if not replica_blocks and unknown_value not in (None, [], {}):
        uncertainties.append("replica is unknown after planning")
        return []

    replicas: list[dict[str, Any]] = []
    for index, replica in enumerate(replica_blocks):
        if not isinstance(replica, Mapping):
            uncertainties.append(f"replica[{index}] has an unrecognized value shape")
            continue
        unknown_block = unknown_blocks[index] if index < len(unknown_blocks) else None
        evidence: dict[str, Any] = {}
        unknown_fields: list[str] = []
        for key in ("region_name", "kms_key_arn", "consistency_mode"):
            parsed = known_block_string(
                replica,
                unknown_block,
                key,
                uncertainties,
                path=f"replica[{index}]",
                unknown_fields=unknown_fields,
            )
            if parsed is not None:
                evidence[key] = parsed
        for key in ("point_in_time_recovery", "deletion_protection_enabled"):
            parsed_bool = known_block_bool(
                replica,
                unknown_block,
                key,
                uncertainties,
                path=f"replica[{index}]",
                unknown_fields=unknown_fields,
            )
            if parsed_bool is not None:
                evidence[key] = parsed_bool
        if unknown_fields:
            evidence["unknown_fields"] = sorted(set(unknown_fields))
        if evidence:
            replicas.append(evidence)
    return replicas

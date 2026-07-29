from __future__ import annotations

import json
from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from tfstride.models import IAMPolicyStatement, NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.network_normalizers import AWS_PROVIDER
from tfstride.providers.aws.policy_documents import parse_policy_statements
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
    as_optional_int,
    attribute_unknown,
    first_mapping,
    known_bool,
    known_string,
    known_string_list,
    value_is_unknown,
)


def normalize_kms_key(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    (
        policy_document,
        policy_statements,
        policy_configuration_state,
        policy_completeness_state,
        policy_uncertainties,
    ) = _kms_policy_details(values, unknown_values, uncertainties)
    key_id = known_string(values, unknown_values, "key_id", uncertainties) or known_string(
        values,
        unknown_values,
        "id",
        uncertainties,
    )
    key_arn = known_string(values, unknown_values, "arn", uncertainties)
    policy_source_present = policy_configuration_state in {STATE_CONFIGURED, STATE_UNKNOWN}
    policy_record = (
        {
            "source": resource.address,
            "source_type": "inline",
            "configuration_state": policy_configuration_state,
            "resolved_key_address": resource.address,
            "completeness_state": policy_completeness_state,
            "bypass_lockout_safety_check_state": None,
            "policy_statements": serialize_kms_policy_statements(policy_statements),
            "posture_uncertainties": list(policy_uncertainties),
        }
        if policy_source_present
        else None
    )
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=key_id,
        arn=key_arn,
        policy_statements=policy_statements,
        data_sensitivity="sensitive",
        metadata={
            AwsResourceMetadata.POLICY_DOCUMENT: policy_document,
            AwsResourceMetadata.KMS_KEY_ID: key_id,
            AwsResourceMetadata.KMS_KEY_ARN: key_arn,
            AwsResourceMetadata.KMS_KEY_USAGE: known_string(values, unknown_values, "key_usage", uncertainties),
            AwsResourceMetadata.KMS_KEY_SPEC: known_string(values, unknown_values, "key_spec", uncertainties),
            AwsResourceMetadata.KMS_CUSTOMER_MASTER_KEY_SPEC: known_string(
                values,
                unknown_values,
                "customer_master_key_spec",
                uncertainties,
            ),
            AwsResourceMetadata.KMS_KEY_ORIGIN: known_string(values, unknown_values, "origin", uncertainties),
            AwsResourceMetadata.KMS_MULTI_REGION_STATE: _kms_bool_state(
                values,
                unknown_values,
                "multi_region",
                uncertainties,
            ),
            AwsResourceMetadata.KMS_CUSTOM_KEY_STORE_ID: known_string(
                values,
                unknown_values,
                "custom_key_store_id",
                uncertainties,
            ),
            AwsResourceMetadata.KMS_XKS_KEY_ID: known_string(values, unknown_values, "xks_key_id", uncertainties),
            AwsResourceMetadata.KMS_ENABLE_KEY_ROTATION_STATE: _kms_rotation_state(
                values,
                unknown_values,
                uncertainties,
            ),
            AwsResourceMetadata.KMS_ROTATION_PERIOD_IN_DAYS: _known_top_level_int(
                values,
                unknown_values,
                "rotation_period_in_days",
                uncertainties,
            ),
            AwsResourceMetadata.KMS_DELETION_WINDOW_IN_DAYS: _known_top_level_int(
                values,
                unknown_values,
                "deletion_window_in_days",
                uncertainties,
            ),
            AwsResourceMetadata.KMS_POLICY_CONFIGURATION_STATE: policy_configuration_state,
            AwsResourceMetadata.KMS_POLICY_COMPLETENESS_STATE: policy_completeness_state,
            AwsResourceMetadata.KMS_POLICY_SOURCE_ADDRESSES: [resource.address] if policy_source_present else [],
            AwsResourceMetadata.KMS_POLICY_POSTURE_UNCERTAINTIES: policy_uncertainties,
            AwsResourceMetadata.KMS_KEY_POLICIES: [policy_record] if policy_record is not None else [],
            AwsResourceMetadata.KMS_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_kms_alias(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    alias_name = known_string(values, unknown_values, "name", uncertainties)
    alias_name_prefix = known_string(values, unknown_values, "name_prefix", uncertainties)
    alias_identifier = known_string(values, unknown_values, "id", uncertainties) or alias_name or resource.address
    alias_arn = known_string(values, unknown_values, "arn", uncertainties)
    target_key_id = known_string(values, unknown_values, "target_key_id", uncertainties)
    target_key_arn = known_string(values, unknown_values, "target_key_arn", uncertainties)
    target_key_reference = target_key_id or target_key_arn
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=alias_identifier,
        arn=alias_arn,
        data_sensitivity="sensitive",
        metadata={
            AwsResourceMetadata.KMS_ALIAS_NAME: alias_name,
            AwsResourceMetadata.KMS_ALIAS_NAME_PREFIX: alias_name_prefix,
            AwsResourceMetadata.KMS_ALIAS_ARN: alias_arn,
            AwsResourceMetadata.KMS_ALIAS_TARGET_KEY_ID: target_key_id,
            AwsResourceMetadata.KMS_ALIAS_TARGET_KEY_ARN: target_key_arn,
            AwsResourceMetadata.KMS_ALIAS_TARGET_KEY_REFERENCE: target_key_reference,
            AwsResourceMetadata.KMS_ALIAS_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_kms_grant(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    grant_id = known_string(values, unknown_values, "grant_id", uncertainties)
    if grant_id is None:
        grant_id = known_string(values, unknown_values, "id", uncertainties)
    constraints = _known_grant_constraints(values, unknown_values, uncertainties)
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=grant_id or resource.address,
        data_sensitivity="sensitive",
        metadata={
            AwsResourceMetadata.KMS_GRANT_ID: grant_id,
            AwsResourceMetadata.KMS_GRANT_NAME: known_string(values, unknown_values, "name", uncertainties),
            AwsResourceMetadata.KMS_GRANT_KEY_REFERENCE: known_string(
                values,
                unknown_values,
                "key_id",
                uncertainties,
            ),
            AwsResourceMetadata.KMS_GRANT_GRANTEE_PRINCIPAL: known_string(
                values,
                unknown_values,
                "grantee_principal",
                uncertainties,
            ),
            AwsResourceMetadata.KMS_GRANT_OPERATIONS: known_string_list(
                values,
                unknown_values,
                "operations",
                uncertainties,
            ),
            AwsResourceMetadata.KMS_GRANT_RETIRING_PRINCIPAL: known_string(
                values,
                unknown_values,
                "retiring_principal",
                uncertainties,
            ),
            AwsResourceMetadata.KMS_GRANT_CONSTRAINTS: constraints,
            AwsResourceMetadata.KMS_GRANT_RETIRE_ON_DELETE_STATE: _kms_bool_state(
                values,
                unknown_values,
                "retire_on_delete",
                uncertainties,
            ),
            AwsResourceMetadata.KMS_GRANT_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_kms_key_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    (
        policy_document,
        policy_statements,
        configuration_state,
        completeness_state,
        policy_uncertainties,
    ) = _kms_policy_details(values, unknown_values, uncertainties)
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=known_string(values, unknown_values, "id", uncertainties)
        or known_string(values, unknown_values, "key_id", uncertainties)
        or resource.address,
        policy_statements=policy_statements,
        data_sensitivity="sensitive",
        metadata={
            AwsResourceMetadata.POLICY_DOCUMENT: policy_document,
            AwsResourceMetadata.KMS_KEY_POLICY_KEY_REFERENCE: known_string(
                values,
                unknown_values,
                "key_id",
                uncertainties,
            ),
            AwsResourceMetadata.KMS_POLICY_CONFIGURATION_STATE: configuration_state,
            AwsResourceMetadata.KMS_POLICY_COMPLETENESS_STATE: completeness_state,
            AwsResourceMetadata.KMS_KEY_POLICY_BYPASS_LOCKOUT_SAFETY_CHECK_STATE: _kms_bool_state(
                values,
                unknown_values,
                "bypass_policy_lockout_safety_check",
                uncertainties,
            ),
            AwsResourceMetadata.KMS_KEY_POLICY_POSTURE_UNCERTAINTIES: policy_uncertainties,
        },
    )


def _kms_policy_details(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> tuple[dict[str, Any], tuple[IAMPolicyStatement, ...], str, str, list[str]]:
    policy_uncertainties: list[str] = []

    def add_policy_uncertainty(message: str) -> None:
        uncertainties.append(message)
        policy_uncertainties.append(message)

    if attribute_unknown(unknown_values, "policy"):
        add_policy_uncertainty("policy is unknown after planning")
        return {}, (), STATE_UNKNOWN, STATE_UNKNOWN, policy_uncertainties

    if "policy" not in values or values.get("policy") in (None, ""):
        return {}, (), STATE_NOT_CONFIGURED, STATE_UNKNOWN, policy_uncertainties

    raw_policy = values.get("policy")
    if isinstance(raw_policy, Mapping):
        policy_document = dict(raw_policy)
    elif isinstance(raw_policy, str) and raw_policy.strip():
        try:
            decoded = json.loads(raw_policy)
        except json.JSONDecodeError:
            decoded = None
        if not isinstance(decoded, dict):
            add_policy_uncertainty("policy is not a valid JSON document")
            return {}, (), STATE_CONFIGURED, STATE_UNKNOWN, policy_uncertainties
        policy_document = decoded
    else:
        add_policy_uncertainty("policy has an unrecognized value shape")
        return {}, (), STATE_CONFIGURED, STATE_UNKNOWN, policy_uncertainties

    if not policy_document:
        add_policy_uncertainty("policy is an empty JSON document")
        return policy_document, (), STATE_CONFIGURED, STATE_UNKNOWN, policy_uncertainties

    if "Statement" not in policy_document:
        add_policy_uncertainty("policy statements are missing")
        return policy_document, (), STATE_CONFIGURED, STATE_UNKNOWN, policy_uncertainties

    statement_documents = _policy_statement_documents(policy_document["Statement"])
    if statement_documents is None:
        add_policy_uncertainty("policy statements have an unrecognized value shape")
        return policy_document, (), STATE_CONFIGURED, STATE_UNKNOWN, policy_uncertainties

    policy_statements = tuple(parse_policy_statements(policy_document))
    if len(policy_statements) != len(statement_documents):
        add_policy_uncertainty("one or more policy statements could not be normalized")
        return policy_document, policy_statements, STATE_CONFIGURED, STATE_UNKNOWN, policy_uncertainties

    return policy_document, policy_statements, STATE_CONFIGURED, "complete", policy_uncertainties


def _policy_statement_documents(value: Any) -> list[Mapping[str, Any]] | None:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, list) and all(isinstance(item, Mapping) for item in value):
        return list(value)
    return None


def serialize_kms_policy_statements(statements: tuple[IAMPolicyStatement, ...]) -> list[dict[str, Any]]:
    return [
        {
            "effect": statement.effect,
            "actions": list(statement.actions),
            "resources": list(statement.resources),
            "principals": list(statement.principals),
            "principal_entries": [{"kind": entry.kind, "value": entry.value} for entry in statement.principal_entries],
            "conditions": [
                {"operator": condition.operator, "key": condition.key, "values": list(condition.values)}
                for condition in statement.conditions
            ],
        }
        for statement in statements
    ]


def _known_grant_constraints(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> dict[str, Any]:
    if attribute_unknown(unknown_values, "constraints"):
        uncertainties.append("constraints are unknown after planning")
        return {}

    raw_constraints = values.get("constraints")
    if raw_constraints in (None, [], {}):
        return {}
    unknown_constraints = unknown_values.get("constraints") if isinstance(unknown_values, Mapping) else None
    if value_is_unknown(unknown_constraints):
        uncertainties.append("constraints contain unknown values after planning")
    mapping = first_mapping(raw_constraints, expand_tuples=True)
    if mapping is None:
        uncertainties.append("constraints have an unrecognized value shape")
        return {}
    return deepcopy(dict(mapping))


def _known_top_level_int(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
) -> int | None:
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{key} is unknown after planning")
        return None
    value = values.get(key)
    if value is None:
        return None
    if isinstance(value, bool):
        uncertainties.append(f"{key} has an unrecognized value shape")
        return None
    parsed = as_optional_int(value)
    if parsed is None:
        uncertainties.append(f"{key} has an unrecognized value shape")
    return parsed


def _kms_bool_state(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
) -> str:
    previous_uncertainty_count = len(uncertainties)
    enabled = known_bool(values, unknown_values, key, uncertainties, allow_string=False)
    if enabled is True:
        return STATE_ENABLED
    if enabled is False:
        return STATE_DISABLED
    if len(uncertainties) > previous_uncertainty_count:
        return STATE_UNKNOWN
    return STATE_DISABLED


def _kms_rotation_state(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> str:
    return _kms_bool_state(values, unknown_values, "enable_key_rotation", uncertainties)

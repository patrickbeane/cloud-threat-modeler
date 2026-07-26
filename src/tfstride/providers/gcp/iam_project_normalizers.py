from __future__ import annotations

import json
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.coercion import STATE_CONFIGURED, STATE_NOT_CONFIGURED, STATE_UNKNOWN, attribute_unknown
from tfstride.providers.gcp.attributes import GcpAttr, GcpValues
from tfstride.providers.gcp.coercion import compact
from tfstride.providers.gcp.iam_normalizer_utils import _binding_identifier, _condition, _iam_bindings, _policy_bindings
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer_common import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import first_non_empty
from tfstride.providers.json_documents import load_json_document


def normalize_project_iam_member(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    role = first_non_empty(values.get(GcpAttr.ROLE))
    member = first_non_empty(values.get(GcpAttr.MEMBER))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get(GcpAttr.ID), role and member and f"{role}:{member}", resource.address),
        metadata={
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.IAM_ROLE: role,
            GcpResourceMetadata.IAM_MEMBER: member,
            GcpResourceMetadata.IAM_MEMBERS: compact([member]),
            GcpResourceMetadata.IAM_CONDITION: _condition(values.raw(GcpAttr.CONDITION)),
            GcpResourceMetadata.IAM_BINDINGS: _iam_bindings(
                role,
                compact([member]),
                condition=values.raw(GcpAttr.CONDITION),
                condition_unknown=attribute_unknown(resource.unknown_values, GcpAttr.CONDITION.key),
                role_unknown=attribute_unknown(resource.unknown_values, GcpAttr.ROLE.key),
                members_unknown=attribute_unknown(resource.unknown_values, GcpAttr.MEMBER.key),
            ),
        },
    )


def normalize_project_iam_binding(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    role = first_non_empty(values.get(GcpAttr.ROLE))
    members = values.get(GcpAttr.MEMBERS)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(
            values.get(GcpAttr.ID),
            _binding_identifier(values.get(GcpAttr.PROJECT), role, members),
            resource.address,
        ),
        metadata={
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.IAM_ROLE: role,
            GcpResourceMetadata.IAM_MEMBERS: members,
            GcpResourceMetadata.IAM_CONDITION: _condition(values.raw(GcpAttr.CONDITION)),
            GcpResourceMetadata.IAM_BINDINGS: _iam_bindings(
                role,
                members,
                condition=values.raw(GcpAttr.CONDITION),
                condition_unknown=attribute_unknown(resource.unknown_values, GcpAttr.CONDITION.key),
                role_unknown=attribute_unknown(resource.unknown_values, GcpAttr.ROLE.key),
                members_unknown=attribute_unknown(resource.unknown_values, GcpAttr.MEMBERS.key),
            ),
        },
    )


def normalize_project_iam_policy(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    raw_policy_data = values.raw(GcpAttr.POLICY_DATA)
    policy_document = load_json_document(raw_policy_data)
    bindings = _policy_bindings(policy_document)
    policy_data_state = _policy_data_state(
        raw_policy_data,
        unknown=attribute_unknown(resource.unknown_values, GcpAttr.POLICY_DATA.key),
    )
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get(GcpAttr.ID), values.get(GcpAttr.PROJECT), resource.address),
        metadata={
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.IAM_BINDINGS: bindings,
            GcpResourceMetadata.POLICY_DOCUMENT: policy_document,
            GcpResourceMetadata.IAM_POLICY_DATA_STATE: policy_data_state,
        },
    )


def _policy_data_state(raw_policy_data: Any, *, unknown: bool) -> str:
    if unknown:
        return STATE_UNKNOWN
    if raw_policy_data in (None, ""):
        return STATE_NOT_CONFIGURED
    if isinstance(raw_policy_data, dict):
        return STATE_CONFIGURED
    if isinstance(raw_policy_data, str) and raw_policy_data.strip():
        try:
            parsed = json.loads(raw_policy_data)
        except json.JSONDecodeError:
            return "invalid"
        return STATE_CONFIGURED if isinstance(parsed, dict) else "invalid"
    return "invalid"

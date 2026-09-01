from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from tfstride.models import IAMPolicyStatement, NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.aws.coercion import as_list, compact
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.network_normalizers import AWS_PROVIDER
from tfstride.providers.aws.policy_documents import (
    extract_principals,
    extract_trust_statements,
    parse_policy_statements,
    policy_statement_is_fully_representable,
)
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
    block_attribute_unknown,
    known_string,
    known_string_list,
    unknown_block_at,
    value_is_unknown,
)
from tfstride.providers.json_documents import load_json_document


def normalize_iam_role(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    permissions_boundary_uncertainties: list[str] = []
    permissions_boundary_arn = known_string(
        values,
        resource.unknown_values,
        "permissions_boundary",
        permissions_boundary_uncertainties,
        require_string=True,
    )
    if permissions_boundary_uncertainties:
        permissions_boundary_state = STATE_UNKNOWN
    elif permissions_boundary_arn is not None:
        permissions_boundary_state = STATE_CONFIGURED
    else:
        permissions_boundary_state = STATE_NOT_CONFIGURED
    assume_role_policy = load_json_document(values.get("assume_role_policy"))
    raw_inline_policies = as_list(values.get("inline_policy"))
    statements: list[IAMPolicyStatement] = []
    uncertainties: list[str] = []
    raw_unknown_inline_policies = resource.unknown_values.get("inline_policy")
    complete = raw_unknown_inline_policies is not True
    if not complete:
        uncertainties.append("inline_policy is unknown after planning")

    inline_policy_names: list[str] = []
    for index, raw_inline_policy in enumerate(raw_inline_policies):
        if not isinstance(raw_inline_policy, dict):
            complete = False
            uncertainties.append(f"inline_policy[{index}] has an unrecognized value shape")
            continue
        inline_policy: dict[str, Any] = {str(key): value for key, value in raw_inline_policy.items()}
        name = inline_policy.get("name")
        if name not in (None, ""):
            inline_policy_names.append(str(name))
        unknown_inline_policy = unknown_block_at(
            raw_unknown_inline_policies,
            index,
        )
        policy_statements, _, policy_complete, policy_uncertainties = _iam_policy_details(
            inline_policy.get("policy"),
            unknown=block_attribute_unknown(unknown_inline_policy, "policy"),
            label=f"inline_policy[{index}].policy",
        )
        statements.extend(policy_statements)
        complete = complete and policy_complete
        uncertainties.extend(policy_uncertainties)

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=values.get("name") or values.get("id"),
        arn=values.get("arn"),
        policy_statements=tuple(statements),
        metadata={
            "assume_role_policy": assume_role_policy,
            "trust_principals": extract_principals(assume_role_policy),
            AwsResourceMetadata.TRUST_STATEMENTS: extract_trust_statements(assume_role_policy),
            AwsResourceMetadata.INLINE_POLICY_NAMES: inline_policy_names,
            AwsResourceMetadata.IAM_POLICY_COMPLETENESS_STATE: ("complete" if complete else "unknown"),
            AwsResourceMetadata.IAM_POLICY_POSTURE_UNCERTAINTIES: uncertainties,
            AwsResourceMetadata.IAM_PERMISSIONS_BOUNDARY_ARN: permissions_boundary_arn,
            AwsResourceMetadata.IAM_PERMISSIONS_BOUNDARY_STATE: permissions_boundary_state,
            AwsResourceMetadata.IAM_PERMISSIONS_BOUNDARY_UNCERTAINTIES: permissions_boundary_uncertainties,
        },
    )


def normalize_iam_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    statements, policy_document, complete, uncertainties = _iam_policy_details(
        values.get("policy"),
        unknown=value_is_unknown(resource.unknown_values.get("policy")),
        label="policy",
    )
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=values.get("name") or values.get("id"),
        arn=values.get("arn"),
        policy_statements=tuple(statements),
        metadata={
            AwsResourceMetadata.POLICY_DOCUMENT: policy_document,
            AwsResourceMetadata.IAM_POLICY_COMPLETENESS_STATE: ("complete" if complete else "unknown"),
            AwsResourceMetadata.IAM_POLICY_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_iam_role_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    statements, policy_document, complete, uncertainties = _iam_policy_details(
        values.get("policy"),
        unknown=value_is_unknown(resource.unknown_values.get("policy")),
        label="policy",
    )
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=values.get("id") or resource.address,
        policy_statements=tuple(statements),
        metadata={
            AwsResourceMetadata.ROLE_REFERENCE: values.get("role"),
            AwsResourceMetadata.POLICY_DOCUMENT: policy_document,
            AwsResourceMetadata.POLICY_NAME: values.get("name"),
            AwsResourceMetadata.IAM_POLICY_COMPLETENESS_STATE: ("complete" if complete else "unknown"),
            AwsResourceMetadata.IAM_POLICY_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_iam_role_policy_attachment(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=values.get("id") or resource.address,
        metadata={
            AwsResourceMetadata.ROLE_REFERENCE: values.get("role"),
            AwsResourceMetadata.POLICY_ARN: values.get("policy_arn"),
        },
    )


def normalize_iam_instance_profile(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    role_references = compact(as_list(values.get("roles")) + [values.get("role")])
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=values.get("name") or values.get("id"),
        arn=values.get("arn"),
        metadata={
            AwsResourceMetadata.ROLE_REFERENCES: role_references,
        },
    )


def normalize_iam_openid_connect_provider(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    url = known_string(values, unknown_values, "url", uncertainties, require_string=True)
    arn = known_string(values, unknown_values, "arn", uncertainties, require_string=True)

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=arn or url or resource.address,
        arn=arn,
        metadata={
            AwsResourceMetadata.OIDC_PROVIDER_URL: url,
            AwsResourceMetadata.OIDC_PROVIDER_ARN: arn,
            AwsResourceMetadata.OIDC_PROVIDER_CLIENT_IDS: known_string_list(
                values,
                unknown_values,
                "client_id_list",
                uncertainties,
            ),
            AwsResourceMetadata.OIDC_PROVIDER_THUMBPRINTS: known_string_list(
                values,
                unknown_values,
                "thumbprint_list",
                uncertainties,
            ),
            AwsResourceMetadata.OIDC_PROVIDER_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def _iam_policy_details(
    raw_policy: object,
    *,
    unknown: bool,
    label: str,
) -> tuple[list[IAMPolicyStatement], dict[str, Any], bool, list[str]]:
    if unknown:
        return [], {}, False, [f"{label} is unknown after planning"]
    document: dict[str, Any]
    if isinstance(raw_policy, Mapping):
        document = {str(key): value for key, value in raw_policy.items()}
    elif isinstance(raw_policy, str) and raw_policy.strip():
        try:
            decoded = json.loads(raw_policy)
        except json.JSONDecodeError:
            decoded = None
        if not isinstance(decoded, dict):
            return [], {}, False, [f"{label} is not a valid JSON document"]
        document = {str(key): value for key, value in decoded.items()}
    else:
        return [], {}, False, [f"{label} is missing or has an unrecognized value shape"]

    raw_statements = document.get("Statement")
    if isinstance(raw_statements, dict):
        statement_documents: list[dict[str, Any]] = [raw_statements]
    elif isinstance(raw_statements, list) and all(isinstance(statement, dict) for statement in raw_statements):
        statement_documents = [statement for statement in raw_statements if isinstance(statement, dict)]
    else:
        return [], document, False, [f"{label} statements have an unrecognized value shape"]

    statements = parse_policy_statements(document)
    complete = (
        bool(statement_documents)
        and len(statements) == len(statement_documents)
        and all(
            policy_statement_is_fully_representable(
                raw_statement,
                statement,
                principal_mode="forbidden",
            )
            for raw_statement, statement in zip(
                statement_documents,
                statements,
                strict=True,
            )
        )
    )
    return (
        statements,
        document,
        complete,
        [] if complete else [f"{label} contains incomplete or unsupported statements"],
    )

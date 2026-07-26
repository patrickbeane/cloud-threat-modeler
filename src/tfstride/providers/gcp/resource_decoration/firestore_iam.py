from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_types import GCP_PROJECT_IAM_RESOURCE_TYPES, GcpResourceType
from tfstride.providers.gcp.resource_utils import GCP_BASIC_IAM_ROLES, binding_members

_FIRESTORE_DATABASE_NAME_PATTERN = re.compile(r"^projects/([^/]+)/databases/([^/]+)$")
_RESOURCE_NAME_EQUALS_LITERAL = re.compile(
    r"""^\s*\(?\s*resource\.name\s*==\s*(?P<quote>["'])(?P<name>[^"']+)(?P=quote)\s*\)?\s*$"""
)
_LITERAL_EQUALS_RESOURCE_NAME = re.compile(
    r"""^\s*\(?\s*(?P<quote>["'])(?P<name>[^"']+)(?P=quote)\s*==\s*resource\.name\s*\)?\s*$"""
)


class NormalizeFirestoreIamPostureStage:
    """Project Firestore IAM grants onto exact in-plan database identities."""

    name = "normalize_firestore_iam_posture"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        del context
        project_iam_resources = tuple(
            resource for resource in resources if resource.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES
        )
        for database in resources:
            if database.resource_type != GcpResourceType.FIRESTORE_DATABASE:
                continue
            grants, uncertainties = _firestore_iam_posture(database, project_iam_resources)
            gcp_mutations(database).set_firestore_iam_posture(
                grants=grants,
                uncertainties=uncertainties,
            )


def _firestore_iam_posture(
    database: NormalizedResource,
    iam_resources: tuple[NormalizedResource, ...],
) -> tuple[list[dict[str, Any]], list[str]]:
    database_resource_name = _database_resource_name(database)
    database_project = _database_project(database_resource_name)
    if database_resource_name is None or database_project is None:
        return [], [f"{database.address}: exact Firestore database identity is unresolved"]

    grants: list[dict[str, Any]] = []
    uncertainties: list[str] = []
    for iam_resource in iam_resources:
        iam_facts = gcp_facts(iam_resource)
        iam_project = _normalize_project(iam_facts.project)
        if iam_project is None:
            uncertainties.append(f"{iam_resource.address}: IAM project is unresolved for {database_resource_name}")
            continue
        if iam_project != database_project:
            continue
        policy_state = iam_facts.iam_policy_data_state
        if policy_state in {"unknown", "invalid", "not_configured"}:
            uncertainties.append(
                f"{iam_resource.address}: IAM policy_data is {policy_state} for {database_resource_name}"
            )
        for binding in iam_bindings(iam_resource):
            if binding.get("role_state") == "unknown":
                uncertainties.append(f"{iam_resource.address}: IAM role is unresolved for {database_resource_name}")
                continue
            if binding.get("members_state") == "unknown":
                uncertainties.append(f"{iam_resource.address}: IAM members are unresolved for {database_resource_name}")
                continue
            role = _known_string(binding.get("role"))
            members = binding_members(binding)
            if role is None or not members:
                uncertainties.append(
                    f"{iam_resource.address}: IAM role or members are unresolved for {database_resource_name}"
                )
                continue

            scope_type, condition_uncertainty = _binding_scope(binding, database_resource_name)
            if scope_type == "unrelated":
                continue
            if scope_type is None:
                uncertainties.append(
                    f"{iam_resource.address}: {condition_uncertainty or 'IAM condition applicability is unresolved'}"
                )
                continue
            if scope_type == "database" and role in GCP_BASIC_IAM_ROLES:
                uncertainties.append(
                    f"{iam_resource.address}: basic IAM role {role} cannot use "
                    f"conditional database scope for {database_resource_name}"
                )
                continue

            grant: dict[str, Any] = {
                "role": role,
                "members": members,
                "source": iam_resource.address,
                "source_type": iam_resource.resource_type,
                "scope_type": scope_type,
                "scope": database_resource_name if scope_type == "database" else database_project,
                "project": database_project,
                "database_resource_name": database_resource_name,
                "grant_basis": "project_iam_condition" if scope_type == "database" else "project_iam",
                "condition_state": "configured" if scope_type == "database" else "not_configured",
            }
            condition = binding.get("condition")
            if scope_type == "database" and isinstance(condition, Mapping):
                grant["condition"] = dict(condition)
            grants.append(grant)

    grants.sort(
        key=lambda grant: (
            str(grant["source"]),
            str(grant["role"]),
            tuple(str(member) for member in grant["members"]),
            str(grant["scope_type"]),
        )
    )
    return grants, dedupe(uncertainties)


def _database_resource_name(database: NormalizedResource) -> str | None:
    for value in (
        database.identifier,
        gcp_facts(database).firestore_database_name,
    ):
        text = _known_string(value)
        if text and _FIRESTORE_DATABASE_NAME_PATTERN.fullmatch(text):
            return text

    facts = gcp_facts(database)
    project = _normalize_project(facts.project)
    database_name = _known_string(facts.firestore_database_name)
    if project and database_name and "/" not in database_name:
        return f"projects/{project}/databases/{database_name}"
    return None


def _database_project(database_resource_name: str | None) -> str | None:
    if database_resource_name is None:
        return None
    match = _FIRESTORE_DATABASE_NAME_PATTERN.fullmatch(database_resource_name)
    return match.group(1) if match else None


def _binding_scope(
    binding: Mapping[str, Any],
    database_resource_name: str,
) -> tuple[str | None, str | None]:
    if binding.get("condition_state") == "unknown":
        return None, f"IAM condition applicability to {database_resource_name} is unknown after planning"

    condition = binding.get("condition")
    if not isinstance(condition, Mapping) or not condition:
        return "project", None

    expression = _known_string(condition.get("expression"))
    if expression is None:
        return None, f"IAM condition applicability to {database_resource_name} is not deterministic"
    conditioned_resource_name = _exact_condition_resource_name(expression)
    if conditioned_resource_name is None:
        return None, f"IAM condition applicability to {database_resource_name} is not deterministic"
    if conditioned_resource_name == database_resource_name:
        return "database", None
    if _FIRESTORE_DATABASE_NAME_PATTERN.fullmatch(conditioned_resource_name):
        return "unrelated", None
    return None, f"IAM condition applicability to {database_resource_name} is not deterministic"


def _exact_condition_resource_name(expression: str) -> str | None:
    for pattern in (_RESOURCE_NAME_EQUALS_LITERAL, _LITERAL_EQUALS_RESOURCE_NAME):
        match = pattern.fullmatch(expression)
        if match:
            return match.group("name")
    return None


def _normalize_project(value: object) -> str | None:
    text = _known_string(value)
    if text is None:
        return None
    parts = [part for part in text.split("/") if part]
    if len(parts) == 2 and parts[0] == "projects":
        return parts[1]
    return text if "/" not in text else None


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None

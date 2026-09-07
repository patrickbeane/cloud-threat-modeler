from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from tfstride.analysis.finding_helpers import build_severity_reasoning
from tfstride.identity import (
    AssignmentScopeKind,
    PrincipalType,
    PrivilegeCategory,
    PrivilegeConfidence,
    PrivilegedAccessGrant,
)
from tfstride.models import SeverityReasoning

_HIGH_IMPACT_CATEGORIES: frozenset[PrivilegeCategory] = frozenset(
    {
        PrivilegeCategory.FULL_ADMIN,
        PrivilegeCategory.IAM_ADMIN,
        PrivilegeCategory.POLICY_ADMIN,
        PrivilegeCategory.ROLE_ASSIGNMENT,
        PrivilegeCategory.PRIVILEGE_ESCALATION,
    }
)
_DATA_ACCESS_CATEGORIES: frozenset[PrivilegeCategory] = frozenset(
    {
        PrivilegeCategory.DATA_ADMIN,
        PrivilegeCategory.SECRETS_ADMIN,
        PrivilegeCategory.KEY_ADMIN,
    }
)
_CONTROL_PLANE_CATEGORIES: frozenset[PrivilegeCategory] = frozenset(
    {
        PrivilegeCategory.COMPUTE_ADMIN,
        PrivilegeCategory.NETWORK_ADMIN,
        PrivilegeCategory.AUDIT_ADMIN,
    }
)


@dataclass(frozen=True, slots=True)
class PrivilegedAssignmentEvidence:
    """Provider-neutral evidence facets derived from privileged grants."""

    privilege_categories: tuple[str, ...]
    permission_patterns: tuple[str, ...]
    grant_principals: tuple[str, ...]
    grant_scopes: tuple[str, ...]
    grant_confidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PrivilegedAssignmentEvaluation:
    """Shared decisions and evidence for one non-empty privileged grant set."""

    privilege_categories: tuple[PrivilegeCategory, ...]
    summary: str
    severity_reasoning: SeverityReasoning
    evidence: PrivilegedAssignmentEvidence


def evaluate_privileged_assignment(
    grants: Iterable[PrivilegedAccessGrant],
) -> PrivilegedAssignmentEvaluation:
    """Evaluate provider-normalized privileged grants without provider-specific policy."""

    resolved_grants = tuple(grants)
    if not resolved_grants:
        raise ValueError("privileged assignment evaluation requires at least one grant")

    categories = _privilege_categories(resolved_grants)
    return PrivilegedAssignmentEvaluation(
        privilege_categories=categories,
        summary=", ".join(category.value for category in categories) or "unknown privileged access",
        severity_reasoning=_severity_reasoning(resolved_grants, categories),
        evidence=PrivilegedAssignmentEvidence(
            privilege_categories=tuple(category.value for category in categories),
            permission_patterns=_dedupe_strings(
                pattern for grant in resolved_grants for pattern in grant.permission_patterns
            ),
            grant_principals=_principal_evidence(resolved_grants),
            grant_scopes=_scope_evidence(resolved_grants),
            grant_confidence=_confidence_evidence(resolved_grants),
        ),
    )


def _privilege_categories(
    grants: tuple[PrivilegedAccessGrant, ...],
) -> tuple[PrivilegeCategory, ...]:
    return tuple(
        sorted(
            {PrivilegeCategory(category) for grant in grants for category in grant.privilege_categories},
            key=lambda category: category.value,
        )
    )


def _severity_reasoning(
    grants: tuple[PrivilegedAccessGrant, ...],
    categories: tuple[PrivilegeCategory, ...],
) -> SeverityReasoning:
    category_set = frozenset(categories)
    high_impact = not category_set.isdisjoint(_HIGH_IMPACT_CATEGORIES)
    data_access = not category_set.isdisjoint(_DATA_ACCESS_CATEGORIES)
    control_plane = not category_set.isdisjoint(_CONTROL_PLANE_CATEGORIES)
    broad_scope = any(grant.has_broad_scope for grant in grants)
    high_confidence = any(PrivilegeConfidence(grant.confidence) == PrivilegeConfidence.HIGH for grant in grants)
    public_principal = any(PrincipalType(grant.principal.principal_type) == PrincipalType.ANY for grant in grants)
    return build_severity_reasoning(
        internet_exposure=public_principal,
        privilege_breadth=3 if high_impact and broad_scope and high_confidence else 2,
        data_sensitivity=2 if data_access else 0,
        lateral_movement=2 if high_impact else 1 if control_plane else 0,
        blast_radius=3 if broad_scope else 1,
    )


def _principal_evidence(
    grants: tuple[PrivilegedAccessGrant, ...],
) -> tuple[str, ...]:
    values: list[str] = []
    for grant in grants:
        principal = grant.principal
        value = f"principal_type={PrincipalType(principal.principal_type).value}"
        if principal.identifier:
            value = f"{value}; principal={principal.identifier}"
        values.append(value)
    return _dedupe_strings(values)


def _scope_evidence(
    grants: tuple[PrivilegedAccessGrant, ...],
) -> tuple[str, ...]:
    values: list[str] = []
    for grant in grants:
        scope = grant.assignment_scope
        value = f"scope_kind={AssignmentScopeKind(scope.scope_kind).value}"
        if scope.value:
            value = f"{value}; scope_value={scope.value}"
        values.append(value)
    return _dedupe_strings(values)


def _confidence_evidence(
    grants: tuple[PrivilegedAccessGrant, ...],
) -> tuple[str, ...]:
    return _dedupe_strings(PrivilegeConfidence(grant.confidence).value for grant in grants)


def _dedupe_strings(values: Iterable[str | None]) -> tuple[str, ...]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return tuple(deduped)

from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import collect_evidence, evidence_item
from tfstride.analysis.privileged_assignment_evaluator import evaluate_privileged_assignment
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.identity import AssignmentScopeKind, PrivilegeCategory, PrivilegedAccessGrant
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.coercion import dedupe_strings

_HIGH_IMPACT_CATEGORIES = frozenset(
    {
        PrivilegeCategory.FULL_ADMIN,
        PrivilegeCategory.IAM_ADMIN,
        PrivilegeCategory.POLICY_ADMIN,
        PrivilegeCategory.ROLE_ASSIGNMENT,
        PrivilegeCategory.PRIVILEGE_ESCALATION,
    }
)
_DATA_ACCESS_CATEGORIES = frozenset(
    {
        PrivilegeCategory.DATA_ADMIN,
        PrivilegeCategory.SECRETS_ADMIN,
        PrivilegeCategory.KEY_ADMIN,
    }
)
_CONTROL_PLANE_CATEGORIES = frozenset(
    {
        PrivilegeCategory.COMPUTE_ADMIN,
        PrivilegeCategory.NETWORK_ADMIN,
        PrivilegeCategory.AUDIT_ADMIN,
    }
)
_RESOURCE_SCOPED_DATA_ROLE_NAMES = frozenset(
    {
        "key vault administrator",
        "key vault certificates officer",
        "key vault crypto officer",
        "key vault data access administrator",
        "key vault secrets officer",
        "storage account contributor",
        "storage blob data contributor",
        "storage blob data owner",
    }
)
_TARGET_RULE_OWNED_TYPES = frozenset(
    {
        AzureResourceType.KEY_VAULT,
        AzureResourceType.KEY_VAULT_CERTIFICATE,
        AzureResourceType.KEY_VAULT_KEY,
        AzureResourceType.KEY_VAULT_SECRET,
    }
)


class AzureIamAssignmentRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_privileged_assignment(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for assignment in context.inventory.by_type(AzureResourceType.ROLE_ASSIGNMENT):
            facts = azure_facts(assignment)
            if facts.resolved_managed_identity_address or facts.resolved_role_definition_address:
                continue
            grants = tuple(grant for grant in facts.privileged_access_grants if _reportable_grant(grant, facts))
            if not grants:
                continue
            assignment_evaluation = evaluate_privileged_assignment(grants)
            common_evidence = assignment_evaluation.evidence
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=assignment_evaluation.severity_reasoning.severity,
                    affected_resources=_affected_resources(assignment, grants),
                    trust_boundary_id=None,
                    rationale=(
                        f"{assignment.display_name} grants deterministic privileged Azure RBAC assignment "
                        f"posture: {assignment_evaluation.summary}. Broad built-in role assignments expand tenant, "
                        "subscription, or resource-group blast radius if the assigned principal is compromised."
                    ),
                    evidence=collect_evidence(
                        evidence_item("role_assignment", _assignment_evidence(assignment, grants)),
                        evidence_item("privileged_access", _grant_evidence(grants)),
                        evidence_item("privilege_categories", list(common_evidence.privilege_categories)),
                        evidence_item("permission_patterns", list(common_evidence.permission_patterns)),
                        evidence_item("grant_principals", list(common_evidence.grant_principals)),
                        evidence_item("grant_scopes", list(common_evidence.grant_scopes)),
                        evidence_item("grant_confidence", list(common_evidence.grant_confidence)),
                        evidence_item("assignment_facts", _provider_fact_evidence(grants)),
                        evidence_item("unresolved_assignments", facts.iam_assignment_posture_uncertainties),
                    ),
                    severity_reasoning=assignment_evaluation.severity_reasoning,
                )
            )
        return findings


def _reportable_grant(grant: PrivilegedAccessGrant, facts: AzureResourceFacts) -> bool:
    if facts.role_assignment_target_resource_type in _TARGET_RULE_OWNED_TYPES:
        return False

    categories = _grant_categories((grant,))
    if categories & _HIGH_IMPACT_CATEGORIES:
        return True
    if grant.has_broad_scope and categories & (_DATA_ACCESS_CATEGORIES | _CONTROL_PLANE_CATEGORIES):
        return True
    if "sensitive_resource_scope" in facts.role_assignment_breadth_signals and categories & (
        _DATA_ACCESS_CATEGORIES | _CONTROL_PLANE_CATEGORIES
    ):
        return True
    return _is_resource_scoped_data_role(grant, categories)


def _is_resource_scoped_data_role(grant: PrivilegedAccessGrant, categories: set[PrivilegeCategory]) -> bool:
    if grant.assignment_scope.scope_kind != AssignmentScopeKind.RESOURCE:
        return False
    if not categories & _DATA_ACCESS_CATEGORIES:
        return False
    return (grant.role_name or "").strip().lower() in _RESOURCE_SCOPED_DATA_ROLE_NAMES


def _grant_categories(grants: tuple[PrivilegedAccessGrant, ...]) -> set[PrivilegeCategory]:
    return {category for grant in grants for category in grant.privilege_categories}


def _assignment_evidence(assignment: NormalizedResource, grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    values = [
        f"address={assignment.address}",
        f"type={assignment.resource_type}",
    ]
    values.extend(f"role={grant.role_name}" for grant in grants if grant.role_name)
    values.extend(f"role_definition_id={grant.role_id}" for grant in grants if grant.role_id)
    return dedupe_strings(values)


def _grant_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    values: list[str] = []
    for index, grant in enumerate(grants, start=1):
        categories = ", ".join(category.value for category in grant.privilege_categories)
        principal = grant.principal.identifier or grant.principal.principal_type.value
        values.append(
            f"grant_{index}=principal={principal}; categories=[{categories}]; "
            f"scope={grant.assignment_scope.scope_kind.value}; confidence={grant.confidence.value}"
        )
    return values


def _provider_fact_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    return dedupe_strings(value for grant in grants for value in grant.evidence)


def _affected_resources(assignment: NormalizedResource, grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    return dedupe_strings([assignment.address, *(grant.assignment_scope.source_address for grant in grants)])

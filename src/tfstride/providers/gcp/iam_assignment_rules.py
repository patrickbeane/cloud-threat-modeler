from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import collect_evidence, evidence_item
from tfstride.analysis.privileged_assignment_evaluator import evaluate_privileged_assignment
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.identity import PrivilegedAccessGrant
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.coercion import dedupe_strings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import (
    GCP_FOLDER_IAM_RESOURCE_TYPES,
    GCP_ORGANIZATION_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES,
)

_LEGACY_SCOPED_IAM_RESOURCE_TYPES = (
    GCP_PROJECT_IAM_RESOURCE_TYPES
    | GCP_ORGANIZATION_IAM_RESOURCE_TYPES
    | GCP_FOLDER_IAM_RESOURCE_TYPES
    | GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES
)


class GcpIamAssignmentRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_privileged_assignment(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for resource in context.inventory.resources:
            if resource.resource_type in _LEGACY_SCOPED_IAM_RESOURCE_TYPES:
                continue
            facts = gcp_facts(resource)
            grants = facts.privileged_access_grants
            if not grants:
                continue
            assignment_evaluation = evaluate_privileged_assignment(grants)
            common_evidence = assignment_evaluation.evidence
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=assignment_evaluation.severity_reasoning.severity,
                    affected_resources=_affected_resources(resource, grants),
                    trust_boundary_id=None,
                    rationale=(
                        f"{resource.display_name} has deterministic privileged GCP IAM assignment posture: "
                        f"{assignment_evaluation.summary}. Those grants can expand control-plane, data-plane, or "
                        "impersonation blast radius if the assigned principal is compromised or mis-scoped."
                    ),
                    evidence=collect_evidence(
                        evidence_item("iam_assignment", _assignment_evidence(resource, grants)),
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


def _assignment_evidence(resource: NormalizedResource, grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    values = [
        f"address={resource.address}",
        f"type={resource.resource_type}",
    ]
    values.extend(f"role={grant.role_name}" for grant in grants if grant.role_name)
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


def _affected_resources(resource: NormalizedResource, grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    return dedupe_strings([resource.address, *(grant.assignment_scope.source_address for grant in grants)])

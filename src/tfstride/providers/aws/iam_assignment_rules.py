from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import collect_evidence, evidence_item
from tfstride.analysis.privileged_assignment_evaluator import evaluate_privileged_assignment
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.identity import PrivilegedAccessGrant
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.coercion import dedupe_strings


class AwsIamAssignmentRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_privileged_role_assignment(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for role in context.inventory.by_type("aws_iam_role"):
            facts = aws_facts(role)
            grants = facts.privileged_access_grants
            if not grants:
                continue
            assignment_evaluation = evaluate_privileged_assignment(grants)
            common_evidence = assignment_evaluation.evidence
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=assignment_evaluation.severity_reasoning.severity,
                    affected_resources=_affected_resources(role),
                    trust_boundary_id=None,
                    rationale=(
                        f"{role.display_name} has deterministic privileged IAM assignment posture: "
                        f"{assignment_evaluation.summary}. If this role is attached to a workload or assumable by a "
                        "control-plane principal, those privileges increase blast radius."
                    ),
                    evidence=collect_evidence(
                        evidence_item("iam_role", _role_evidence(role)),
                        evidence_item("privileged_access", _grant_evidence(grants)),
                        evidence_item("privilege_categories", list(common_evidence.privilege_categories)),
                        evidence_item("permission_patterns", list(common_evidence.permission_patterns)),
                        evidence_item("grant_scopes", list(common_evidence.grant_scopes)),
                        evidence_item("grant_confidence", list(common_evidence.grant_confidence)),
                        evidence_item("attached_policies", _attached_policy_evidence(role)),
                        evidence_item("inline_policy_sources", _inline_policy_evidence(role)),
                        evidence_item("unresolved_assignments", facts.iam_assignment_posture_uncertainties),
                    ),
                    severity_reasoning=assignment_evaluation.severity_reasoning,
                )
            )
        return findings


def _role_evidence(role: NormalizedResource) -> list[str]:
    values = [
        f"address={role.address}",
        f"type={role.resource_type}",
    ]
    if role.arn:
        values.append(f"arn={role.arn}")
    if role.identifier:
        values.append(f"identifier={role.identifier}")
    return values


def _grant_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    values: list[str] = []
    for index, grant in enumerate(grants, start=1):
        categories = ", ".join(category.value for category in grant.privilege_categories)
        values.append(
            f"grant_{index}=categories=[{categories}]; scope={grant.assignment_scope.scope_kind.value}; "
            f"confidence={grant.confidence.value}"
        )
    return values


def _attached_policy_evidence(role: NormalizedResource) -> list[str]:
    facts = aws_facts(role)
    values: list[str] = []
    values.extend(f"attached_policy_arn={arn}" for arn in facts.attached_policy_arns)
    values.extend(f"attached_policy_address={address}" for address in facts.attached_policy_addresses)
    return values


def _inline_policy_evidence(role: NormalizedResource) -> list[str]:
    facts = aws_facts(role)
    values: list[str] = []
    values.extend(f"inline_policy_name={name}" for name in facts.inline_policy_names)
    values.extend(f"inline_policy_source={address}" for address in facts.inline_policy_resource_addresses)
    return values


def _affected_resources(role: NormalizedResource) -> list[str]:
    facts = aws_facts(role)
    return dedupe_strings([role.address, *facts.attached_policy_addresses, *facts.inline_policy_resource_addresses])

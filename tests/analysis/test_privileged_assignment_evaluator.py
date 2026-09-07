from __future__ import annotations

import inspect
import unittest
from dataclasses import FrozenInstanceError

from tfstride.analysis import privileged_assignment_evaluator as evaluator_module
from tfstride.analysis.privileged_assignment_evaluator import (
    PrivilegedAssignmentEvaluation,
    PrivilegedAssignmentEvidence,
    evaluate_privileged_assignment,
)
from tfstride.identity import (
    AssignmentScopeKind,
    PrincipalType,
    PrivilegeCategory,
    PrivilegeConfidence,
    PrivilegedAccessGrant,
    PrivilegedAssignmentScope,
    PrivilegedPrincipal,
)
from tfstride.models import Severity, SeverityReasoning


def _grant(
    *,
    categories: tuple[PrivilegeCategory, ...],
    principal_type: PrincipalType = PrincipalType.ROLE,
    principal_identifier: str | None = "principal-1",
    scope_kind: AssignmentScopeKind = AssignmentScopeKind.RESOURCE,
    scope_value: str | None = "resource-1",
    confidence: PrivilegeConfidence = PrivilegeConfidence.HIGH,
    permission_patterns: tuple[str | None, ...] = (),
) -> PrivilegedAccessGrant:
    return PrivilegedAccessGrant(
        provider="example",
        principal=PrivilegedPrincipal(
            principal_type=principal_type,
            identifier=principal_identifier,
        ),
        assignment_scope=PrivilegedAssignmentScope(
            scope_kind=scope_kind,
            value=scope_value,
        ),
        privilege_categories=categories,
        confidence=confidence,
        permission_patterns=permission_patterns,
    )


class PrivilegedAssignmentEvaluatorTests(unittest.TestCase):
    def test_evaluator_aggregates_typed_categories_and_ordered_evidence(self) -> None:
        grants = (
            _grant(
                categories=(
                    PrivilegeCategory.IAM_ADMIN,
                    PrivilegeCategory.ROLE_ASSIGNMENT,
                ),
                principal_identifier="role/app",
                scope_kind=AssignmentScopeKind.ACCOUNT,
                scope_value="account-1",
                permission_patterns=("identity:AttachPolicy", "identity:PassRole"),
            ),
            _grant(
                categories=(
                    PrivilegeCategory.DATA_ADMIN,
                    PrivilegeCategory.IAM_ADMIN,
                ),
                principal_type=PrincipalType.GROUP,
                principal_identifier=None,
                scope_value=None,
                confidence=PrivilegeConfidence.MEDIUM,
                permission_patterns=("identity:PassRole", "data:*"),
            ),
        )

        evaluation = evaluate_privileged_assignment(grant for grant in grants)

        self.assertEqual(
            evaluation.privilege_categories,
            (
                PrivilegeCategory.DATA_ADMIN,
                PrivilegeCategory.IAM_ADMIN,
                PrivilegeCategory.ROLE_ASSIGNMENT,
            ),
        )
        self.assertEqual(evaluation.summary, "data-admin, iam-admin, role-assignment")
        self.assertEqual(
            evaluation.severity_reasoning,
            SeverityReasoning(
                internet_exposure=0,
                privilege_breadth=3,
                data_sensitivity=2,
                lateral_movement=2,
                blast_radius=3,
                final_score=10,
                severity=Severity.HIGH,
            ),
        )
        self.assertEqual(
            evaluation.evidence,
            PrivilegedAssignmentEvidence(
                privilege_categories=("data-admin", "iam-admin", "role-assignment"),
                permission_patterns=("identity:AttachPolicy", "identity:PassRole", "data:*"),
                grant_principals=(
                    "principal_type=role; principal=role/app",
                    "principal_type=group",
                ),
                grant_scopes=(
                    "scope_kind=account; scope_value=account-1",
                    "scope_kind=resource",
                ),
                grant_confidence=("high", "medium"),
            ),
        )

    def test_public_principal_contributes_internet_exposure(self) -> None:
        evaluation = evaluate_privileged_assignment(
            [
                _grant(
                    categories=(PrivilegeCategory.SECRETS_ADMIN,),
                    principal_type=PrincipalType.ANY,
                    principal_identifier="all-principals",
                )
            ]
        )

        self.assertEqual(
            evaluation.severity_reasoning,
            SeverityReasoning(
                internet_exposure=2,
                privilege_breadth=2,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
                final_score=7,
                severity=Severity.HIGH,
            ),
        )
        self.assertEqual(
            evaluation.evidence.grant_principals,
            ("principal_type=any-principal; principal=all-principals",),
        )

    def test_high_confidence_and_control_plane_severity_branches_are_explicit(self) -> None:
        cases = {
            "broad high-impact medium confidence": (
                _grant(
                    categories=(PrivilegeCategory.IAM_ADMIN,),
                    scope_kind=AssignmentScopeKind.ORGANIZATION,
                    confidence=PrivilegeConfidence.MEDIUM,
                ),
                SeverityReasoning(
                    internet_exposure=0,
                    privilege_breadth=2,
                    data_sensitivity=0,
                    lateral_movement=2,
                    blast_radius=3,
                    final_score=7,
                    severity=Severity.HIGH,
                ),
            ),
            "resource-scoped control plane": (
                _grant(
                    categories=(PrivilegeCategory.NETWORK_ADMIN,),
                    confidence=PrivilegeConfidence.LOW,
                ),
                SeverityReasoning(
                    internet_exposure=0,
                    privilege_breadth=2,
                    data_sensitivity=0,
                    lateral_movement=1,
                    blast_radius=1,
                    final_score=4,
                    severity=Severity.MEDIUM,
                ),
            ),
        }

        for label, (grant, expected) in cases.items():
            with self.subTest(label=label):
                self.assertEqual(
                    evaluate_privileged_assignment([grant]).severity_reasoning,
                    expected,
                )

    def test_empty_grant_set_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least one grant"):
            evaluate_privileged_assignment([])

    def test_evaluation_contracts_are_frozen_and_slotted(self) -> None:
        evaluation = evaluate_privileged_assignment([_grant(categories=(PrivilegeCategory.FULL_ADMIN,))])

        self.assertIsInstance(evaluation, PrivilegedAssignmentEvaluation)
        self.assertFalse(hasattr(evaluation, "__dict__"))
        self.assertFalse(hasattr(evaluation.evidence, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            evaluation.summary = "changed"  # pyright: ignore[reportAttributeAccessIssue]

    def test_evaluator_has_no_provider_or_finding_dependencies(self) -> None:
        source = inspect.getsource(evaluator_module)

        self.assertNotIn("tfstride.providers", source)
        self.assertNotIn("NormalizedResource", source)
        self.assertNotIn("TerraformResource", source)
        self.assertNotIn("FindingFactory", source)
        self.assertNotIn("resource_type", source)


if __name__ == "__main__":
    unittest.main()

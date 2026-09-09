from __future__ import annotations

import inspect
import unittest
from dataclasses import FrozenInstanceError
from typing import cast, get_args

from tfstride.key_management import (
    ManagedKeyLifecycleApplicability,
    ManagedKeyLifecycleAssessment,
    ManagedKeyLifecycleIssue,
    ManagedKeyLifecyclePosture,
)
from tfstride.key_management import lifecycle as lifecycle_module


class ManagedKeyLifecyclePostureTests(unittest.TestCase):
    def test_typed_vocabularies_are_complete(self) -> None:
        self.assertEqual(
            get_args(ManagedKeyLifecycleApplicability),
            ("applicable", "not_applicable", "unknown"),
        )
        self.assertEqual(
            get_args(ManagedKeyLifecycleAssessment),
            ("compliant", "action_required", "unknown", "not_evaluated"),
        )
        self.assertEqual(
            get_args(ManagedKeyLifecycleIssue),
            (
                "rotation_disabled",
                "rotation_period_missing",
                "rotation_policy_missing",
                "rotation_automation_missing",
                "rotation_interval_too_long",
                "expiration_policy_missing",
                "expiration_interval_too_long",
                "key_lifetime_too_long",
            ),
        )

    def test_decisions_distinguish_attention_from_indeterminate_posture(self) -> None:
        cases = (
            (
                "compliant",
                ManagedKeyLifecyclePosture("applicable", "compliant"),
                (True, False, False),
            ),
            (
                "action-required",
                ManagedKeyLifecyclePosture(
                    "applicable",
                    "action_required",
                    issues=("rotation_disabled",),
                ),
                (True, True, False),
            ),
            (
                "unknown-assessment",
                ManagedKeyLifecyclePosture("applicable", "unknown"),
                (True, False, True),
            ),
            (
                "not-applicable",
                ManagedKeyLifecyclePosture("not_applicable", "not_evaluated"),
                (False, False, False),
            ),
            (
                "unknown-applicability",
                ManagedKeyLifecyclePosture("unknown", "not_evaluated"),
                (False, False, True),
            ),
        )

        for case, posture, expected in cases:
            with self.subTest(case=case):
                self.assertEqual(
                    (
                        posture.is_applicable,
                        posture.requires_attention,
                        posture.is_indeterminate,
                    ),
                    expected,
                )

    def test_issues_and_uncertainties_preserve_adapter_order(self) -> None:
        posture = ManagedKeyLifecyclePosture(
            "applicable",
            "action_required",
            issues=(
                "expiration_interval_too_long",
                "rotation_interval_too_long",
                "key_lifetime_too_long",
            ),
            uncertainties=(
                "rotation source is unresolved",
                "expiration source is unresolved",
                "rotation source is unresolved",
            ),
        )

        self.assertEqual(
            posture.issues,
            (
                "expiration_interval_too_long",
                "rotation_interval_too_long",
                "key_lifetime_too_long",
            ),
        )
        self.assertEqual(
            posture.uncertainties,
            (
                "rotation source is unresolved",
                "expiration source is unresolved",
                "rotation source is unresolved",
            ),
        )

    def test_invalid_vocabulary_values_are_rejected_at_runtime(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported managed-key lifecycle applicability"):
            ManagedKeyLifecyclePosture(
                cast(ManagedKeyLifecycleApplicability, "sometimes"),
                "not_evaluated",
            )
        with self.assertRaisesRegex(ValueError, "unsupported managed-key lifecycle assessment"):
            ManagedKeyLifecyclePosture(
                "applicable",
                cast(ManagedKeyLifecycleAssessment, "unsafe"),
            )
        with self.assertRaisesRegex(ValueError, "unsupported managed-key lifecycle issue"):
            ManagedKeyLifecyclePosture(
                "applicable",
                "action_required",
                issues=(cast(ManagedKeyLifecycleIssue, "provider_issue"),),
            )

    def test_applicability_and_assessment_must_be_consistent(self) -> None:
        cases = (
            lambda: ManagedKeyLifecyclePosture("applicable", "not_evaluated"),
            lambda: ManagedKeyLifecyclePosture("not_applicable", "compliant"),
            lambda: ManagedKeyLifecyclePosture("unknown", "unknown"),
        )

        for case, posture_factory in enumerate(cases, start=1):
            with self.subTest(case=case):
                with self.assertRaisesRegex(ValueError, "applicability and assessment are inconsistent"):
                    posture_factory()

    def test_issues_exactly_match_action_required_assessment(self) -> None:
        cases = (
            lambda: ManagedKeyLifecyclePosture("applicable", "action_required"),
            lambda: ManagedKeyLifecyclePosture(
                "applicable",
                "compliant",
                issues=("rotation_disabled",),
            ),
            lambda: ManagedKeyLifecyclePosture(
                "applicable",
                "unknown",
                issues=("rotation_period_missing",),
            ),
        )

        for case, posture_factory in enumerate(cases, start=1):
            with self.subTest(case=case):
                with self.assertRaisesRegex(ValueError, "issues must exactly match"):
                    posture_factory()

    def test_posture_is_frozen_and_slotted(self) -> None:
        posture = ManagedKeyLifecyclePosture("applicable", "compliant")

        self.assertFalse(hasattr(posture, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            posture.assessment = "unknown"  # pyright: ignore[reportAttributeAccessIssue]

    def test_module_has_no_provider_or_rule_dependencies(self) -> None:
        source = inspect.getsource(lifecycle_module)

        self.assertNotIn("from tfstride", source)
        self.assertNotIn("import tfstride", source)
        self.assertNotIn("NormalizedResource", source)
        self.assertNotIn("TerraformResource", source)
        self.assertNotIn("ResourceFacts", source)
        self.assertNotIn("FindingFactory", source)
        self.assertNotIn("SeverityReasoning", source)
        self.assertNotIn("datetime", source)
        self.assertNotIn("provider ==", source)
        self.assertNotIn("resource_type", source)


if __name__ == "__main__":
    unittest.main()

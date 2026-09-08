from __future__ import annotations

import inspect
import unittest
from dataclasses import FrozenInstanceError
from typing import cast, get_args

from tfstride.storage import StorageVersioningPosture, StorageVersioningState
from tfstride.storage import versioning as versioning_module


class StorageVersioningPostureTests(unittest.TestCase):
    def test_state_vocabulary_is_typed_and_complete(self) -> None:
        self.assertEqual(
            get_args(StorageVersioningState),
            ("enabled", "disabled", "unknown", "not_observed"),
        )

    def test_attention_decision_is_pinned_for_each_state(self) -> None:
        expected = {
            "enabled": False,
            "disabled": True,
            "unknown": True,
            "not_observed": False,
        }

        for state, requires_attention in expected.items():
            with self.subTest(state=state):
                posture = StorageVersioningPosture(cast(StorageVersioningState, state))
                self.assertIs(posture.requires_attention, requires_attention)

    def test_uncertainties_preserve_provider_supplied_order(self) -> None:
        posture = StorageVersioningPosture(
            state="unknown",
            uncertainties=(
                "versioning status is unresolved",
                "versioning source is unresolved",
                "versioning status is unresolved",
            ),
        )

        self.assertEqual(
            posture.uncertainties,
            (
                "versioning status is unresolved",
                "versioning source is unresolved",
                "versioning status is unresolved",
            ),
        )

    def test_invalid_state_is_rejected_at_runtime(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported storage versioning state"):
            StorageVersioningPosture(cast(StorageVersioningState, "unsupported"))

    def test_posture_is_frozen_and_slotted(self) -> None:
        posture = StorageVersioningPosture("enabled")

        self.assertFalse(hasattr(posture, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            posture.state = "disabled"  # pyright: ignore[reportAttributeAccessIssue]

    def test_module_has_no_provider_or_rule_dependencies(self) -> None:
        source = inspect.getsource(versioning_module)

        self.assertNotIn("from tfstride", source)
        self.assertNotIn("import tfstride", source)
        self.assertNotIn("NormalizedResource", source)
        self.assertNotIn("TerraformResource", source)
        self.assertNotIn("ResourceFacts", source)
        self.assertNotIn("FindingFactory", source)
        self.assertNotIn("SeverityReasoning", source)
        self.assertNotIn("provider ==", source)
        self.assertNotIn("resource_type", source)


if __name__ == "__main__":
    unittest.main()

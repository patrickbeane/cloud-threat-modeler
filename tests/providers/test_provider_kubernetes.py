from __future__ import annotations

import unittest

from tfstride.providers.kubernetes import (
    block_value,
    dedupe,
    first_unknown_block,
    uncertainty_evidence,
    unknown_block_at_index,
)


class ProviderKubernetesHelperTests(unittest.TestCase):
    def test_unknown_block_helpers_handle_mapping_list_and_boolean_shapes(self) -> None:
        self.assertEqual(first_unknown_block({"field": True}), {"field": True})
        self.assertEqual(first_unknown_block([{"field": True}]), {"field": True})
        self.assertIs(first_unknown_block(True), True)
        self.assertIsNone(first_unknown_block([]))
        self.assertEqual(unknown_block_at_index([{"first": True}, {"second": True}], 1), {"second": True})
        self.assertEqual(unknown_block_at_index({"field": True}, 0), {"field": True})
        self.assertIsNone(unknown_block_at_index({"field": True}, 1))
        self.assertEqual(
            unknown_block_at_index({"field": True}, 1, mapping_applies_to_any_index=True),
            {"field": True},
        )
        self.assertIsNone(unknown_block_at_index([], 0))

    def test_block_value_preserves_unknown_boolean_marker(self) -> None:
        self.assertEqual(block_value({"field": "value"}, "field"), "value")
        self.assertIs(block_value(True, "field"), True)
        self.assertIsNone(block_value(None, "field"))

    def test_dedupe_compacts_strings_stably(self) -> None:
        self.assertEqual(dedupe([" api ", "audit", "api", None, "", "audit", 7]), ["api", "audit", "7"])

    def test_uncertainty_evidence_filters_by_field_markers(self) -> None:
        self.assertEqual(
            uncertainty_evidence(
                [
                    "vpc_config.public_access_cidrs is unknown",
                    "access_config.authentication_mode is unknown",
                    "enabled_cluster_log_types is unknown",
                ],
                ("public_access_cidrs", "enabled_cluster_log_types"),
            ),
            [
                "vpc_config.public_access_cidrs is unknown",
                "enabled_cluster_log_types is unknown",
            ],
        )


if __name__ == "__main__":
    unittest.main()

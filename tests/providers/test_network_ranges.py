from __future__ import annotations

import unittest

from tfstride.providers.network_ranges import is_broad_public_range


class NetworkRangeTests(unittest.TestCase):
    def test_broad_public_range_detects_zero_prefix_and_aliases(self) -> None:
        for value in ("0.0.0.0/0", "::/0", "any", "internet", "*"):
            with self.subTest(value=value):
                self.assertTrue(is_broad_public_range(value))

    def test_broad_public_range_rejects_non_universal_or_invalid_values(self) -> None:
        for value in (
            "0.0.0.0",
            "0.0.0.0/1",
            "10.0.0.0/8",
            "192.0.2.0/24",
            "2001:db8::/32",
            "",
            None,
            "not-a-cidr",
        ):
            with self.subTest(value=value):
                self.assertFalse(is_broad_public_range(value))


if __name__ == "__main__":
    unittest.main()

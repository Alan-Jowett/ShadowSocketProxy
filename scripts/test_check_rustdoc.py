#!/usr/bin/env python3
"""Unit tests for the rustdoc coverage checker's cfg parser."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-rustdoc.py")
SPEC = importlib.util.spec_from_file_location("check_rustdoc", SCRIPT)
assert SPEC and SPEC.loader
CHECK_RUSTDOC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK_RUSTDOC)


class CfgPredicateTests(unittest.TestCase):
    def test_only_predicates_requiring_test_are_selected(self) -> None:
        self.assertTrue(CHECK_RUSTDOC.cfg_requires_test("#[cfg(test)]"))
        self.assertTrue(
            CHECK_RUSTDOC.cfg_requires_test('#[cfg(all(test, feature = "rustls"))]')
        )
        self.assertFalse(
            CHECK_RUSTDOC.cfg_requires_test('#[cfg(any(feature = "rustls", test))]')
        )
        self.assertFalse(CHECK_RUSTDOC.cfg_requires_test("#[cfg(not(test))]"))

    def test_multiline_all_predicate_is_supported(self) -> None:
        attribute = """#[cfg(all(
            test,
            feature = "rustls",
        ))]"""
        self.assertTrue(CHECK_RUSTDOC.cfg_requires_test(attribute))

    def test_exclusion_keeps_non_test_cfg_items_in_scope(self) -> None:
        lines = [
            '#[cfg(any(feature = "rustls", test))]',
            "fn product_item() {}",
        ]
        self.assertNotIn(1, CHECK_RUSTDOC.excluded_test_lines(lines))

    def test_exclusion_covers_test_item_body(self) -> None:
        lines = [
            "#[cfg(test)]",
            "fn test_item() {",
            "    let value = 1;",
            "}",
            "fn product_item() {}",
        ]
        excluded = CHECK_RUSTDOC.excluded_test_lines(lines)
        self.assertEqual(excluded, {0, 1, 2, 3})


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Tests for the repo's focused reccmp function-comparison entrypoint."""

from __future__ import annotations

import logging
import unittest

from tools.reccmp.compare_cli import FunctionCompareLogFilter


def record(name: str, message: str) -> logging.LogRecord:
    return logging.LogRecord(name, logging.WARNING, __file__, 1, message, (), None)


class FunctionCompareLogFilterTests(unittest.TestCase):
    def test_hides_only_global_vtable_size_warning(self) -> None:
        log_filter = FunctionCompareLogFilter()
        self.assertFalse(
            log_filter.filter(
                record(
                    "reccmp.compare.verify",
                    "Recomp vtable is larger than orig vtable for TWindow::`vftable'",
                )
            )
        )

        self.assertTrue(
            log_filter.filter(
                record(
                    "reccmp.compare.core",
                    "Failed to find function symbol with filename and line: TOcean.h:87",
                )
            )
        )
        self.assertTrue(
            log_filter.filter(
                record(
                    "reccmp.compare.match_msvc",
                    "Ambiguous match 0x6129d7 on name CDC::SelectObject",
                )
            )
        )
        self.assertTrue(
            log_filter.filter(
                record(
                    "reccmp.compare.verify",
                    "A different vtable verification warning",
                )
            )
        )


if __name__ == "__main__":
    unittest.main()

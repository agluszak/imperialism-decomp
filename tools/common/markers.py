#!/usr/bin/env python3
"""Reccmp address-marker regexes shared across the tooling.

Source markers are the single ownership authority: a function-kind marker
(`// FUNCTION/STUB/TEMPLATE/SYNTHETIC/LIBRARY: <TARGET> 0xADDR`) in manual
source claims its address. There is no ownership ledger.
"""

from __future__ import annotations

import re

FUNCTION_MARKER_RE_TEMPLATE = (
    r"//\s*(?:FUNCTION|STUB|TEMPLATE|SYNTHETIC|LIBRARY)\s*:\s*{target}\s+"
    r"(?:0x)?([0-9a-fA-F]+)"
)
MANUAL_OVERRIDE_RE_TEMPLATE = (
    r"//\s*MANUAL_OVERRIDE_ADDR\s+{target}\s+"
    r"(?:0x)?([0-9a-fA-F]+)"
)


def function_marker_regex(target: str) -> re.Pattern[str]:
    return re.compile(FUNCTION_MARKER_RE_TEMPLATE.format(target=re.escape(target)), re.IGNORECASE)


def manual_override_regex(target: str) -> re.Pattern[str]:
    return re.compile(MANUAL_OVERRIDE_RE_TEMPLATE.format(target=re.escape(target)), re.IGNORECASE)

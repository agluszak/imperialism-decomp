#!/usr/bin/env python3
"""Hex parsing helpers shared by tooling scripts."""

from __future__ import annotations


def parse_hex_address(value: str) -> int:
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    return int(text, 16)

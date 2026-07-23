"""Read the canonical C++ turn-event vocabulary for source/codegen checks."""

from __future__ import annotations

import re
from pathlib import Path


VOCABULARY_PATH = "include/game/turn_event_codes.h"
_VOCABULARY_RE = re.compile(
    r"^\s*(?P<name>kTurnEvent[A-Za-z0-9_]+)\s*=\s*(?P<code>0x[0-9a-fA-F]+|[0-9]+)\s*,?\s*$",
    re.MULTILINE,
)


def load_turn_event_vocabulary(repo_root: Path) -> tuple[dict[int, str], dict[str, int]]:
    source = (repo_root / VOCABULARY_PATH).read_text(encoding="utf-8")
    by_event: dict[int, str] = {}
    by_name: dict[str, int] = {}
    for match in _VOCABULARY_RE.finditer(source):
        name = match.group("name")
        event = int(match.group("code"), 0)
        if name in by_name:
            raise ValueError(f"{VOCABULARY_PATH}: duplicate name {name}")
        if event in by_event:
            raise ValueError(
                f"{VOCABULARY_PATH}: duplicate value 0x{event:04x} "
                f"for {by_event[event]} and {name}"
            )
        by_name[name] = event
        by_event[event] = name
    if not by_event:
        raise ValueError(f"{VOCABULARY_PATH}: no turn-event definitions found")
    return by_event, by_name

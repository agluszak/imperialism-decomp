#!/usr/bin/env python3
"""Resolve Ghidra jmp-thunk / alias names to authoritative real names in C text.

Imperialism's ``.text`` opens with an ILT jmp table plus a scatter of linker jmp
stubs. Ghidra prints calls through those stubs under the *stub's* auto-name
(``thunk_Foo``) or under an alias that collides with the real symbol's bare name.
This module rewrites such tokens to the resolved real name, so promoted bodies and
ad-hoc decompiles read against real symbols.

Two name families need different handling to avoid corrupting output:

  * ``thunk_*`` names are genuine Ghidra thunk auto-names that only ever appear as
    thunk calls. The decompiler may print them qualified by the *target's* class
    (e.g. ``TCity::thunk_Foo``); we consume any leading namespace qualifier(s) and
    rewrite the whole token to the authoritative real name ``TCity::Foo``.
  * other names come from jmp-stub aliases whose name equals the target's bare name
    and thus collide with real symbols (headers, already-correct qualified calls,
    even type names — a constructor's simple name like ``TGreatPower`` maps to
    ``TGreatPower::TGreatPower``). We only rewrite these when unqualified AND in call
    position (followed by ``(``), so we never double-qualify nor corrupt a cast.

The mapping is built offline from ``config/thunk_map.csv`` (dumped from Ghidra by
``tools.ghidra.dump_thunk_map``) or, in ``decompile_one``, live from the Ghidra DB.
"""

from __future__ import annotations

import re
from pathlib import Path


class ThunkResolver:
    """Compiled ``thunk_name -> real_name`` rewriter for C source text."""

    def __init__(self, thunk_map: dict[str, str]):
        self._map = {k: v for k, v in thunk_map.items() if k and v and k != v}
        self._re = self._compile(self._map)

    @staticmethod
    def _compile(thunk_map: dict[str, str]) -> re.Pattern[str] | None:
        thunk_alts = sorted(
            (re.escape(k) for k in thunk_map if k.startswith("thunk_")),
            key=len,
            reverse=True,
        )
        other_alts = sorted(
            (re.escape(k) for k in thunk_map if not k.startswith("thunk_")),
            key=len,
            reverse=True,
        )
        branches: list[str] = []
        if thunk_alts:
            branches.append(r"(?:[A-Za-z_]\w*::)*(" + "|".join(thunk_alts) + r")")
        if other_alts:
            branches.append(r"(" + "|".join(other_alts) + r")(?=\s*\()")
        if not branches:
            return None
        # The leading `~` exclusion keeps a bare-name alias (e.g. ``CWnd`` ->
        # ``CWnd::~CWnd``) from re-qualifying a name that is already a destructor
        # token (``Foo::~CWnd(`` / ``~CWnd(``). Without it the rewrite is not a
        # fixpoint and appends ``::~CWnd`` on every pass. A genuine bare call
        # (``CWnd(``, not preceded by ``~``) is still rewritten.
        return re.compile(r"(?<![:\w~])(?:" + "|".join(branches) + r")\b")

    def resolve(self, c_text: str) -> str:
        if self._re is None:
            return c_text
        return self._re.sub(
            lambda m: self._map[next(g for g in m.groups() if g is not None)], c_text
        )

    def __bool__(self) -> bool:
        return self._re is not None


def load_thunk_map(path: Path) -> dict[str, str]:
    """Load ``config/thunk_map.csv`` (``thunk_name|real_name``) into a dict.

    Returns an empty dict when the file is absent so offline consumers degrade
    gracefully (the resolver becomes a no-op).
    """
    if not path.exists():
        return {}
    from tools.common.pipe_csv import read_pipe_rows

    out: dict[str, str] = {}
    for row in read_pipe_rows(path):
        thunk = (row.get("thunk_name") or "").strip()
        real = (row.get("real_name") or "").strip()
        if thunk and real and thunk != real:
            out[thunk] = real
    return out


def dump_thunk_map(thunk_map: dict[str, str]) -> str:
    """Serialize a thunk map to deterministic ``thunk_name|real_name`` CSV text."""
    lines = ["thunk_name|real_name"]
    lines.extend(f"{k}|{thunk_map[k]}" for k in sorted(thunk_map))
    return "\n".join(lines) + "\n"

#!/usr/bin/env python3
"""Pure vtable auto-extent boundary rules (no Ghidra imports; unit-testable).

Shared by ``tools.ghidra.vtable_slots`` (the extractor) and the tooling tests.
Encodes the lessons of the TMapMaker/stretch-table incident: a run of null
slots followed by more function pointers must NOT silently extend the current
class's vtable — the resumed pointers usually belong to an adjacent table
(``stretch<T>`` and other non-RTTI/template tables have no slot-0 classname
getter, so the RTTI-getter boundary check alone cannot see them).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ExtentDecision:
    stop: bool
    reason: str  # "", "known_vtable", "rtti_getter", "unresolved", "resume_after_null_run"


def is_rtti_getter(name: str | None) -> bool:
    """True if a slot target looks like a class's slot-0 classname/RTTI getter.

    The T-tree is MFC-rooted at CObject, where slot 0 of every class vtable is a
    ``GetRuntimeClass``-family getter (named ``Get<Class>ClassNamePointer`` here).
    Encountering one at slot index > 0 means we have run off the end of this
    vtable into the *next* class's table — a reliable auto-detect boundary.
    """
    if not name:
        return False
    return name == "GetRuntimeClass" or "ClassNamePointer" in name


def extent_decision(
    index: int,
    is_null: bool,
    resolved_name: str | None,
    null_run_seen: bool,
    at_known_vtable: bool = False,
    use_getter_heuristic: bool = True,
) -> ExtentDecision:
    """Decide whether auto-extent detection must stop BEFORE slot ``index``.

    ``null_run_seen`` is true once at least one null slot has been emitted for
    this vtable. Rules, in order:

    0. ``at_known_vtable``: this slot's ADDRESS is another known (annotated)
       vtable's base — a precise reviewed boundary, checked before anything
       else (including nulls).
    1. A slot whose resolved target is another class's slot-0 RTTI getter marks
       the next class's vtable (classic abutting-table boundary). Callers that
       supply the known-vtable-address set should pass
       ``use_getter_heuristic=False``: the T-tree's view branch keeps a real
       class-name VIRTUAL mid-table (TView slot 26 -> TEventHandler's getter),
       which this name heuristic misreads as a boundary — it truncated 245
       view-family extractions at 26 slots before the address-set fix.
    2. A non-null slot that resolves to no function body is trailing data.
    3. A non-null function slot appearing AFTER a null run must not resume the
       table: genuinely-abstract NULL slots at the very END of a vtable are
       indistinguishable from padding before an adjacent non-RTTI table (the
       TMapMaker/stretch<T> case), so resumption requires an explicit :COUNT
       override reviewed by a human.
    """
    if index > 0 and at_known_vtable:
        return ExtentDecision(stop=True, reason="known_vtable")
    if is_null:
        return ExtentDecision(stop=False, reason="")
    if index > 0 and use_getter_heuristic and is_rtti_getter(resolved_name):
        return ExtentDecision(stop=True, reason="rtti_getter")
    if index > 0 and resolved_name is None:
        return ExtentDecision(stop=True, reason="unresolved")
    if null_run_seen:
        return ExtentDecision(stop=True, reason="resume_after_null_run")
    return ExtentDecision(stop=False, reason="")

# City + University Reverse-Engineering Plan

Date: 2026-02-15

## Scope

This plan focuses on:
- University civilian unlock logic (tech-gated units)
- University recruitment order flow (UI -> game-state command)
- Persistence of recruitment/production orders (save/load and in-memory tables)
- Cost/resource deduction path for creating civilians

## Known Starting Facts

- University UI builders are currently identified as:
  - `BuildUniversityDialogControls @ 0x00474ac5`
  - `BuildUniversityRecruitmentRows @ 0x00475f84`
- Generic city production dialog path (non-specialized buildings):
  - `OpenCityViewProductionDialog @ 0x004ce5a0`
- City production slot persistence is already confirmed at city offsets `+0x1DC` and `+0x1FC`.

## Work Plan

1. Locate university open/refresh/apply handlers
- Find callers and event handlers for `BuildUniversityDialogControls`/`BuildUniversityRecruitmentRows`.
- Recover missing thunk/vtable links in `0x00474xxx..0x00478xxx` as needed.
- Name dialog lifecycle functions: open, refresh, apply, commit/cancel.

2. Map unlock conditions to technologies
- Identify code branches that hide/disable forester/rancher/driller rows.
- Resolve tech-check function(s) and the tech-state storage table/bitfield.
- Build mapping: civilian type -> required tech id/flag -> UI enable rule.

3. Trace recruitment order submission path
- From row controls (`civ*`, `ucl*`, `num*`) trace click handlers and action tags.
- Identify command objects or direct state writes for "recruit civilian" orders.
- Record exact parameter payload (civilian type, quantity, city id/slot).

4. Trace deduction of resources and cash
- Follow submit/commit handler into economy/inventory calls.
- Confirm where these are deducted:
  - Expert workers
  - Paper
  - Cash
- Document whether deduction is immediate, queued, or end-turn processed.

5. Confirm persistence model
- Find in-memory storage for queued university recruits and active recruit counters.
- Find serializer/deserializer functions and offsets for this data.
- Verify save/load path and any network sync path.

6. Normalize naming + documentation in Ghidra
- Rename key functions and variables (verb-first, readable semantics).
- Add plate comments + focused inline comments on unlock checks and commit path.
- Keep ambiguity notes where evidence is not yet conclusive.

## Deliverables

- Updated function names/comments in Ghidra for university order pipeline.
- `imperialism-decomp.md` sections for:
  - unlock logic
  - recruit commit/deduction flow
  - save/load offsets
- `bitmap-ids.md` canonical icon table.
- `technology-unlocks.md` with extracted Imp1 tech-unlock notes used in this pass.

## Verification Checklist

- [ ] Forester unlock confirmed in code and tied to specific tech flag
- [ ] Rancher unlock confirmed in code and tied to specific tech flag
- [ ] Driller unlock confirmed in code and tied to specific tech flag
- [x] Recruit order data structure identified (entry table + key fields mapped)
- [x] Resource deduction call site identified (core entry callback resolved)
- [x] Save/load offsets for recruitment orders identified (entry archive sync resolved)
- [ ] Ghidra comments updated for all critical decision points

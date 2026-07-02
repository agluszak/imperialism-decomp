# Reference

Durable layout contracts and game-domain knowledge. These are lookup references, not
workflow guides (those are in `.claude/skills/`), not the active backlog (use Beads),
and not the change log (use clear git commit messages for change-specific commands,
validation, and score deltas).

## Decompilation / layout contracts

- `construction.md` — long-form "real C++ construction and inheritance" rules: the full
  examples, recipes, and rationale behind the crisp principles in `AGENTS.md` (the
  mechanically-checkable parts are enforced by `just antipattern-gate` / `marker-gate`).
- `imperialism-decomp.md` — master function reference: startup entry chain
  (PE entry -> MFC app lifecycle -> main loop), city-screen building/icon mappings,
  strategic map order/civilian findings, and university/city-production notes,
  with confirmed code addresses.
- `tradecontrol_redecomp_contract.md` — `TradeControl` field layout (0x00–0x94) and
  `TControl` method signatures with addresses/conventions.
- `tgreatpower-power-score-family.md` — TGreatPower vtable slots 0x86/0x8e-0x9e
  recovered ground truth: slot map with bodies/semantics, CIterator, the
  border-link check receiver, named float/data globals, nation-array layout,
  and the TListObject slot-0x28 drift caveat.
- `TDiplomacyMapView_layout.md` — discovered offsets for `TDiplomacyMapView`
  (mask-buffer / packed-color runs, frame/legend fields).

## Game-domain knowledge

- `bitmap-ids.md` — UI bitmap-ID → feature map (buildings, units, resources, terrain).
- `technology-unlocks.md`, `tech-experiment-university-unlocks.md` — tech tree
  gating and university recruitment evidence. Active university tracing work is in
  Beads issue `imperialism-decomp-1uj.34`.
- Civilian unit orders and command dispatch facts are in `imperialism-decomp.md`.
  Active map-order icon-state tracing is in Beads issue `imperialism-decomp-1uj.38`.
- `cursor-code-usage-sites.md`, `cursor-resource-mapping.md`, `cursor-semantics-exe.md`
  — game cursor types, resource mapping, control semantics.
- `gob-stringtable-workflow.md`, `tabsenu-gob-findings.md` — GOB resource/string-table
  structure and extraction notes.
- `strenu-strings.tsv` (+ `strenu-index-sample.txt`) — extracted UI/localization string
  table (`id`, `block`, `index`, `text`); the fastest text→resource-ID lookup.
- `manual_text.txt` — extracted game manual; baseline gameplay/mechanics reference.

## Moved Backlog

Former plan/worklist documents were removed after their full text was preserved in
Beads issue design fields. Use the Big Goal epic (`imperialism-decomp-1uj`) and
`bd ready` for active work.

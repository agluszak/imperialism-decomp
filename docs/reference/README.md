# Reference

Durable layout contracts and game-domain knowledge. These are lookup references, not
workflow guides (those are in `.claude/skills/`) and not the execution log
(`docs/worklog.md`).

## Decompilation / layout contracts

- `imperialism-decomp.md` — master function reference: startup entry chain
  (PE entry → MFC app lifecycle → main loop) and city-screen building/icon mappings,
  with confirmed code addresses.
- `tradecontrol_redecomp_contract.md` — `TradeControl` field layout (0x00–0x94) and
  `TControl` method signatures with addresses/conventions.
- `TDiplomacyMapView_layout.md` — discovered offsets for `TDiplomacyMapView`
  (mask-buffer / packed-color runs, frame/legend fields).

## Game-domain knowledge

- `bitmap-ids.md` — UI bitmap-ID → feature map (buildings, units, resources, terrain).
- `technology-unlocks.md`, `tech-experiment-university-unlocks.md`,
  `city-university-research-plan.md` — tech tree gating and university recruitment.
- `map-orders-research-plan.md` — civilian unit orders and command dispatch.
- `cursor-code-usage-sites.md`, `cursor-resource-mapping.md`, `cursor-semantics-exe.md`
  — game cursor types, resource mapping, control semantics.
- `gob-stringtable-workflow.md`, `tabsenu-gob-findings.md` — GOB resource/string-table
  structure and extraction notes.

---
name: sync-pipeline
description: Own the derived-artifact pipeline for the Imperialism decomp — symbols.csv, function ownership, autogen stubs, name overrides, and the Ghidra DB resync (regen-stubs / sync-ghidra / db-resync). Use when editing markers changes ownership, when running or debugging a resync, when symbols.csv rows look wrong (type flips, junk thunk rows, size clamps), when stubs collide or go missing at link time, or when deciding where a curated name belongs.
---

# Sync pipeline

Who owns which state, which command regenerates what, and the known ways a resync
goes wrong. The three canonical playbooks live in `docs/workflows.md`; the DB
mutation ledger + re-run procedure in `docs/ghidra-db-mutations.md`.

## Authority map (edit the owner, never the derived copy)

| State | Owner (edit this) | Derived (never hand-edit) |
|---|---|---|
| Function names/prototypes (curated) | `config/function_name_overrides.csv` | names in symbols.csv, stubs, Ghidra DB |
| Address ownership / stub suppression | `// FUNCTION:`-family markers in source | `config/function_ownership.csv` (`marker_sync` rows) |
| Curated stub suppression w/o marker | ownership rows with a curated note (below) | — |
| Symbol table for reccmp | Ghidra DB (via `sync-ghidra` merge) | `config/symbols.csv` (curated name/proto/type survive the merge) |
| Vtable identity | `// VTABLE:` annotation + real inheritance | any symbols.csv row at that address is a bug (merge drops them) |
| Reference decompiles | Ghidra DB | `src/ghidra_autogen/`, `include/ghidra_autogen/` |
| Linkable stubs | symbols.csv + ownership | `src/autogen/stubs/` |
| Confirmed CRT/MFC library identity | `config/msvc500_library_overrides.csv` | symbols.csv name/symbol/proto + `src/game/library_msvc500_overrides.cpp` marker |

Surgical symbols.csv edits are allowed (deleting junk rows); a full resync
re-derives the file, and the merge preserves curated values by address.

## Library identity (a FID miss is NOT game code)

Ghidra FID is heuristic — it has minimum-length/score thresholds, so it silently
skips tiny or aliased CRT/MFC functions (the canonical case: `rand` at
`0x005e83f0`, whose body is the MSVC LCG `state*0x343fd + 0x269ec3`,
`(state>>16)&0x7fff`). `apply_msvc500_library_region.py` only sees functions FID
returned, so a miss keeps its invented Ghidra name (`GenerateThreadLocalRandom15`)
with no `_rand` symbol and no library ownership — forever.

The **reviewed override layer** fixes such rows durably:

- Add a row to `config/msvc500_library_overrides.csv`
  (`address|name|symbol|prototype|library_family|object_member|evidence`).
- `just apply-library-overrides` (idempotent; auto-runs inside `regen-stubs`)
  projects it into symbols.csv (name/symbol/prototype, `provenance=msvc500_library_override`)
  and ensures a `// LIBRARY:` marker (in `library_msvc500_overrides.cpp`) so
  `sync-ownership` sets `ownership=library`. It only adds a marker where none
  exists, so prototype-only corrections on already-owned FID rows don't duplicate.
- Precedence: **reviewed override > FID > existing curated > provisional Ghidra**.
  The FID apply defers override addresses, so a manual FID re-run can't clobber them.
- `just library-identity-gate` (in `just gates`) pins every override into symbols.csv
  + `ownership=library` and ratchets the applied count — regressing rand back to a
  descriptive name fails the gate.

**Before behaviourally naming any MSVC/MFC-range or CRT-shaped function, run
`just library-identify 0xADDR`.** It aggregates symbols/ownership/override/FID/oracle
into a verdict; a missing FID result is explicitly flagged as *not* evidence of game
ownership. The systematic fix (a relocation-masked `.obj` matcher feeding a
`config/msvc500_library_oracle.csv`) is the durable follow-up; until it lands, the
reviewed override CSV is how confirmed identities get pinned.

## The two commands

- **`just regen-stubs`** — after any marker add/remove/move (incl. `just promote`).
  Runs `sync-ownership` (deletion-reconciling) + `symbols-integrity-gate` first,
  then stubgen. Then `just build`.
- **`just db-resync`** — the full resync after any Ghidra DB mutation:
  `tooling-check` → `sync-ghidra` (push-names → prune ILT DB entities → export →
  prune ILT csv rows → thunk map → normalize autogen → symbol gates) →
  `regen-stubs` → `build` → `detect` → `gates` → `stats` → `export-project`.
  `sync-ghidra` alone still mutates the DB (push-names), so `export-project`
  must follow it before committing either way.

## Ownership notes semantics

- `marker_sync` — created and reconciled from source markers; pruned when the
  marker and every file mention of the address disappear (pruned addresses are
  printed — read that list).
- Curated notes (`mfc_runtime_macro`, `name_paired_no_marker`, …) — **never
  pruned**. They suppress autogen stubs for addresses owned by code with no
  marker text: MFC-macro emissions (`IMPLEMENT_DYNCREATE` bodies), name-paired
  methods, and legacy extern-thunk anchors. If a function pairs by NAME (no
  `// FUNCTION:` marker), its suppression row must carry a curated note or the
  next sync re-prunes it and a colliding stub steals the pairing (this exact
  loop happened twice: bad0b410 and again 2026-07-02).

## Junk taxonomy (what a resync used to re-introduce; now auto-cleaned)

1. **ILT-range rows/entities (0x401000–0x409ab5 jmp table).** ANY reccmp entity
   at a jmp-thunk address — a DB Function, a symbols.csv `function` row, or even
   a bare `global` label row — blocks reccmp's thunk auto-resolution and mass-drops
   scores (~400 fns in attempt 1; 238 fns via label rows on 2026-07-02).
   Auto-cleaned by `prune-ilt-db-functions` (DB side, inside sync-ghidra) and
   `prune-ilt-thunks` (csv side, any row type). Keep-rules: address claimed by a
   manual marker, or name referenced by manual source (those stubs must keep
   linking; Ghidra `_00ADDR` name suffixes are stripped before matching).
2. **Rows at `// VTABLE:` addresses.** Always wrong (they clobber the
   marker-derived vtable name); the curated merge drops them; the
   `vtable-collision-gate` proves it.
3. **Label-demoted function rows.** The DB deliberately models the kept thunk
   stubs as labels; the merge preserves a curated `function` row over a bare
   label export row so stubgen keeps emitting the link-required stub. Watch the
   `function types N` count in the merge summary.
4. **Degenerate sizes.** A symbols.csv `function` row with a tiny `size` (1 byte,
   or a switch case-body pseudo-function) clamps reccmp's compare window → a
   byte-identical port scores ~0–26%. Fix the DB (remove the degenerate function
   AND its label — a leftover label re-exports as a blocking `global` row) or
   delete the row for marker-owned addresses.

## Resync failure → fix

| Symptom | Cause | Fix |
|---|---|---|
| Link: unresolved `thunk_*` externals | referenced thunk row lost `function` type or was pruned | merge preserves curated function rows (check `function types` stat); keep-rule matches bare + `_00ADDR`-suffixed names |
| Mass score drops, `thunk_*` fns 100→0 | entity rows (any type) at jmp-thunk addresses | `just prune-ilt-thunks` (runs in sync-ghidra); for non-ILT jmp islands, remove the DB function+label |
| One fn 100→0 after resync | `size=1`/tiny row clamping the window | see Junk taxonomy #4 |
| `just vtable` collapses (~all classes) | rows at VTABLE addrs, or scalar-dtor name drift | `vtable-collision-gate` lists them; see quality-control skill #7 |
| Stubs regenerate at name-paired addresses | ownership row pruned (was `marker_sync`) | re-add with a curated note (`name_paired_no_marker`) — `just stub-count-gate` fails on any stub-count rise, which is the mechanical tell for this trap |
| Stats show +N original-only globals after resync | junk label rows imported into symbols.csv | prune (ILT auto; islands by hand) |

## Name convergence

`push-names --apply` (inside sync-ghidra) writes source-owned names into the DB
before the export so names stop churning. Unpushable names (backticks/spaces,
e.g. `` CFrameWnd::`scalar deleting dtor' ``) are counted as skipped, not errors.
Durable renames go in `config/function_name_overrides.csv` — never hand-edit the
export output; the overrides win in symbols.csv, stubs, and the DB push.

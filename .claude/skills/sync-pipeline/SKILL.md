---
name: sync-pipeline
description: Own the derived-artifact pipeline for the Imperialism decomp — the raw entity inventory (original_entities.csv), generated stubs + symbols overlay, and the Ghidra DB flows (just generate / ghidra-apply-source / refresh-inventory). Use when editing markers changes ownership, when running or debugging a resync, when inventory rows look wrong (type flips, junk thunk rows, size clamps), when stubs collide or go missing at link time, or when deciding where a curated name belongs.
---

# Sync pipeline

Who owns which state, which command regenerates what, and the known ways a resync
goes wrong. The three canonical playbooks live in `docs/workflows.md`; the DB
mutation ledger + re-run procedure in `docs/ghidra-db-mutations.md`.

## Authority map (edit the owner, never the derived copy)

| State | Owner (edit this) | Derived (never hand-edit) |
|---|---|---|
| Function names/prototypes (curated) | manual source decls + `config/original_entities.csv` rows | generated symbols.csv, stubs, Ghidra DB |
| Address ownership / stub suppression | `// FUNCTION:`-family markers in source | (scanned directly at build time — no ledger) |
| Curated stub suppression w/o marker | ownership rows with a curated note (below) | — |
| Symbol table for reccmp | `config/original_entities.csv` + source overlay | `build-msvc500/generated/symbols.csv` (disposable; `just generate`) |
| Vtable identity | `// VTABLE:` annotation + real inheritance | inventory rows at those addresses are dropped by the overlay |
| Reference decompiles | Ghidra DB | `just seed-function` / refresh evidence export (build dir, uncommitted) |
| Linkable stubs | original_entities.csv + source markers | `build-msvc500/generated/stubs/` (build artifact) |
| Confirmed CRT/MFC library identity (reviewed) | `config/msvc500_library_overrides.csv` | inventory name/symbol/proto + `src/game/library_msvc500_overrides.cpp` marker |
| CRT/MFC identity (object-matcher oracle) | `libcmt.lib`/`nafxcw.lib` via `just build-library-oracle` | `config/msvc500_library_oracle.csv` + inventory + `src/game/library_msvc500_oracle.cpp` marker |

Surgical inventory edits are allowed (deleting junk rows); a full resync
re-derives the file, and the merge preserves curated values by address.

## Library identity (a FID miss is NOT game code)

Ghidra FID is heuristic — it has minimum-length/score thresholds, so it silently
skips tiny or aliased CRT/MFC functions (the canonical case: `rand` at
`0x005e83f0`, whose body is the MSVC LCG `state*0x343fd + 0x269ec3`,
`(state>>16)&0x7fff`). `apply_msvc500_library_region.py` only sees functions FID
returned, so a miss keeps its invented Ghidra name (`GenerateThreadLocalRandom15`)
with no `_rand` symbol and no library ownership — forever.

The **reviewed override layer** fixes such rows durably:

- Add a row to `config/reviewed_library_identities.csv`
  (`address|name|symbol|prototype|library_family|object_member|evidence`) — the ONE
  reviewed identity table (hand overrides + accepted object-matcher results).
- `just apply-library-overrides` (idempotent) ensures a `// LIBRARY:` marker (in
  `library_msvc500_overrides.cpp`); the name/symbol/prototype projection happens as
  a generation-time overlay (tools/generate_symbols.py) so
  ownership derives from the markers directly. It only adds a marker where none
  exists, so prototype-only corrections on already-owned FID rows don't duplicate.
- Precedence: **reviewed override > FID > existing curated > provisional Ghidra**.
  The FID apply defers override addresses, so a manual FID re-run can't clobber them.
- `just library-identity-gate` (in `just gates`) pins every reviewed row into the
  generated overlay + a LIBRARY marker — regressing rand back to a descriptive
  name fails the gate.

**Before behaviourally naming any MSVC/MFC-range or CRT-shaped function, run
`just library-identify 0xADDR`.** It aggregates symbols/ownership/override/FID/oracle
into a verdict; a missing FID result is explicitly flagged as *not* evidence of game
ownership.

### The object-matcher oracle (systematic identity)

`just build-library-oracle` is the authoritative identity source — it does not
depend on FID. It parses the vendored `vendor/msvc500/lib/{libcmt,nafxcw}.lib` COFF
object members, masks each function's relocation fields (call/jmp targets, absolute
data refs) and trims alignment padding to a normal form, then matches every
executable function's bytes against it. An exact-size, exact-masked match is a
confident identity regardless of where the linker placed anything. Output:
`build-msvc500/evidence/library/msvc500_library_oracle.csv` (uncommitted report;
`address|name|symbol|prototype|library|member|match_kind|confidence|candidate_count`).
Accepting a match = copying it into `config/reviewed_library_identities.csv`.

`just apply-library-oracle` (idempotent) projects the
confident, unique matches: it **upgrades the exact decorated `symbol` + prototype**
on already-library rows, and **converts unowned FID-missed functions** (in the dense
range, large enough, invented name unreferenced in source) to library ownership.
Guards that keep it safe:
- Bodies shared across multiple executable addresses (empty ctors/dtors, trivial
  thunks) are demoted to `duplicate-body/review` — byte matching can't disambiguate
  them, so they are never auto-applied.
- Manually curated game code is **never** rewritten. A confident unique match owned
  by a game `.cpp` (e.g. libcmt float-conversion internals ported as
  `bignum96_math.cpp`) is a mislabel routed to `config/msvc500_library_oracle_review.csv`
  and flagged by `library-identity-gate` unless acknowledged in
  `config/library_oracle_gamecode_allowlist.csv`. Moving one to library needs a build
  to confirm its callers still link.

Precedence: **reviewed override > object-match > FID > curated game identity >
provisional Ghidra**. Library names/prototypes converge into the Ghidra DB on the
next refresh (`ghidra-apply-source` pushes names over the
dense range).

## The two commands

- **`just build`** — after any marker add/remove/move; it regenerates the build
  inputs (source index + stubs) from current markers automatically.
  Runs `symbols-integrity-gate` first,
  then stubgen. Then `just build`.
- **`just ghidra-apply-source-full`** — after meaningful source-model changes:
  `build` → apply the source model → `export-project`. **`just refresh-inventory`**
  — after intentional DB boundary mutations (prune ILT DB entities → export →
  prune ILT csv rows → thunk map → normalize autogen → symbol gates) →
  ownership sync → `build` → `detect` → `gates` → `stats` → `export-project`.
  `ghidra-apply-source --apply` alone mutates the DB, so `export-project`
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
   at a jmp-thunk address — a DB Function, an inventory `function` row, or even
   a bare `global` label row — blocks reccmp's thunk auto-resolution and mass-drops
   scores (~400 fns in attempt 1; 238 fns via label rows on 2026-07-02).
   Auto-cleaned by `prune-ilt-db-functions` (DB side, inside refresh-inventory) and
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
4. **Degenerate sizes.** An inventory `function` row with a tiny `size` (1 byte,
   or a switch case-body pseudo-function) clamps reccmp's compare window → a
   byte-identical port scores ~0–26%. Fix the DB (remove the degenerate function
   AND its label — a leftover label re-exports as a blocking `global` row) or
   delete the row for marker-owned addresses.

## Resync failure → fix

| Symptom | Cause | Fix |
|---|---|---|
| Link: unresolved `thunk_*` externals | referenced thunk row lost `function` type or was pruned | merge preserves curated function rows (check `function types` stat); keep-rule matches bare + `_00ADDR`-suffixed names |
| Mass score drops, `thunk_*` fns 100→0 | entity rows (any type) at jmp-thunk addresses | `just prune-ilt-thunks` (runs in refresh-inventory); for non-ILT jmp islands, remove the DB function+label |
| One fn 100→0 after resync | `size=1`/tiny row clamping the window | see Junk taxonomy #4 |
| `just vtable` collapses (~all classes) | rows at VTABLE addrs, or scalar-dtor name drift | `vtable-collision-gate` lists them; see quality-control skill #7 |
| Stubs regenerate at name-paired addresses | ownership row pruned (was `marker_sync`) | re-add with a curated note (`name_paired_no_marker`) — `just stub-count-gate` fails on any stub-count rise, which is the mechanical tell for this trap |
| Stats show +N original-only globals after resync | junk label rows imported into the inventory | prune (ILT auto; islands by hand) |

## Name convergence

`ghidra-apply-source --apply` writes source-derived names into the DB
before the export so names stop churning. Unpushable names (backticks/spaces,
e.g. `` CFrameWnd::`scalar deleting dtor' ``) are counted as skipped, not errors.
Durable renames go in `config/function_name_overrides.csv` — never hand-edit the
export output. The overrides table is retired; original_entities.csv is the single store.

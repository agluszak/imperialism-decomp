# Ghidra DB mutation ledger

The vendored Ghidra database (`vendor/ghidra/exports/Imperialism.gzf`, LFS) is
planned to be replaced with a newer DB in a separate folder. Everything below is
the record of what has mutated the DB, so the still-wanted mutations can be
re-run against the new database.

## Committed mutations (already in the current .gzf, newest first)

From `git log --follow -- vendor/ghidra/exports/Imperialism.gzf`:

| commit | what it did to the DB |
|---|---|
| 3170d5a2 | Propagate Ghidra virtual method names |
| 05dcd197 | Regenerate ghidra_autogen folder (DB names/types refresh) |
| 4a1e94a4 | Regenerate ghidra_autogen folder |
| 0a7ad0c5 | Tier-1 singleton typing, dissolve pseudo-classes, cc overrides |
| 6855af06 | Dissolve placeholder pseudo-class namespaces |
| 1a8390bc | Collapse duplicate Ghidra class datatypes |
| 15750044 | Canonicalize MFC datatypes |
| b41b8790 | Improve MFC class datatypes |
| db7e68fd | Model CString |
| d8cf9200 | Source datatype importer run |
| 97e73bf3 / a9402f72 | Export refreshes |
| 80c2c633 | TCity vtable slot bodies defined (CreateFunctionCmd) |
| 9f94b192 | TAutoGreatPower vtable slot bodies defined |
| 2e01f8ef | TGreatPower vtable slot wiring |
| 68d7c5f9 / 781ca9f3 | Initial vendoring |

Most of these are *derived* mutations (names/types pushed from source or from
imports) and are reproducible on a new DB via the standard pipeline:
`just push-names --apply` + `just import-ghidra` + the apply_* tools
(`apply_mfc_datatypes`, `apply_mfc_rtti`, `apply_source_datatypes`).

## 2026-07-02: gap-repair mutation committed (two bugs found and fixed)

The gap-repair mutation (`tools/ghidra/repair_code_gaps.py --apply` + ILT-range
cleanup + `just sync-ghidra`) was attempted three times against this same live
DB before it stuck. The first two attempts were reverted; the root causes are
recorded here so they aren't rediscovered.

**Attempt 1 (first session).** `repair-code-gaps --apply` created 2167 missing
functions. Reverted because the subsequent `sync-ghidra` export re-introduced
ILT-range (0x401000–0x409ab5) function entities into `config/symbols.csv`,
collapsing `just vtable` (~400 functions lost 100%, hundreds of vtable slots
stopped auto-resolving through jmp thunks).

**Attempt 2.** Fixed the ILT problem by directly deleting the stray Function
entities in the live DB (`FunctionManager.removeFunction`) *before*
`sync-ghidra`, rather than relying on `just prune-ilt-thunks` alone — that tool
turned out to have its own bug (below). `just vtable` held 393/393 through the
full resync this time, but `just stats` regressed hard (-34 aligned functions,
305 lower-similarity, several functions dropping 100% → 0%, e.g.
`CMcWindow::OnKeyDown` at 0x493b30). Reverted again (repo tree + the **live**
Ghidra project both restored from the pre-mutation `.gzf` checkpoint).

**Root causes found and fixed:**

1. **`tools/workflow/prune_ilt_thunks.py`** read `parts[3]` as the CSV `type`
   column, but the schema is `address|name|symbol|size|type|prototype[|provenance]`
   — a `symbol` column was inserted at index 2 at some point without updating
   this tool, so it was actually comparing the `size` field against
   `"function"` and silently pruning **zero rows on every run**, forever.
   Fixed to read `parts[4]`.
2. **`tools/ghidra/repair_code_gaps.py`**'s `CreateFunctionCmd(address)` call
   bounds the new function's body from *already-disassembled* code units. On a
   raw undisassembled gap (the normal case here — that's *why* it's a gap),
   there are no code units yet, so Ghidra silently created a degenerate 1-byte
   function instead of following the real instruction flow — e.g.
   `CMcWindow::OnKeyDown` (0x493b30, real body `ret 0xc`, 3 bytes) became a
   1-byte stub, clamping reccmp's compare window to nothing. Fixed to
   `DisassembleCommand` the target first when no instruction exists there yet,
   and to detect+undo (rather than silently leave behind) any function that is
   still 1-byte after disassembling, reporting it as `DEGENERATE` instead.

**Attempt 3 (this fix): committed.** Re-ran the full procedure with both fixes:
`repair-code-gaps --apply` (493 created, 0 failed, 23 genuinely degenerate —
removed and reported, not left corrupting anything), direct ILT-range
Function-entity deletion (2479 removed), `push-names --apply`, `import-ghidra`,
`just sync-ghidra` (full resync — also re-introduced 393 stale
`'vftable'`-typed symbols.csv rows colliding with real header `// VTABLE:`
annotations, same pattern as the merge step; deleted by address), then
`just export-project` last. Verified: `just gates` clean, `just vtable` 393/393
100%, `just stats` **zero regressions** vs the pre-mutation baseline (confirmed
both mechanically and by hand: `CMcWindow::OnKeyDown` and
`TFileBasedDocument::CreateObject` back to their correct pre-mutation scores).

## Procedure for a future re-run (this DB or a newer one)

1. Restore/open the DB; run the standard reproduction pipeline first
   (`push-names --apply`, datatype appliers, `import-ghidra`).
2. Run `just repair-code-gaps` (dry-run), review, then `--apply`. The tool now
   disassembles gaps before creating functions and self-reports any residual
   degenerate (1-byte) result — treat a nonzero `degenerate` count as worth a
   look, not silently ignorable.
3. **Before `just sync-ghidra`:** delete any stray Function entities in the
   ILT range (0x401000–0x409ab5) directly in the live DB
   (`FunctionManager.removeFunction`) — `just prune-ilt-thunks` only handles
   the `config/symbols.csv` side and won't fix DB-side ILT function entities.
4. Gate every step: `just symbols-integrity-gate` (dupes), `just vtable`
   (393/393 must stay 100%), `just stats` (no mass regressions) — all three
   caught real problems across these attempts.
5. After `just sync-ghidra`, check for stale `'vftable'`-typed
   `config/symbols.csv` rows colliding with real `// VTABLE:` header
   annotations (`just vtable-collision-gate` reports them by address) — delete
   them; this happens on every full resync so far.
6. `just export-project` LAST (after push-names), so the committed `.gzf`
   carries everything.

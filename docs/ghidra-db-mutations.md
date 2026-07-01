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

## Applied 2026-07-02 but NOT committed (reverted repo-side; re-run on the new DB)

1. **`tools/ghidra/repair_code_gaps.py --apply`** — created **2167 missing
   functions** (0 failures) at vtable-slot targets, ILT jmp targets, and
   symbols.csv function addresses that Ghidra had never defined. The DB change
   itself is good (fills the code gaps that blind xrefs/decompile and reccmp
   extents).
2. **`just sync-ghidra`'s `push-names --apply`** — pushed 1113 source-owned names
   into the DB (normal, re-runnable pipeline step).

**Why the repo-side fallout was reverted (commit references the incident):** the
subsequent `sync-ghidra` export of the enlarged function set re-introduced
thunk-range entities into `config/symbols.csv`, and `just vtable` collapsed
(hundreds of slots stopped auto-resolving through ILT thunks; ~400 functions lost
100% alignment). `CreateFunctionCmd` also auto-creates functions at *flow
targets*, which defined the 5-byte ILT jmp bodies themselves as functions.

## Procedure for the new-DB folder

1. Restore/open the new DB; run the standard reproduction pipeline first
   (`push-names --apply`, datatype appliers, `import-ghidra`).
2. Run `just repair-code-gaps` (dry-run), review, then `--apply`.
3. **Before `just sync-ghidra`:** ensure ILT-range functions (0x401000–0x409ab5)
   are either deleted, marked as Ghidra thunk functions, or excluded by the
   exporter — reccmp's vtable slot resolution requires bare (entity-free) jmp
   thunks. `just prune-ilt-thunks` handles the symbols.csv side; the failure mode
   is thunk rows/entities surviving into the export.
4. Gate every step: `just symbols-integrity-gate` (dupes), `just vtable`
   (379/379 must stay 100%), `just stats` (no mass regressions) — all three
   caught real problems during the 2026-07-02 attempt.
5. `just export-project` LAST (after push-names), so the committed .gzf carries
   everything.

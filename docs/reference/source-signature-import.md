# Source → Ghidra signature projection: coverage diagnosis (PR #91)

## Question

`ghidra-apply-source-full` runs `build → import-ghidra → ghidra-apply-source
--apply --strict → export`. Strict convergence checks that **names** converge.
Yet `just in-stack-audit` finds **214 source-owned** functions whose Ghidra
signature is weaker than the C++ declaration already present in source (the
missing parameters surface as `in_stack_*` reads). Why does the PDB import miss
them?

## Experiment (read-only)

`tools/ghidra/signature_probe.py` captured the DB signature + `in_stack` for 16
representative source-owned functions (free / `__thiscall` / `__stdcall` /
vtable override / MFC override / ctor / struct-return / packed-args / unknown-cc),
**before and after a fresh `just import-ghidra`** against a matching build.

Result: **0 of 16 changed.** `before == after`, byte for byte. The import run
itself reported `Successes: 9149, Functions changed: 148, Missing types: <none>` —
i.e. it "succeeded" on ~everything while changing almost nothing, and touched
none of the affected functions.

## Root cause (toolchain, systemic)

`reccmp-ghidra-import` builds each function's parameter list from the PDB's
argument-list type records (`cvdump -t`; the importer skips any function whose
current Ghidra signature already matches the type it derived — see
`function_importer.matches_ghidra_function`).

On this **MSVC500 (1997)** recomp PDB, the modern cvdump (14.00.23611, the one
reccmp ships and uses) extracts:

| `cvdump` section | records |
|---|---|
| `-s` symbols (`S_GPROC32`) | **8549** (names/addresses/return-type index resolve fine) |
| `-t` types (`LF_MFUNCTION` / `LF_ARGLIST`) | **0** — the `*** TYPES` section is empty |

The CodeView **type** stream MSVC 5.0 emitted is in a format/location the modern
cvdump does not parse, so reccmp gets **no argument lists for any function**. The
importer therefore constructs a parameter-less signature, which matches the
parameter-less signature Ghidra already inferred for these functions → it skips
them. Names converge (from symbols); **parameter lists cannot converge from the
PDB on this toolchain.**

This is why the "214" never move: it is not an importer bug to patch, it is a
data source that does not carry the needed information.

## Implication for the fix (PR #92)

The PDB is a dead end for parameters here. The authoritative signature source
must be the **source model** (`tools/source_model.py` already parses the C++
declaration head into a prototype). The supplemental projection the plan
mentioned as a fallback is actually the *primary* mechanism: read the source
prototype and apply a complete signature via
`updateFunction(DYNAMIC_STORAGE_FORMAL_PARAMS)`, verify by re-decompile, and
check signature convergence **against the source model**, not the PDB.

## Failure taxonomy (the 16, generalising to the 214)

Ownership is already known (audit); these sub-categories drive *how* the source
signature must be projected:

1. **Plain missing trailing params** — the common case. DB has 0–2 params, source
   declares more; each `in_stack` offset is exactly a declared parameter.
   `ImperialismCommandLineInfo::ParseParam` (DB 2, src 3 — missing `BOOL bLast`
   @0xc), `TFATemplateDialog::TFATemplateDialog` (DB 0, src 1 @0x4),
   `TSortedList::AddHead` (0→1), `TFileStream::ReadBytes` (0→2),
   `TWindow`/`TControl::HandleEvent` (1→3). *Fix:* project the source prototype
   with dynamic-storage formal params.

2. **Struct return (sret hidden pointer)** — source returns a struct by value, so
   the ABI inserts a hidden return-pointer parameter at the first stack slot and
   the real args shift up. `TView::TransformPointViaSlot138` returns `CPoint`;
   DB `param_1@0x4` is the sret pointer, `in_stack@0x8` is the real `CPoint*`.
   *Fix:* the projection must model return-by-value → hidden pointer (reccmp's
   importer already has this `X* __return_storage_ptr` handling; the source
   projector needs the same rule).

3. **Short/bool packing & sub-dword alignment** — the compiler packs two `short`s
   into one dword (`short@0x4` + `short@0x6`), or a `bool` byte; Ghidra models the
   second arg dword-aligned at `0x8`, so the real read at `0x6` is unbound.
   `TPicture::SetPictureResourceIdAndRefresh`, `ResolveCivilianTileSelection…`,
   `TOcean::EnsurePortZoneForTile`. *Fix:* needs `CUSTOM_STORAGE` with the packed
   stack offsets, or acceptance that dword-aligned vs packed is a structural
   difference (the convergence audit must treat these carefully, not by textual
   offset).

4. **Calling-convention mismatch** — DB convention disagrees with source.
   `GetMapContextActionLabelTokenByActionCode`: DB `__cdecl`, source `__stdcall`.
   *Fix:* project the convention from source (this alone re-lays the frame).

5. **`cc = unknown` / spurious `in_stack`** — when Ghidra can't determine the
   convention, params are unplaced and *locals* can masquerade as `in_stack`.
   `TMapMaker::ReindexContiguousCityRegionIds` declares **zero** params in source
   yet shows `in_stack@0x14` — a high offset that is a local, not a parameter.
   `TRadioTextCluster::AddItem`, `TViewMgr::DispatchLocalizedUiMessageWithTemplate`
   (unknown cc; the latter also has `CString`-by-value params spanning slots).
   *Fix:* set the convention from source first; some residual `in_stack` here are
   genuinely not parameters and must be recognised as such (not "fixed").

## Deliverable status

PR #91 is diagnosis only — no committed DB change (the fresh import ran in the
live project for observation; the vendored `.gzf` stays at the clean #90 state).
`signature_probe.py` is retained; it becomes the basis of the
`source-signature-audit` / convergence check in PR #92.

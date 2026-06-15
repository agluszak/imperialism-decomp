# Retail-MFC migration plan

Proven viable (worklog 2026-06-16): the MSVC500 toolchain ships retail MFC 4.2
(`C:\msvc\mfc\{include,lib}`); `<afx.h>` compiles, `nafxcw.lib` links (with the Win32
import libs), and the library code is **byte-identical** to the original
(`CObject::IsKindOf` matches opcode-for-opcode). MFC `CObject` always carries all 5
vtable slots (GetRuntimeClass / ~ / Serialize / AssertValid / Dump — `AssertValid`/`Dump`
are **not** `#ifdef _DEBUG`-guarded), so the layout matches the game's root.

Payoff (proxy over 50 MFC-named functions in `symbols.csv`): 7@100, 6 partial, 37 missing
→ ~43/50 would improve, plus the larger unnamed MFC surface.

## Why this is NOT a one-shot change

- `afx.h` is monolithic: it defines `CObject`/`CString`/`CPtrList`/`CArchive`/
  `CMapPtrToPtr`/… together, colliding with our 16 hand-rolled `C*` headers — they migrate
  as a unit, and `CObject` is the universal root.
- Signature divergence forces a wide sweep: MFC `GetRuntimeClass() const` vs ours
  (non-const) means **~120 override sites across 128 files** must gain `const`; MFC
  `Serialize(CArchive&)` vs ours (`CArchive*`); MFC `AssertValid()`/`Dump(CDumpContext&)`
  vs our `AssertValidOrSlot0c()`/`DumpOrSlot10(int)`.
- `// LIBRARY:` annotations cannot coexist with `// FUNCTION:` for the same address —
  otherwise the marker-hygiene gate fails. Replace `FUNCTION` with `LIBRARY` when
  reclaiming a symbol from `nafxcw.lib`.

So there is **no green checkpoint for a single blind pass**. Execute as staged increments,
each ending green (`just build` + `just gates` + targeted `just compare`).

## Tooling ready

- `tools/mfc/gen_library_annotations.py` → can bulk-emit `include/game/library_mfc.h`
  (`// LIBRARY: IMPERIALISM 0xADDR` + qualified name, inside `#if 0`). Prefer placing
  markers in the owning `.cpp` (e.g. `src/game/CObject.cpp`) so ownership stays obvious;
  use the generator for large batch stages (CString, collections) where a single header
  is cleaner. Second line must be the **true MFC name** (fix provisional names like
  `TNetMgr::GetCObjectRuntimeClass`→`CObject::GetRuntimeClass` in `symbols.csv` during
  the relevant stage).
- CMake `-DIMPERIALISM_LINK_MFC=ON` links `nafxcw.lib` + import libs (ON in `justfile`
  since stage 2). Import set now includes `oledlg.lib` (pulled in by `oledlgs2.obj`).
  `/FORCE:MULTIPLE` removed once duplicate hand-rolled bodies were replaced with
  `// LIBRARY:` markers (CString ctor/dtor, CArchive Close/FillBuffer, CMapPtrToPtr,
  CPtrList core, CDC/CClientDC/CGdiObject dtors, CDocument::DisconnectViews).

### LIBRARY marker shape (in-source)

When a function body is removed because `nafxcw.lib` owns the implementation, leave
comment-only ownership in the class `.cpp` — no empty stub body:

```cpp
// LIBRARY: IMPERIALISM 0x00412bf0
// CObject::AssertValid
```

reccmp pairs by address + qualified name; the marker is scanned from comments even when
wrapped in `#if 0` (see `library_msvc.h`), but in-source placement keeps
`function_ownership.csv` sync obvious.

## Progress (2026-06-16)

| Stage | Status | Notes |
|-------|--------|-------|
| 1 — signature prep | **done** | `Serialize(CArchive&)`, `AssertValid() const`, `Dump(CDumpContext&) const`; `CDumpContext` placeholder; `symbols.csv` renamed AssertValid/Dump |
| 2 — link MFC + CObject swap | **mostly done** | `IMPERIALISM_LINK_MFC=ON`; `LIBRARY` markers for CObject/CRuntimeClass core + duplicate CString/CArchive/CMapPtrToPtr/CPtrList/CDC/CDocument symbols; clean link (no `/FORCE:MULTIPLE`); `CRuntimeClass::Store` still local |
| 3 — CString | **done** | All `CString.cpp` bodies reclaimed as `// LIBRARY:`; header uses MFC names (`operator=`, `operator+=`, `AllocBuffer`, `ConcatCopy`, `GetBuffer`, …); manual callers updated; `CompareAnsiStringsWithMbcsAwareness` stays local |
| 4 — CPtrList/CPtrArray/CObList | partial | CPtrList ctor/dtor/RemoveAll/RemoveHead/RemoveTail/GetRuntimeClass reclaimed; node helpers still local |
| 5 — CArchive/CMapPtrToPtr | partial | Close/FillBuffer + `WriteObject` `Serialize(*this)` reclaimed; buffer R/W bodies still local |
| 6 — CWnd/CDC/… GUI | pending | needs `CWinApp`/`AfxWinInit` scaffolding |

Open items for stage 2:

- `classCObject` global (`0x006706e0`) — was a `// GLOBAL:` in our `CObject.cpp`; now
  supplied by MFC data. Confirm reccmp global pairing after a `just compare` pass.
- Scalar deleting destructor (`0x00415f00`) — stays `// SYNTHETIC:` (compiler-generated).
- Pull in `<afx.h>` / drop hand-rolled `CObject.h` once duplicate-symbol pressure from
  overlapping CString/CArchive modules is manageable (or staged with `/FORCE:MULTIPLE`).

## Suggested stage order

1. **Prep sweep (green, no MFC yet):** make our `CObject` virtuals match MFC signatures
   — `GetRuntimeClass() const`, `Serialize(CArchive&)`, rename slots 3/4 to
   `AssertValid() const` / `Dump(CDumpContext&) const`. Sweep all ~120 overrides. Build
   green. **Done.**
2. **Link MFC + core swap:** turn on `IMPERIALISM_LINK_MFC`; remove local `CObject`/
   `CRuntimeClass` bodies reclaimed by `nafxcw.lib`; add `// LIBRARY:` markers in the
   owning `.cpp`; resolve link order; build + reccmp. **In progress.**
3. **CString**, then **CPtrList/CPtrArray/CObList**, then **CArchive/CMapPtrToPtr**, each
   as its own green increment with `LIBRARY` markers (in-source or `library_mfc.h`) and a
   `just compare` delta.
4. **CWnd/CDC/CGdiObject/CDialog/CDocument/CView** GUI surface last (largest, needs the
   `CWinApp`/`AfxWinInit` app scaffolding for a clean static-MFC link).

Track the reccmp delta per stage; the proxy predicts the win concentrates in stages 3–5
(CString/collection/archive internals are the bulk of the unmatched MFC surface).

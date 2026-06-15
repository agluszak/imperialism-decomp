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
- `// LIBRARY:` annotations cannot be added before the hand-rolled defs are removed —
  otherwise the same address is owned by both a `FUNCTION` and a `LIBRARY` marker and the
  marker-hygiene gate fails.

So there is **no green checkpoint for a single blind pass**. Execute as staged increments,
each ending green (`just build` + `just gates` + targeted `just compare`).

## Tooling ready

- `tools/mfc/gen_library_annotations.py` → emits `include/game/library_mfc.h`
  (`// LIBRARY: IMPERIALISM 0xADDR` + qualified name, inside `#if 0`). Extend `MFC_CLASSES`
  as more surface is reclaimed. Second line must be the **true MFC name** (fix provisional
  names like `AssertValidOrSlot0c`→`AssertValid` in `symbols.csv` during the relevant stage).
- CMake `-DIMPERIALISM_LINK_MFC=ON` links `nafxcw.lib` + import libs (OFF by default).
  Mind link order: `nafxcw` before the static CRT (`libcmt`); tune with a real link.

## Suggested stage order

1. **Prep sweep (green, no MFC yet):** make our `CObject` virtuals match MFC signatures
   — `GetRuntimeClass() const`, `Serialize(CArchive&)`, rename slots 3/4 to
   `AssertValid() const` / `Dump(CDumpContext&) const`. Sweep all ~120 overrides. Build
   green. This de-risks the swap by pre-aligning every signature while still using our
   classes.
2. **Link MFC + core swap:** turn on `IMPERIALISM_LINK_MFC`; replace `CObject.h` +
   `CRuntimeClass.h` with `<afx.h>` (or a shim that includes it); delete our `CObject`
   bodies; resolve link order; generate `library_mfc.h` for the CObject/CRuntimeClass set;
   build + reccmp.
3. **CString**, then **CPtrList/CPtrArray/CObList**, then **CArchive/CMapPtrToPtr**, each
   as its own green increment with regenerated annotations and a `just compare` delta.
4. **CWnd/CDC/CGdiObject/CDialog/CDocument/CView** GUI surface last (largest, needs the
   `CWinApp`/`AfxWinInit` app scaffolding for a clean static-MFC link).

Track the reccmp delta per stage; the proxy predicts the win concentrates in stages 3–4
(CString/collection/archive internals are the bulk of the unmatched MFC surface).

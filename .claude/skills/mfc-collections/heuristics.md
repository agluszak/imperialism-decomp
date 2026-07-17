# Field notes (mfc-collections)

Accumulated matching lessons for this skill's domain (migrated from the old
decomp-loop heuristics file; append new ones here).

### Real MFC surface — call it directly, don't model it
*(ex decomp-loop note 15)*


`include/game/mfc.h` includes the **real** `<afx.h>`/`<afxwin.h>`/`<afxcoll.h>`, and the
binary links retail `nafxcw.lib` (see [[real-mfc-linking-viable]]). So `CObject`, `CWnd`,
`CString`, `CPtrList`, `CRuntimeClass`, `POSITION` are the **actual MFC types with real
virtuals/methods** — never re-model them, and don't write raw `(**(code**)(*field+off))()`
against them.

- **Call the MFC method by name** and let it pair via a `// LIBRARY:` annotation (e.g.
  `CObject::IsKindOf` @0x606fc0 is annotated in `CObject.cpp`). A window dtor `[vtbl+4](1)`
  is just `delete cwndptr`; `[vtbl+0xc]` (slot 3) is `AssertValid()`; `CenterWindow`,
  `m_hWnd`, `SendMessageA` are all direct. Took `TWindow::Free` 0x48e2a0 from a stub to a
  faithful 62% with every call site matching (commit 6c69fe86).
- **Never C++-model an MFC class that's already in the header (`CWnd`, `CCmdTarget`,
  `CFrameWnd`, `CDocument`, `CDC`, …) — annotate it.** Mirror `CObject.cpp`/`CDocument.cpp`/
  `MfcRuntime.cpp`: a bodyless `// LIBRARY: IMPERIALISM 0xADDR` + `// Class::Method` comment
  pair (ascending address order), and rename the `symbols.csv` row at that addr to the real
  MFC name. **Caveat:** a LIBRARY function only pairs once our build actually *links* it —
  i.e. some manual code calls it. To "recover" an MFC-derived game class you do NOT model
  `CWnd` — you `class X : public CWnd`, LIBRARY-annotate the CWnd surface it calls, and
  write the real `new X(...)`. See [[cmcwindow-recovery-plan]].
- **A `RUNTIME_CLASS` arg is a data global**: `IsKindOf(0x64b5d0)` → add a `g_pClassDesc<Class>`
  char + `// GLOBAL:` marker at that addr (rename the `symbols.csv` `Class::classRuntimeClass`
  row to it), pass `reinterpret_cast<CRuntimeClass*>(&g_pClassDesc<Class>)`. Same recipe as
  the slot-0 `GetRuntimeClass` descriptors.
- **A "custom stack iterator" over a list field is usually MFC `POSITION` iteration.** A
  local `{pos, parent, flag, code, element}` struct whose advance helper walks
  `node{next@0, prev@4, data@8}` (reading `*(list+4)` = `m_pNodeHead`) is exactly
  `GetHeadPosition()` + `GetNext(pos)`/`GetPrev(pos)` over a `CPtrList`.
- **Generic-named callees are real functions, not "missing".** `FUN_00xxxxxx` is a defined
  function (just unnamed); a 5-byte `JMP` at `0x40xxxx` is an ILT thunk to a named target
  (`just ghidra-listing` the addr to resolve it). Forward-declare + call — minding the
  legacy typedef-cast thunk-signature trap (§12c).
- **Don't fake these two shapes — recover the class instead:** (1) a free callee invoked with
  `ECX=this` is a `__thiscall` *method* on that receiver; (2) `buf = operator new(sz);
  Ctor(buf /*ecx*/, args)` is a real `new RealClass(args)` expression (the banned
  EH-new-factory) — recover `RealClass` and write `new CMcWindow(this)` (ctor 0x493470).

### MFC convention/access traps + CMap embedded tables (extends 15/16)
*(ex decomp-loop note 18)*


Three traps make an MFC-surface helper look like game code needing modeling when it is
really a real MFC method to call directly:

- **`AFX_CDECL` varargs members look like `__thiscall` but are `__cdecl`.** MFC's variadic
  members (`CString::Format`, `AfxTrace`, …) take the hidden `this` as the **first stack
  arg**, not ECX. A leaf doing `MOV ECX,[ESP+4]` then `CALL <thiscall helper>` is such a
  member forwarding `this` to a protected internal — not a free function to port.
  (`0x5ff15e` *is* `CString::Format`; call `cstr.Format(fmt, arg)` + `// LIBRARY:`.)
  Contrast: `this` in ECX *on entry* = real method (note 15).
- **A tiny forwarder into a protected/AfxGetApp path is the library function itself.**
  `0x6185e4` calls the **protected** `DoMessageBox` — only the library fn can, so it *is*
  `AfxMessageBox(LPCTSTR,UINT,UINT)`. Same tell for any "wrapper" touching protected
  MFC members.
- **Verify access/convention against the docker image's `afx.h`, not modern docs.** MFC 4.2
  differs from current `CStringT` (e.g. `CString::FormatV` is protected here though public
  in modern docs). Grep the vendored/docker headers for the member and its access section.
- **Embedded CMap tables (extends 16).** A subobject laid out `{vtbl, m_pHashTable,
  m_nHashTableSize=0x11, m_nCount, m_pFreeList, m_pBlocks, m_nBlockSize=0xa}` (0x1c bytes)
  whose slot 0 is the *inherited* `CObject::GetRuntimeClass` is an MFC **`CMap<>`
  specialization**. Confirm K/V are scalar via the dtor (frees only hash buffer + plex
  chain, no per-element destruction). Model it as a real `CMap<K,ARG_K,V,ARG_V>` member —
  the genuine default ctor emits the `size=17/block=10` init byte-for-byte. Two different
  embedded vtables ⇒ two distinct instantiations. Example: `TModuleLibraryCacheTableStateB`
  @0x498f60 (see [[imperialismapp-keystone-initinstance]]).
- **First-time linkage of an MFC fn causes reccmp re-pairing wobble.** Newly-linked nafxcw
  code shifts the MFC layout, so nearby LIBRARY functions re-pair and a few swing ±1-2pp (a
  big single-fn drop is a mis-pairing artifact, not a real loss). Aggregate stays ~flat;
  refresh the baseline, don't revert clean real-MFC calls.

### CList/CArray twin copies masquerade as class methods and vtables
*(ex decomp-loop note 27)*


A cluster of {ctor writing head/tail/count/free/blocks(+blockSize), dtor doing
walk+FreeDataChain, Serialize doing ReadCount+per-element Read/AddTail} adjacent to a real
class's vtable is a **per-TU template instantiation** (afxtempl CList/CArray compiled into
that TU) — the original had no ICF, so every TU has its own copy. Model the underlying
object (often a file-scope static reachable via an `InitStub`/atexit pair: `MOV ECX,<addr>`
in the static-init gives the object address, the ctor arg gives blockSize) as a real
`CList<...>`/`CArray<...>` global and call the public API; `/Ob1` re-inlines AddTail
identically (TNetMgr::Send 35%→65%). The twin-copy addresses themselves can't pair against
the single recomp COMDAT — leave them to autogen stubs. Linker switches do not fix this:
`/OPT:NOREF` is identical to baseline for the CList rows, while `/OPT:REF` discards
thousands of intentionally-unreferenced recomp bodies and collapses coverage. Bonus:
"mystery globals" inside the object footprint are member aliases (0x6a13e8 = the 0x6a13e0
list's m_pNodeTail).

### Find unknown message handlers by scanning for AFX_MSGMAP_ENTRY records
*(ex decomp-loop note 42)*


To find who handles a custom window message (e.g. the 0x4ef repaint trigger), scan the
original binary's data for the 24-byte AFX_MSGMAP_ENTRY pattern `{nMessage, nCode,
nID, nLastID, nSig, pfn}` with pfn in the image range, then resolve the pfn ILT thunk.
The null terminator entry is followed (in this binary) by the class's window-class
string, which identifies the owner (CIncludeView's map at 0x6489e8 ends before
"AmbitGameWindow"). This is how CIncludeView was recovered as the real main-frame
paint host.

### stretch<T> vs MFC CArray: realloc-double-or-fallback is the discriminator
*(ex decomp-loop note 46)*


Both are growable arrays with a `data/capacity/count` tail, but MFC `CArray` grows by
allocating a fresh block and *copy-constructing* elements across (new + copy + delete),
whereas the project's `stretch<T>` family reallocs in place — request `count*2*stride`
via `ReallocateHeapBlockWithAllocatorTracking`, and on failure realloc to the exact
`count*stride`. That realloc-double-then-exact-fallback shape (no element copy loop on
grow) means `stretch<T>`: model it as a real `class X : public stretch<T, Tag>`
overriding the single-slot append virtual, not an ad-hoc struct. Mac evidence names the
family `stretch<Seapoint>` / `stretch<SeaSegment>` with `Add/operator[]/OverStretch`.

### A non-inline wrapper for a CList AddTail/RemoveTail COMDAT can't match the original's direct dispatch — and __inline makes it worse
*(ex decomp-loop note 56)*


The UI-builder giants call `g_UiWidgetBuildStack006a13e0.AddTail(node)` /
`.RemoveTail()` at every widget push/pop. The original emits each as a *direct
out-of-line dispatch* to the CList template COMDAT: `mov ecx, &list; call
AddTail@0x479b00` (thiscall, callee cleans stack, `ret 4`). The repo routes these
through free-function wrappers `Push/PopUiWidgetBuildStackNode` in
turn_event_dialog_factory.cpp so the AddTail body stays out-of-line. Two failure
modes, neither matches:
- **Wrapper NOT `__inline`** (called many times → past the TU inline budget, note 55):
  emits `call PushUiWidgetBuildStackNode` (a cdecl free fn) + caller `add esp,4`,
  vs the original's `call AddTail` + no caller cleanup. Mismatch at every push/pop,
  AND the cdecl call clobbers the register holding `parent`, forcing a stack spill
  that inflates the frame by 8 bytes (`sub esp,0x18` vs orig `0x10`) and cascades
  into dozens of wrong `[esp+off]` immediates.
- **Wrapper `__inline`**: MSVC inlines the wrapper, then also inlines the *template
  body* of AddTail/RemoveTail at each site (NewNode expansion + field writes), which
  is even further from the original's single `call AddTail`. Score went 64.31% ->
  59.94% on BuildUniversityDialogShell (0x4749a0) when both wrappers were marked.
The original's exact shape (direct `call` to the out-of-line COMDAT, no wrapper, no
body inline) is not reproducible from source at this build's `/Ob1`: a direct
`.AddTail()` call inlines the implicitly-inline template method, and any wrapper adds
a call layer. Keep the plain (non-inline) wrapper — it's the higher-scoring of the
two — and treat the residual push/pop call-shape + frame-size delta as an accepted
structural cost of these 10-15KB builders. Do not chase it by toggling `__inline`.

### Recovering a family of MFC dialog-template subclasses (16 at once)
*(ex decomp-loop note 105)*


Recovered the whole modal-dialog-template family (TC2/TD2 + 13 more: DB/DC/DE/DF/FA/AD/104/
A7/AB/AE/B1/A1/D0/E0/DD/64). Each is a game CDialog subclass built by an
`InitializeDialogTemplate<ID>` ctor; model = `// VTABLE:` + ctor (`: TModalDialogBase(id,...)`
or `: CDialog(id,...)`) + members + DoDataExchange override + scalar-dtor/GetMessageMap
SYNTHETIC + empty message map. Four traps that each cost a wrong first attempt:

1. **Distinguish TModalDialogBase-derived from plain CDialog by the RIGHT slots.** Slots
   0x08/0x14/0x88 are shared by *every* CDialog subclass and prove nothing. The decisive slots
   are 0xc0/0xd8/0xdc: TModalDialogBase overrides them (DoModal 0x4055f6→0x49d450, +0x4076ee,
   +0x402ca7); a plain CDialog subclass has the library `CDialog::DoModal` (0x6051b9) at 0xc0
   and NULL at 0xd8/0xdc (its vtable ends at 0xd4). Plain-CDialog members start at 0x5c (they
   occupy what would be TModalDialogBase's modal scratch); TModalDialogBase members start at
   0x74. A second tell: the ctor of a TModalDialogBase subclass writes an *intermediate* vtable
   (0x63e5a0) before its own; a plain-CDialog ctor writes only its own.

2. **Plain-CDialog subclasses can't reach 100% until `CDialog::DoModal` is a named library
   function.** Their inherited slot 0xc0 references it, but if 0x6051b9 is an unnamed placeholder
   the recomp's COMDAT copies don't pair. Add it to `msvc500_library_overrides.csv`
   (`?DoModal@CDialog@@UAEHXZ`, nafxcw/dlgcore.obj) — fixes all of them at once. Then retire the
   freed `DoModal_6051b9` stub: its game callers become real `dialog.DoModal()`.

3. **MSVC emits a class vtable only in the TU that CONSTRUCTS it** (vtable is tied to the ctor,
   not to a key function as in the Itanium ABI). A dialog whose only constructor is *inlined into
   its driver* (T64 → ShowDialogTemplate64Modal) never emits its vtable from the class TU alone —
   `just vtable` reports a vacuous "Vtables found: 0". Recover the driver so it constructs the
   real class; that emits and pairs the vtable.

4. **Embedded-control vtable identities:** 0x6714cc = CSliderCtrl, 0x671d1c = CListBox (verify
   from the reference ctor, e.g. TC2 installs CSliderCtrl@+0x74 / CListBox@+0xb0). Getting this
   backwards mislabels the member type and mis-installs the control vtable in the ctor.

Parallelize the per-dialog Ghidra investigation across subagents (one recipe per dialog: base
test, overridden slots with resolved ILT targets, DDX body, members, size), then model + build +
`just vtable` serially. Message-map handlers and complex OnInitDialog/OnOK bodies are NOT vtable
slots — minimal override bodies still give a 100% vtable; refine bodies later.

### Recovering an MFC GDI OnPaint (CPaintDC/CPen/CBrush/CRgn + DIB blits)
*(ex decomp-loop note 107)*


`mfc.h` includes the real `<afxwin.h>`, so CPaintDC/CDC/CPen/CBrush/CRgn/CDibPal and
`CDC::FromHandle` are all available as genuine MFC classes — model the paint body with them, not
raw handles. Recipe that matched well:
- **`CPaintDC dc(this);`** at the top; scope CPen in its own `{}` block and CRgn+CBrush in
  theirs so the EH funclet nesting matches.
- **`dc.GetSafeHdc()`** reproduces the `lea; neg; sbb; and` null-guard idiom the disassembly
  shows at every GDI handle pass; a bare `dc.m_hDC` / `(dc?dc->m_hDC:0)` ternary emits the
  branch in the *opposite* order (then-block first) and misses. Prefer `GetSafeHdc()` — it also
  fixed CreateDibBitmapFromStoredInfo 86%→100%.
- **`memcpy`/`memset` of a dynamic byte count → `rep movsd`+`rep movsb`** matches the original's
  inlined copy; **do NOT** pre-mask the count with `& 0x3fffffff` (that mask is Ghidra's artifact
  of `(n*4)>>2`; the real code is just `n*4`). Inline the count expression per call — the
  original recomputes it, doesn't hoist a `tableBytes` local.
- **Memory-DC BitBlt path uses raw Win32** (`::CreateCompatibleDC`/`::SelectObject`/`::BitBlt`/
  `::DeleteDC`) because it selects an HBITMAP directly; CDC::BitBlt wants a CDC* src and won't match.
- **A single-use gating global** (e.g. 0x694c50) needs full plumbing to pair its operand: a
  `symbols.csv` `…|global||` row + a `// GLOBAL:` def in `global_data_tables.cpp` + `extern` in
  the `.h`. Name it behaviorally and hedge as provisional if only one reader is known.
- **Ceiling ~70%:** the residual is MSVC CSE (the original re-reads `picture->m_pInfoHeader` and
  recomputes `abs(biHeight)` per height arg; cleaner C++ gets CSE'd to fewer instructions) and a
  library FromHandle identity. Writing raw field accesses inline (no locals) recovers *some* of
  the double-abs but not the header-pointer CSE. Per the philosophy, stop here — don't contort
  the source to chase the last MSVC-scheduling percent on an architecturally-correct paint body.

- **A game class whose method bodies look like hand-inlined MFC collection internals is a
     thin virtual facade over an MFC TEMPLATE base — model the inheritance, not the internals.**
     TLongintList (vtable 0x650a08, junk-named TSoundChannelNode) is
     `class TLongintList : public CList<long, long>` with ten one-liner virtuals
     (`InsertLast { AddTail(value); }`, `At { return GetAt(FindIndex(i-1)); }`, ...): the
     template's header-inline members expand under /Ob1 to byte-identical code, so every method
     hit 100% on the first build. Tells: ctor store order matching the template ctor's chained
     null assignments (c,10,8,4,14,18 for CList), a "double store" that is really
     ConstructElement's memset + the assignment, a "vestigial walk" that is DestructElement over
     trivial elements, vtable slot 0 = inherited CObject::GetRuntimeClass, and a Serialize slot
     whose size equals a known CList instantiation (280B). Claim the template-emitted bodies
     (Serialize, ~CList, sdd) with `// TEMPLATE:` markers + mangled names (TView.cpp precedent),
     NOT FUNCTION markers. Always cross-check the field's constructor site: ownedRegionList's
     `new` wrote vtable 0x650a08, so its declared TSortedList* type (different vtable, different
     slot map) had silently mismodeled every accessor — the "AddTailEx" calls in the
     Remove-region family were really `Delete(value)` at +0x34.

  *(ex decomp-loop list-note 111)*

- **stretch<T> containment scans are two nested inlines: `T* FindEntry(T)` (for-loop,
     unsigned index/count compares, hit returned as `&Data()[index]`) and a bool
     `ContainsEntry` wrapper whose return materializes via SETNE.** 0x564570 went
     48% -> 100% by modeling both on TZoneSecondaryNeighborStretch (NOT on the template:
     MSVC500 eagerly instantiates template members, and stretch<Seapoint> has no
     operator==). The rotated for-loop shape (pre-test `jbe`, body compare at top,
     backward `jb`) only falls out of the indexed for-form, not a do-while.

  *(ex decomp-loop list-note 117)*

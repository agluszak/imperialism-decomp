---
name: cmcwindow-recovery-plan
description: CMcWindow is a real CWnd subclass; structure + the recovery steps to unblock new CMcWindow(this)
metadata:
  type: project
---

CMcWindow (the host window behind TView::nativeWindow50) is a **real MFC `CWnd` subclass**
— confirmed by the autogen `struct CMcWindow` (root_types.h ~1034) carrying the exact CWnd
member names: m_hWnd@0x1c, m_hWndOwner, m_nFlags, m_pfnSuper, m_nModalResult, m_pDropTarget,
m_pCtrlCont, m_pCtrlSite. Chain: CMcWindow -> CWnd -> CCmdTarget -> CObject.

- **No autogen bucket** — its functions live in `global_part005.cpp` (and elsewhere),
  named as free functions, not grouped under CMcWindow.
- **Vtable = 0x64b7c8** (what the ctor writes: `*this = &PTR_LAB_0064b7c8`). NOT in
  symbols.csv; the `CMcWindow::vftable` rows there (0x649e74/0x64b35c/0x655944/0x656d04/
  0x6572dc/0x65751c) are Ghidra mislabels, ignore them. classRuntimeClass = 0x64b5d0
  (= g_pClassDescCMcWindow, already added).
- **Base ctor** `ConstructObjectVtable00670b4cBase` @0x6077c6 = CWnd::CWnd-equivalent
  (CCmdTarget() + sets vtable 0x670b4c + zeroes the CWnd fields). So CWnd's vtable in this
  binary is 0x670b4c.
- **Ctor/factory** `CreateMcWindowFromDescriptorAndShow` @0x493470 (`__thiscall(this, int
  descriptor)`, ~600B): sets vptr 0x64b7c8, stores descriptor@+0x3c, big switch on the
  descriptor's window-type byte (+0x60..) building dwStyle/dwExStyle, asserts via McWindow.cpp
  path, computes rect from descriptor +0x24/+0x28/+0x34/+0x38, AdjustWindowRectEx, AfxGetThread,
  CWnd::CreateEx (CreateEx_608115), SetWindowPos, BringWindowToTop. Helper deps:
  InvokeAfxThreadVslot7CAndGetValueAtOffset98, GetWindowPlacementFromThisHwnd, DAT_006a1c6c/70,
  s_D__Ambit_McWindow_cpp_006950d8.

**Vtable 0x64b7c8 dumped** (`just ghidra-vtable-dump CMcWindow 0x0064b7c8`): it's the full
~42-slot MFC **CWnd message-map vtable** — slots resolve to the real CWnd/CCmdTarget/CDocument
methods (WindowProc @0x608b66, OnWndMsg @0x608ba8, PreTranslateMessage, CalcWindowRect @0x609a3f,
CreateChildWindowFromRect @0x60820b, CCmdTarget scalar-dtor @0x608409, …), with a handful of
CMcWindow overrides reached via ILT thunks (slots 0x00 @0x403125, 0x01 @0x407d29, 0x05
DispatchCommandToAfxMessageMapChain @0x606a07, plus several `TMacViewMgr_Slot*_Target`).

**Do NOT model CWnd — it's already in `<afxwin.h>`. Annotate it `// LIBRARY`.** (Corrected:
an earlier note here wrongly said to model the CWnd/CCmdTarget foundation.) The CWnd vtable
methods are real nafxcw functions; add bodyless `// LIBRARY: 0xADDR` + `// CWnd::Method` pairs
(mirror CObject.cpp / MfcRuntime.cpp) and rename the symbols.csv row to the MFC name. Started in
MfcRuntime.cpp: `CWnd::CreateEx` @0x608115, `CWnd::CenterWindow` @0x60a27d (the latter lifted
the caller 0x48e150 71%→74%). A LIBRARY fn only pairs once our build links it (some manual code
calls it).

**Recovery = `class CMcWindow : public CWnd`** (CWnd from the header), `// VTABLE: 0x64b7c8`,
override the ~6 game-thunk slots (0x00 @0x403125, 0x01 @0x407d29, 0x05 @0x606a07, the
`TMacViewMgr_Slot*` ones); inheritance owns the vptr (no manual write). LIBRARY-annotate the
CWnd surface the ctor/vtable use (CreateEx etc.). Then port the ctor @0x493470 as
`CMcWindow(descriptor) : CWnd()` and write `new CMcWindow(this)` in DispatchSlot9C.
See [[twindow-body-port-progress]], [[real-mfc-linking-viable]], decomp-loop heuristics §15.

**Unported classes (73 buckets, ~84% of 447 already have manual files):** biggest are
CCmdTarget(39, MFC→LIBRARY), TTradeMgr(32), TArmsForeignMinister(26) + the foreign-minister
family (Bill/Ted/Diplomat/Trader/Textile…), the mission family (Invade/AttackProvince/
ScatteredShips/Blockade/Beachhead/Escort/ControlSeaZone), view classes (TCouncilView,
TBattleReportView, TacticalBattleView), and MFC C-classes (CFrameWnd, CWnd, CMainFrame,
CDocTemplate, CObArray, CImageList — all cheap // LIBRARY). The minister/mission families
mirror already-ported siblings (cheap, batchable).

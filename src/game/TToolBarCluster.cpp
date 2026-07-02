#include "game/TToolBarCluster.h"
// SYNTHETIC: IMPERIALISM 0x00584d80
// TToolBarCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x00584e00
// TToolBarCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TToolBarCluster, TCluster)

TToolBarCluster::TToolBarCluster() {}

// SYNTHETIC: IMPERIALISM 0x00584e50
// TToolBarCluster::`scalar deleting destructor'
TToolBarCluster::~TToolBarCluster() {}

// FUNCTION: IMPERIALISM 0x00584ea0
void TToolBarCluster::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}

// FUNCTION: IMPERIALISM 0x005851c0
void TToolBarCluster::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                          int hitArg) {
  (void)point;
  (void)hitArg;
}

// FUNCTION: IMPERIALISM 0x005853f0
undefined TToolBarCluster::RefreshTurnOrderStatusPanelTextsAndControls() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00585ba0
void TToolBarCluster::UpdateControlTagTreaTextFromNationAndMapContext(int nationId) {
  // TODO: port body @ 0x585ba0 (refreshes a tag's text from the active nation + map context).
  (void)nationId;
}

// FUNCTION: IMPERIALISM 0x00585ee0
undefined TToolBarCluster::SehCleanup_ReleaseTwoTempSharedStringRefs() {
  return 0;
}

// Map-interaction/order-entry cluster (bd 1uj.50). These three replace the two ILT
// thunk rows (0x4032a1 SetMapInteractionMode, 0x408995 RefreshMapOrderEntryPanel) that
// survived prune_ilt_thunks.py because TWorldView.cpp referenced them via a
// Hard-Rule-9-violating reinterpret_cast<...__fastcall...> free-function bridge over a
// fake `TToolBarClusterFields` struct. That callsite now calls these real methods
// instead, so the thunk rows become unreferenced and prune cleanly.
//
// Bodies are intentionally left as TODO stubs (not guessed field access): the real
// disassembly touches `this+0x96` (short) and a 3-element pointer array at
// `this+0xb0..0xbc`, both past TToolBarCluster's verified 0x88-byte object size
// (CreateObject @ 0x584d80 allocates exactly size 0x88; RTTI oracle agrees; no class
// derives from TToolBarCluster per config/rtti_class_oracle.csv). The true receiver is
// most likely a further-derived, RTTI-invisible subclass (never registered via
// DECLARE_DYNCREATE) that this curated symbols.csv attribution doesn't yet capture.
// Follow-up: recover that subclass's real layout/size before porting these bodies.

// FUNCTION: IMPERIALISM 0x00596cb0
void TToolBarCluster::SetMapInteractionMode(short nMode) {
  // TODO: port body @ 0x596cb0 (691 bytes; SEH-framed CString hint-text builder that
  // also toggles 3 mode-select icon buttons). See class-layout caveat above.
  (void)nMode;
}

// FUNCTION: IMPERIALISM 0x00597810
void TToolBarCluster::RefreshMapOrderEntryPanel(void* pMapOrderEntry) {
  // TODO: port body @ 0x597810 (246 bytes; forces order-entry interaction mode, then
  // either clears or repopulates the 4 order-entry slider controls ("0slc".."3slc")
  // from pMapOrderEntry's per-category quota fields). See class-layout caveat above.
  (void)pMapOrderEntry;
}

// FUNCTION: IMPERIALISM 0x00597950
void TToolBarCluster::SetActiveMapOrderEntry(void* pMapOrderEntry) {
  // TODO: port body @ 0x597950 (113 bytes; forces order mode, invalidates the old and
  // new order-entry regions, then calls RefreshMapOrderEntryPanel). See class-layout
  // caveat above.
  (void)pMapOrderEntry;
}

#include "game/TToolBarCluster.h"
// SYNTHETIC: IMPERIALISM 0x00584d80
// TToolBarCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x00584e00
// TToolBarCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TToolBarCluster, TCluster)

// FUNCTION: IMPERIALISM 0x00584e20
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

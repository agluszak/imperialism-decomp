#include "game/TToolBarCluster.h"

#include "game/global_data_tables.h"

// Builds the 16 per-slot hover/hit-test rects consumed by
// TToolBarCluster::HandleCityBuildingHoverSelection from a table of 17 (x,y) anchor points.
// Most slots get a fixed 10x10 box at their anchor; slots 10 and 11 instead span between two
// consecutive anchors (a wider combined-slot region). Placement-constructs each CRect directly
// into the pre-existing global array, matching the original's direct constructor calls.
// FUNCTION: IMPERIALISM 0x004b95c0
void InitializeCityBuildingHoverSelectionRects_004b95c0() {
  short* coords = g_anCityBuildingSlotCoords;
  CRect* rects = g_aCityBuildingHoverSelectionRects;
  new (&rects[0]) CRect(coords[0], coords[1], coords[0] + 10, coords[1] + 10);
  new (&rects[1]) CRect(coords[2], coords[3], coords[2] + 10, coords[3] + 10);
  new (&rects[2]) CRect(coords[4], coords[5], coords[4] + 10, coords[5] + 10);
  new (&rects[3]) CRect(coords[6], coords[7], coords[6] + 10, coords[7] + 10);
  new (&rects[4]) CRect(coords[8], coords[9], coords[8] + 10, coords[9] + 10);
  new (&rects[5]) CRect(coords[10], coords[11], coords[10] + 10, coords[11] + 10);
  new (&rects[6]) CRect(coords[12], coords[13], coords[12] + 10, coords[13] + 10);
  new (&rects[7]) CRect(coords[14], coords[15], coords[14] + 10, coords[15] + 10);
  new (&rects[8]) CRect(coords[16], coords[17], coords[16] + 10, coords[17] + 10);
  new (&rects[9]) CRect(coords[18], coords[19], coords[18] + 10, coords[19] + 10);
  new (&rects[10]) CRect(coords[20], coords[21], coords[22] + 10, coords[23] + 10);
  new (&rects[11]) CRect(coords[24], coords[25], coords[26] + 10, coords[27] + 10);
  new (&rects[12]) CRect(coords[26], coords[27], coords[26] + 10, coords[27] + 10);
  new (&rects[13]) CRect(coords[28], coords[29], coords[28] + 10, coords[29] + 10);
  new (&rects[14]) CRect(coords[30], coords[31], coords[30] + 10, coords[31] + 10);
  new (&rects[15]) CRect(coords[32], coords[33], coords[32] + 10, coords[33] + 10);
}

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

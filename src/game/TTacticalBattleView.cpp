#include "game/TTacticalBattleView.h"
// SYNTHETIC: IMPERIALISM 0x005a82b0
// TTacticalBattleView::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a8330
// TTacticalBattleView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacticalBattleView, TView)

TTacticalBattleView::TTacticalBattleView() {}

// FUNCTION: IMPERIALISM 0x005a83c0
undefined TTacticalBattleView::OrphanRetStub_005a83c0() {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x005a83e0
// TTacticalBattleView::`scalar deleting destructor'
TTacticalBattleView::~TTacticalBattleView() {}

// FUNCTION: IMPERIALISM 0x005a8430
void TTacticalBattleView::Free() {}

// FUNCTION: IMPERIALISM 0x005a84d0
void TTacticalBattleView::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x005a8550
void TTacticalBattleView::ForwardParam(int param) {}

// FUNCTION: IMPERIALISM 0x005a8660
void TTacticalBattleView::BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                                               int arg4) {
  (void)point;
  (void)arg2;
  (void)arg3;
  (void)arg4;
}

// FUNCTION: IMPERIALISM 0x005a8860
void TTacticalBattleView::InvalidateTacticalHexTileRect(int tileIndex) {
  // TODO: port body @ 0x5a8860.
  (void)tileIndex;
}

// FUNCTION: IMPERIALISM 0x005a8900
undefined TTacticalBattleView::WrapperFor_InvalidateCityDialogRectRegion_At005a8900(int param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a89a0
undefined TTacticalBattleView::InvalidateTacticalUnitTileRect(TTacticalUnit* unit) {
  (void)unit;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a89f0
undefined TTacticalBattleView::OrphanLeaf_NoCall_Ins59_005a89f0(int param_1, int* param_2) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a8ac0
void TTacticalBattleView::CenterViewportAroundGridIndexAndSnap(int tileIndex) {
  // TODO: port body @ 0x5a8ac0.
  (void)tileIndex;
}

// FUNCTION: IMPERIALISM 0x005a8be0
undefined TTacticalBattleView::AdjustTacticalUnitVerticalOffsetAndRefreshMarker() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a8ca0
void TTacticalBattleView::HandleCursorHoverFallback(CPoint* point, int hitArg) {}

// FUNCTION: IMPERIALISM 0x005a8d40
void TTacticalBattleView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                              int hitArg) {
  (void)point;
  (void)hitArg;
}

// FUNCTION: IMPERIALISM 0x005a9090
undefined TTacticalBattleView::PlayTacticalTileEffect(int tileIndex, int effectId, int frameCount) {
  (void)tileIndex;
  (void)effectId;
  (void)frameCount;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a9170
undefined TTacticalBattleView::RunOneTimeAnimationModalWaitAndInvalidateCityDialog() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a9240
undefined TTacticalBattleView::AnimateTacticalUnitMoveBetweenTiles(TTacticalUnit* unit,
                                                                   int fromTileIndex,
                                                                   int toTileIndex) {
  (void)unit;
  (void)fromTileIndex;
  (void)toTileIndex;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a9550
void TTacticalBattleView::DrawUiTilesAndOverlay(astruct_13* ui_ctx) {
  (void)ui_ctx;
}

// Promoted tactical-UI helpers (called from the TTacticalBattle command handlers).

// FUNCTION: IMPERIALISM 0x005a9b40
void TTacticalBattleView::UpdateTacticalActionControlBitmapForCurrentUnit(char side) {
  // TODO: port body @ 0x5a9b40.
  (void)side;
}

// FUNCTION: IMPERIALISM 0x005a9bb0
void TTacticalBattleView::SpawnTacticalUiMarkerAtUnitTile() {
  // TODO: port body @ 0x5a9bb0.
}

// FUNCTION: IMPERIALISM 0x005a9cc0
void TTacticalBattleView::TriggerTacticalUiUpdate2711() {
  // TODO: port body @ 0x5a9cc0.
}

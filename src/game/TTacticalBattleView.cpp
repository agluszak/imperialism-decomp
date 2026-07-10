#include "game/TTacticalBattleView.h"

#include "game/TAnimation.h"
#include "game/TAnimator.h"
#include "game/TCivAnimation2.h"
#include "game/TPicture.h"
#include "game/TSimMgr.h"
#include "game/TTacticalBattle.h"
#include "game/TTacticalPlayer.h"
#include "game/TTacticalUnit.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
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

// FUNCTION: IMPERIALISM 0x005a87d0
void TTacticalBattleView::ComputeTacticalHexTileScreenRect(RECT* rectOut, int tileIndex) {
  // TODO: port body @ 0x5a87d0.
  (void)rectOut;
  (void)tileIndex;
}

// FUNCTION: IMPERIALISM 0x005a8860
void TTacticalBattleView::InvalidateTacticalHexTileRect(int tileIndex) {
  RECT tileRect;
  int row = tileIndex / tileColumnsPerRow80;
  int tileWidth = tileWidthPx88;
  int x = (tileIndex % tileColumnsPerRow80) * tileWidth - viewOriginX78;
  tileRect.left = x;
  if (row & 1) {
    // Odd hex rows are staggered right by half a tile.
    x += tileWidth / 2;
    tileRect.left = x;
  }
  int rowHeight = tileRowHeightPx8C;
  tileRect.top = row * rowHeight;
  tileRect.right = x + tileWidth;
  tileRect.bottom = tileRect.top + rowHeight;
  InvalidateCityDialogRectRegion(&tileRect, 1);
}

// FUNCTION: IMPERIALISM 0x005a8900
undefined TTacticalBattleView::WrapperFor_InvalidateCityDialogRectRegion_At005a8900(int param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a89a0
undefined TTacticalBattleView::InvalidateTacticalUnitTileRect(TTacticalUnit* unit) {
  RECT unitRect;
  if (unit->tileIndex8 != -1) {
    ComputeTacticalUnitTileScreenRect(unit, &unitRect);
    InvalidateCityDialogRectRegion(&unitRect, 1);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a89f0
undefined TTacticalBattleView::ComputeTacticalUnitTileScreenRect(TTacticalUnit* unit,
                                                                 RECT* rectOut) {
  // TODO: port body @ 0x5a89f0 (tile rect grown 0x18 px upward, bottom-4; zero RECT
  // when tileIndex8 == -1).
  (void)unit;
  (void)rectOut;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a8ac0
void TTacticalBattleView::CenterViewportAroundGridIndexAndSnap(int tileIndex) {
  int firstVisibleColumn = viewOriginX78 / tileWidthPx88;
  int visibleColumnCount = frameWidth34 / tileWidthPx88;
  int lastVisibleColumn = firstVisibleColumn + visibleColumnCount;
  // Screen column in whole tiles; odd rows contribute a half-column stagger
  // (tile grid is 0x1d columns wide, matching TTacticalBattle::tacticalTileStride40).
  int screenColumn = ((tileIndex % 0x1d) * 2 + ((tileIndex / 0x1d) & 1)) / 2;
  if (screenColumn >= firstVisibleColumn + 2 && screenColumn <= lastVisibleColumn - 2) {
    return;
  }
  short tileWidth = (short)tileWidthPx88; // original loads the low word once and reuses it
  viewOriginX78 = (short)(screenColumn * tileWidth - frameWidth34 / 2);
  if (viewOriginX78 < 0) {
    viewOriginX78 = 0;
  } else if (viewOriginX78 > scrollableContentWidth7A - frameWidth34) {
    viewOriginX78 = (short)(scrollableContentWidth7A - frameWidth34);
  }
  // Snap the origin back to a whole-tile boundary.
  if (viewOriginX78 % tileWidthPx88 != 0) {
    viewOriginX78 = (short)((viewOriginX78 / tileWidthPx88) * tileWidth);
  }
  RefreshControl();
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
  RECT effectRect;
  TTacticalUnit* occupant = tacticalBattle60->tileGrid4[tileIndex].occupant4;
  if (occupant != 0) {
    ComputeTacticalUnitTileScreenRect(occupant, &effectRect);
  } else {
    int row = tileIndex / tileColumnsPerRow80;
    int tileWidth = tileWidthPx88;
    int x = (tileIndex % tileColumnsPerRow80) * tileWidth - viewOriginX78;
    effectRect.left = x;
    if (row & 1) {
      x += tileWidth / 2;
      effectRect.left = x;
    }
    int rowHeight = tileRowHeightPx8C;
    effectRect.top = row * rowHeight;
    effectRect.right = x + tileWidth;
    effectRect.bottom = effectRect.top + rowHeight;
  }
  return RunOneTimeAnimationModalWaitAndInvalidateCityDialog(&effectRect, effectId, frameCount,
                                                             tileIndex, 2);
}

// FUNCTION: IMPERIALISM 0x005a9170
undefined TTacticalBattleView::RunOneTimeAnimationModalWaitAndInvalidateCityDialog(
    RECT* rect, int effectId, int frameCount, int tileIndex, int mode) {
  // TODO: port body @ 0x5a9170.
  (void)rect;
  (void)effectId;
  (void)frameCount;
  (void)tileIndex;
  (void)mode;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a9240
undefined TTacticalBattleView::AnimateTacticalUnitMoveBetweenTiles(TTacticalUnit* unit,
                                                                   int fromTileIndex,
                                                                   int toTileIndex) {
  // TODO(verify): +0x52 = preferenceValues[5] -- animation-enable preference gate.
  if (g_pSimMgr->preferenceValues[5] == 0) {
    return 0;
  }

  int fromRow = fromTileIndex / tileColumnsPerRow80;
  int fromX = (fromTileIndex % tileColumnsPerRow80) * tileWidthPx88 - viewOriginX78;
  if (fromRow & 1) {
    fromX += tileWidthPx88 / 2;
  }
  int fromY = fromRow * tileRowHeightPx8C;
  int fromBottom = fromY + tileRowHeightPx8C;

  int toRow = toTileIndex / tileColumnsPerRow80;
  int toX = (toTileIndex % tileColumnsPerRow80) * tileWidthPx88 - viewOriginX78;
  if (toRow & 1) {
    toX += tileWidthPx88 / 2;
  }
  int toY = toRow * tileRowHeightPx8C;
  int toBottom = toY + tileRowHeightPx8C;

  RECT animRect;
  animRect.left = (fromX < toX) ? fromX : toX;
  int maxBottom = (fromBottom > toBottom) ? fromBottom : toBottom;
  animRect.top = maxBottom - 3 * tileRowHeightPx8C;
  animRect.right = animRect.left + 2 * tileWidthPx88;
  animRect.bottom = maxBottom;

  moveAnimUnitOffsetYA8 = fromBottom - animRect.top - 4;
  moveAnimScreenRectC0.left = animRect.left;
  moveAnimScreenRectC0.top = animRect.top;
  moveAnimScreenRectC0.right = animRect.right;
  moveAnimScreenRectC0.bottom = animRect.bottom;
  moveAnimStepX9C = (toX - fromX) / 3;
  moveAnimStepYA0 = (toY - fromY) / 3;
  moveAnimUnitOffsetXA4 = fromX - animRect.left;

  int spriteLeft = unit->unitTypeC * unitSpriteCellWidth90;
  // Half-column positions decide the facing: moving toward a higher half-column uses
  // sprite-sheet row 0, otherwise the second row (offset by one cell height).
  int fromHalfColumn = (fromTileIndex % 0x1d) * 2 + ((fromTileIndex / 0x1d) & 1);
  int toHalfColumn = (toTileIndex % 0x1d) * 2 + ((toTileIndex / 0x1d) & 1);
  int spriteTop = (fromHalfColumn < toHalfColumn) ? 0 : unitSpriteCellHeight94;
  moveAnimSpriteSrcRectAC.left = spriteLeft;
  moveAnimSpriteSrcRectAC.top = spriteTop;
  moveAnimSpriteSrcRectAC.right = spriteLeft + unitSpriteCellWidth90;
  moveAnimSpriteSrcRectAC.bottom = spriteTop + unitSpriteCellHeight94;

  InvalidateCityDialogRectRegion(&animRect, 1);

  RECT fromTileRect;
  int row2 = fromTileIndex / tileColumnsPerRow80;
  int tileWidth2 = tileWidthPx88;
  int x2 = (fromTileIndex % tileColumnsPerRow80) * tileWidth2 - viewOriginX78;
  fromTileRect.left = x2;
  if (row2 & 1) {
    x2 += tileWidth2 / 2;
    fromTileRect.left = x2;
  }
  int rowHeight2 = tileRowHeightPx8C;
  fromTileRect.top = row2 * rowHeight2;
  fromTileRect.right = x2 + tileWidth2;
  fromTileRect.bottom = fromTileRect.top + rowHeight2;
  InvalidateCityDialogRectRegion(&fromTileRect, 1);

  InvokeSlot13C();
  moveAnimUnitOffsetXA4 = -1;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a9550
void TTacticalBattleView::DrawUiTilesAndOverlay(astruct_13* ui_ctx) {
  (void)ui_ctx;
}

// Promoted tactical-UI helpers (called from the TTacticalBattle command handlers).

// FUNCTION: IMPERIALISM 0x005a9b40
void TTacticalBattleView::UpdateTacticalActionControlBitmapForCurrentUnit(char side) {
  (void)side; // parameter is dead in the original: the side is read from the battle state
  TPicture* coatControl =
      static_cast<TPicture*>(ownerContext->ResolveControlByTag(kControlTagCoat));
  coatControl->AssertValid();
  TTacticalBattle* battle = tacticalBattle60;
  // tacticalPlayer14/18 are indexed as a two-slot array by the current side.
  TTacticalPlayer* currentPlayer = (&battle->tacticalPlayer14)[battle->currentSideC];
  coatControl->SetPictureResourceIdAndRefresh(
      static_cast<short>(currentPlayer->nationIndex1C + 0xea6), 1);
}

// FUNCTION: IMPERIALISM 0x005a9bb0
void TTacticalBattleView::SpawnTacticalUiMarkerAtUnitTile() {
  g_pUiAnimator->RemoveUiTransientRegistryObjectByTag(0x2711);
  TTacticalUnit* selectedUnit = tacticalBattle60->selectedUnit1c;
  if (selectedUnit == 0) {
    return;
  }
  int tileIndex = selectedUnit->tileIndex8;
  if (tileIndex < 0) {
    return;
  }
  RECT tileRect;
  int row = tileIndex / tileColumnsPerRow80;
  int tileWidth = tileWidthPx88;
  int x = (tileIndex % tileColumnsPerRow80) * tileWidth - viewOriginX78;
  tileRect.left = x;
  if (row & 1) {
    x += tileWidth / 2;
    tileRect.left = x;
  }
  int rowHeight = tileRowHeightPx8C;
  tileRect.top = row * rowHeight;
  tileRect.right = x + tileWidth;
  tileRect.bottom = tileRect.top + rowHeight;
  TAnimation* marker = new TAnimation;
  // Original calls the init body unconditionally on the new-result (no null guard).
  marker->ConstructTAnimationBaseState(this, &tileRect, 2, 0, 0xa, 0x2711);
  TCivAnimation2* animator = static_cast<TCivAnimation2*>(static_cast<void*>(g_pUiAnimator));
  animator->AddObjectToUiTransientRegistry(marker);
}

// FUNCTION: IMPERIALISM 0x005a9cc0
void TTacticalBattleView::TriggerTacticalUiUpdate2711() {
  g_pUiAnimator->RemoveUiTransientRegistryObjectByTag(0x2711);
}

#include "game/TOceanDialog.h"

#include "game/TDisplayMgr.h"
#include "game/TMapMgr.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"

// Standalone binary helper also reached via TWorldView.cpp/TMapDialog.cpp's identical
// bridge (0x51ace0); real signature void(short*, short*).
void NormalizeWrappedMapCoord108x60(short* xCoord, short* yCoord);

// SYNTHETIC: IMPERIALISM 0x00565db0
// TOceanDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x00565e70
// TOceanDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOceanDialog, TWorldView)

// FUNCTION: IMPERIALISM 0x00565e90
TOceanDialog::TOceanDialog() : scrollRowOffset7c(0), scrollColOffset7e(0) {
  // Inherited TWorldView viewport fields seeded from the ocean-dialog seed globals
  // (0x6a3ff0/0x6a3ff4); their only writer is the reset helper at 0x56a3b0 which zeroes
  // both. projectionScale76/previewSquareRadius78 are fixed layout constants for the
  // ocean dialog.
  viewportOffsetX = g_nOceanDialogSeedViewportOffsetX;
  viewportOffsetY = g_nOceanDialogSeedViewportOffsetY;
  projectionScale76 = 4;
  previewSquareRadius78 = 0x10;
}

// SYNTHETIC: IMPERIALISM 0x00565ee0
// TOceanDialog::`scalar deleting destructor'
TOceanDialog::~TOceanDialog() {}

// FUNCTION: IMPERIALISM 0x00565f50
void TOceanDialog::DoPostCreate(int arg) {
  TWorldView::DoPostCreate(arg);
  projectionScale76 = 4;
  previewSquareRadius78 = 0x10;
}

// Mac oracle: TOceanDialog::InvalidateZone(TZone*).
// FUNCTION: IMPERIALISM 0x00565f80
void TOceanDialog::InvalidateZone(TZone* zone) {
  if (zone != 0) {
    CRect bounds = BoundingRect(zone);
    InvalidateCityDialogRectRegion(&bounds, 1);
  }
}

// FUNCTION: IMPERIALISM 0x00565fc0
void TOceanDialog::InvalidateTile(short tileIndex) {
  if (tileIndex < 0) {
    return;
  }

  int row = tileIndex / 0x6c;
  int x = ((tileIndex - scrollColOffset7e + 0x6c) % 0x6c) << 4;
  if ((row & 1) == 0) {
    x -= 8;
  }
  int y = (row - scrollRowOffset7c) << 4;
  CRect tileRect(x, y, x + 0x10, y + 0x10);
  InvalidateCityDialogRectRegion(&tileRect, 1);
}

// Computes the viewport-space bounding rectangle of every strategic tile whose owner tag
// matches the order entry's field at +0x12, converted through the dialog's scroll offsets.
// Emits a zero rect when nothing matches.
// FUNCTION: IMPERIALISM 0x00566060
CRect TOceanDialog::BoundingRect(TZone* zone) {
  tagRECT bounds;
  bounds.right = -2000;
  bounds.bottom = -2000;
  int minLeft = 1000;
  int minRowMirror = 1000;
  bounds.left = 1000;
  bounds.top = 1000;
  int i = 0;
  do {
    if (static_cast<short>(
            g_pGlobalMapState->terrainStateTable[static_cast<short>(i)].ownerNationTag04) ==
        zone->seedNationId12) {
      int row = i / 0x6c;
      int col = (row & 1) + 1 + (i % 0x6c) * 2;
      if (col < minLeft) {
        minLeft = col;
        bounds.left = col;
      }
      if (bounds.right < col) {
        bounds.right = col;
      }
      if (row < bounds.top) {
        bounds.top = row;
      }
      minRowMirror = bounds.top;
      if (bounds.bottom < row) {
        bounds.bottom = row;
      }
    }
    ++i;
  } while (i < 0x1950);
  CRect result;
  if (minRowMirror == 1000) {
    result.SetRectEmpty();
  } else {
    OffsetRect(&bounds, scrollColOffset7e * -2, -static_cast<int>(scrollRowOffset7c));
    result.left = bounds.left * 8;
    result.top = bounds.top << 4;
    result.right = bounds.right * 8;
    result.bottom = bounds.bottom << 4;
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x005661d0
void TOceanDialog::ComputeWrappedMapCellAndRegionBandFromScreenCoord(int overlayRecord,
                                                                     short* outRow,
                                                                     unsigned short* outCol,
                                                                     short* outBand) {
  (void)overlayRecord;
  (void)outRow;
  (void)outCol;
  (void)outBand;
}

// FUNCTION: IMPERIALISM 0x005665e0
void TOceanDialog::RenderStrategicTileSelectionAndNeighborHighlights() {}

// FUNCTION: IMPERIALISM 0x00566750
void TOceanDialog::OrphanRetStub_005966c0(short arg1) {
  (void)arg1;
}

// FUNCTION: IMPERIALISM 0x005667f0
void TOceanDialog::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
}

// FUNCTION: IMPERIALISM 0x00567fa0
void TOceanDialog::RenderMapOrderEntryTilePreview(TCivUnit* orderEntry, int projectedX,
                                                  int projectedY, int flag, short tileIndex) {
  (void)orderEntry;
  (void)projectedX;
  (void)projectedY;
  (void)flag;
  (void)tileIndex;
}

// FUNCTION: IMPERIALISM 0x00568120
void TOceanDialog::RenderTacticalStackCountIndicatorAndUnitBadge(short tileIndex, void* dstRect,
                                                                 int flag) {
  (void)tileIndex;
  (void)dstRect;
  (void)flag;
}

// FUNCTION: IMPERIALISM 0x005682d0
void TOceanDialog::RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, void* dstRect,
                                                                 unsigned char altOverlay) {
  (void)tileIndex;
  (void)dstRect;
  (void)altOverlay;
}

// FUNCTION: IMPERIALISM 0x00568640
void TOceanDialog::ForwardProjectTileIndexToWrappedScreenOffsetByScale(int arg1, int arg2, int arg3,
                                                                       int arg4, int arg5) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  (void)arg5;
}

// FUNCTION: IMPERIALISM 0x005687b0
undefined TOceanDialog::OrphanLeaf_NoCall_Ins02_005966e0(short arg1) {
  (void)arg1;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005688d0
void TOceanDialog::SetMapViewCellCoordinates(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
}

// FUNCTION: IMPERIALISM 0x005689f0
void TOceanDialog::CenterOn(int tileIndex) {
  short promotedTileIndex = static_cast<short>(tileIndex);
  int row = promotedTileIndex / 0x6c;
  int col = promotedTileIndex % 0x6c;
  SetMapViewCellCoordinates(col - 0x10, row - 0xe);
}

// FUNCTION: IMPERIALISM 0x00568a40
void TOceanDialog::ApplyDirectionalNudgeAndRefreshDisplay(unsigned char directionFlags) {
  // Nudged values are passed to the slot-0x1e4 virtual (SetMapViewCellCoordinates), which is
  // a genuine 3-byte RET-8 no-op in every reachable override -- VERIFIED, so the nudge is
  // effectively discarded and no persistence happens. Residual <100% here is the original's
  // 16-bit partial-register load idiom (`mov ax, [+0x7e]`, no sign-extend), which clean C++
  // can't reproduce without a type-pun; kept as the natural `int` load.
  int col = scrollColOffset7e;
  int row = scrollRowOffset7c;
  if ((directionFlags & 1) != 0) {
    row -= 4;
  } else if ((directionFlags & 2) != 0) {
    row += 4;
  }
  if ((directionFlags & 4) != 0) {
    col += 4;
  } else if ((directionFlags & 8) != 0) {
    col -= 4;
  }
  SetMapViewCellCoordinates(col, row);
  g_pDisplayMgr->activeDialog->InvokeSlot13C();
}

// FUNCTION: IMPERIALISM 0x00568ab0
int TOceanDialog::ComputeWrappedTileIndexFromObjectOffset7C7E() {
  short row = static_cast<short>(scrollRowOffset7c + 0xe);
  short col = static_cast<short>(scrollColOffset7e + 0x10);
  NormalizeWrappedMapCoord108x60(&col, &row);
  return col + row * 0x6c;
}

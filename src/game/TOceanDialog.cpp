#include "game/TOceanDialog.h"

#include "game/TDisplayMgr.h"
#include "game/TMapMgr.h"
#include "game/global_data_tables.h"

// Standalone binary helper also reached via TWorldView.cpp/TMapDialog.cpp's identical
// bridge (0x51ace0); real signature void(short*, short*).
void NormalizeWrappedMapCoord108x60(short* xCoord, short* yCoord);

// SYNTHETIC: IMPERIALISM 0x00565db0
// TOceanDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x00565e70
// TOceanDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOceanDialog, TWorldView)

// TODO: ground truth also sets viewportOffsetX/viewportOffsetY from two file-scope
// globals (0x6a3ff0/0x6a3ff4, both read-only here -- the writer is at 0x56a3b2/0x56a3b7,
// not yet traced/named) and overwrites field76=4/field78=0x10; deferred pending those
// globals' real role.
// FUNCTION: IMPERIALISM 0x00565e90
TOceanDialog::TOceanDialog() : scrollRowOffset7c(0), scrollColOffset7e(0) {}

// SYNTHETIC: IMPERIALISM 0x00565ee0
// TOceanDialog::`scalar deleting destructor'
TOceanDialog::~TOceanDialog() {}

// FUNCTION: IMPERIALISM 0x00565f50
void TOceanDialog::NoOpUiLifecycleHook(int arg) {
  (void)arg;
}

// Computes the viewport-space bounding rectangle of every strategic tile whose owner tag
// matches the order entry's field at +0x12, converted through the dialog's scroll offsets.
// Emits a zero rect when nothing matches.
// FUNCTION: IMPERIALISM 0x00566060
void TOceanDialog::ComputeTileClassBoundsInViewport(int* outRect, int entry) {
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
        *reinterpret_cast<short*>(entry + 0x12)) {
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
  if (minRowMirror == 100) {
    outRect[0] = 0;
    outRect[1] = 0;
    outRect[2] = 0;
    outRect[3] = 0;
  } else {
    OffsetRect(&bounds, scrollColOffset7e * -2, -static_cast<int>(scrollRowOffset7c));
    outRect[0] = bounds.left * 8;
    outRect[1] = bounds.top << 4;
    outRect[2] = bounds.right * 8;
    outRect[3] = bounds.bottom << 4;
  }
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
void TOceanDialog::RenderMapOrderEntryTilePreview(int arg1, int arg2, int arg3) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
}

// FUNCTION: IMPERIALISM 0x00568120
void TOceanDialog::RenderTacticalStackCountIndicatorAndUnitBadge(short tileIndex, int arg2,
                                                                 int arg3) {
  (void)tileIndex;
  (void)arg2;
  (void)arg3;
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
void TOceanDialog::OrphanRetStub_00596680(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
}

// FUNCTION: IMPERIALISM 0x005689f0
void TOceanDialog::UpdateMapDialogTileRowColumnMarkerAndInvalidate(int arg1) {
  (void)arg1;
}

// FUNCTION: IMPERIALISM 0x00568a40
void TOceanDialog::ApplyDirectionalNudgeAndRefreshDisplay(unsigned char directionFlags) {
  // Nudged values are only ever passed to OrphanRetStub_00596680 -- the fields
  // themselves are not written back here (any persistence happens inside that call,
  // still a documented TODO stub).
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
  OrphanRetStub_00596680(col, row);
  g_pDisplayMgr->activeDialog->InvokeSlot13C();
}

// FUNCTION: IMPERIALISM 0x00568ab0
int TOceanDialog::ComputeWrappedTileIndexFromObjectOffset7C7E() {
  short row = static_cast<short>(scrollRowOffset7c + 0xe);
  short col = static_cast<short>(scrollColOffset7e + 0x10);
  NormalizeWrappedMapCoord108x60(&col, &row);
  return col + row * 0x6c;
}

#include "game/TOceanDialog.h"

#include "game/TDisplayMgr.h"
#include "game/global_data_tables.h"

// Standalone binary helper also reached via TWorldView.cpp/TMapDialog.cpp's identical
// bridge (0x51ace0); real signature void(short*, short*).
undefined4 thunk_NormalizeWrappedMapCoord108x60(void);

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
  reinterpret_cast<void(__cdecl*)(short*, short*)>(thunk_NormalizeWrappedMapCoord108x60)(&col,
                                                                                         &row);
  return col + row * 0x6c;
}

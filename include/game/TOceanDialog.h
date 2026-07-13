#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TWorldView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065d020
class TOceanDialog : public TWorldView {
public:
  // TWorldView's own fields end exactly at 0x7c; these are TOceanDialog's own slice.
  // ComputeWrappedTileIndexFromObjectOffset7C7E treats scrollRowOffset7c as the row
  // component (multiplied by the 0x6c map width) and scrollColOffset7e as the column
  // component; ApplyDirectionalNudgeAndRefreshDisplay nudges each by +-4 per direction bit.
  short scrollRowOffset7c; // +0x7c
  short scrollColOffset7e; // +0x7e

  DECLARE_DYNCREATE(TOceanDialog)
  virtual ~TOceanDialog() override;

  virtual void NoOpUiLifecycleHook(int arg) override;
  virtual void ApplyRectSlot110(RECT* rectBuffer) override;

  virtual void RenderMapOrderEntryTilePreview(int arg1, int arg2, int arg3) override;
  virtual void RenderTacticalStackCountIndicatorAndUnitBadge(short tileIndex, int arg2,
                                                             int arg3) override;
  virtual void RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, void* dstRect,
                                                             unsigned char altOverlay) override;
  virtual void RenderStrategicTileSelectionAndNeighborHighlights() override;
  virtual void ForwardProjectTileIndexToWrappedScreenOffsetByScale(int arg1, int arg2, int arg3,
                                                                   int arg4, int arg5) override;
  virtual void ComputeWrappedMapCellAndRegionBandFromScreenCoord(int overlayRecord, short* outRow,
                                                                 unsigned short* outCol,
                                                                 short* outBand) override;
  virtual void UpdateMapDialogTileRowColumnMarkerAndInvalidate(int arg1) override;
  virtual void OrphanRetStub_00596680(int arg1, int arg2) override;
  virtual void OrphanRetStub_005966c0(short arg1) override;
  virtual undefined OrphanLeaf_NoCall_Ins02_005966e0(short arg1) override;
  // Wraps (scrollRowOffset7c+0xe, scrollColOffset7e+0x10) onto the 108x60 hex map via
  // NormalizeWrappedMapCoord108x60 and returns the resulting linear tile index
  // (row*0x6c + col). 0x00568ab0.
  virtual int ComputeWrappedTileIndexFromObjectOffset7C7E();
  void ComputeTileClassBoundsInViewport(int* outRect, int entry); // 0x566060

  // Nudges scrollRowOffset7c/scrollColOffset7e by +-4 per set bit in directionFlags
  // (bit0/1 adjust the row offset, bit2/3 the column offset), forwards the new (col, row)
  // pair to OrphanRetStub_00596680, then refreshes the active dialog surface via
  // g_pDisplayMgr->activeDialog->InvokeSlot13C(). 0x00568a40.
  void ApplyDirectionalNudgeAndRefreshDisplay(unsigned char directionFlags);

  TOceanDialog();
};

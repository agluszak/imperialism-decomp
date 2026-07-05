#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TWorldView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065d020
class TOceanDialog : public TWorldView {
public:
  DECLARE_DYNCREATE(TOceanDialog)
  virtual ~TOceanDialog();

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
  virtual undefined ComputeWrappedTileIndexFromObjectOffset7C7E();

  TOceanDialog();
};

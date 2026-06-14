#pragma once

#include "game/TWorldView.h"

// VTABLE: IMPERIALISM 0x658a58
class TMapDialog : public TWorldView {
public:
  void RenderWrappedMapQuickDrawOverlayFromStridedRecords(int overlayRecord);
  void ForwardMapDialogTileCoordUpdateToDerivedHandler(int tileX, int tileY);

  virtual void RenderMapOrderEntryTilePreview(int arg1, int arg2, int arg3) override;
  virtual void RenderTacticalStackCountIndicatorAndUnitBadge() override;
  virtual void RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, void* dstRect,
                                                             unsigned char altOverlay) override;
  virtual void RenderStrategicTileSelectionAndNeighborHighlights() override;
  virtual void ForwardProjectTileIndexToWrappedScreenOffsetByScale(int arg1, int arg2, int arg3,
                                                                   int arg4, int arg5) override;
  virtual void ComputeWrappedMapCellAndRegionBandFromScreenCoord(int overlayRecord, short* outRow,
                                                                 unsigned short* outCol,
                                                                 short* outBand) override;
  virtual void UpdateMapDialogTileRowColumnMarkerAndInvalidate(int arg1) override;
};

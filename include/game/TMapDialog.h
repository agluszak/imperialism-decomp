#pragma once

#include "game/TWorldView.h"

// VTABLE: IMPERIALISM 0x658a58
class TMapDialog : public TWorldView {
public:
  void RenderWrappedMapQuickDrawOverlayFromStridedRecords(int overlayRecord);
  void ForwardMapDialogTileCoordUpdateToDerivedHandler(int tileX, int tileY);

  virtual void RenderMapOrderEntryTilePreview(int arg1, int arg2, int arg3);
  virtual void RenderTacticalStackCountIndicatorAndUnitBadge();
  virtual void RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, void* dstRect,
                                                             unsigned char altOverlay);
  virtual void RenderStrategicTileSelectionAndNeighborHighlights();
  virtual void ForwardProjectTileIndexToWrappedScreenOffsetByScale(int arg1, int arg2, int arg3,
                                                                   int arg4, int arg5);
  virtual void ComputeWrappedMapCellAndRegionBandFromScreenCoord(int overlayRecord, short* outRow,
                                                                 unsigned short* outCol,
                                                                 short* outBand);
  virtual void UpdateMapDialogTileRowColumnMarkerAndInvalidate(int arg1);
};

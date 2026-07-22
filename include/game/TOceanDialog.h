#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TWorldView.h"
#include "game/mfc.h"

class TZone;

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

  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;

  virtual void RenderMapOrderEntryTilePreview(TCivUnit* orderEntry, int projectedX, int projectedY,
                                              int flag, short tileIndex) override;
  virtual void RenderTacticalStackCountIndicatorAndUnitBadge(short tileIndex, CRect* dstRect,
                                                             int flag) override;
  virtual void RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, CRect* dstRect,
                                                             unsigned char altOverlay) override;
  virtual void RenderStrategicTileSelectionAndNeighborHighlights() override;
  virtual void ForwardProjectTileIndexToWrappedScreenOffsetByScale(int tileIndex,
                                                                   short* viewportOriginXY,
                                                                   short* outVerticalOffset,
                                                                   short* outHorizontalOffset,
                                                                   int projectionScale) override;
  virtual void ConvertPoint(const CPoint& point, short& outColumn, short& outRow,
                            short& outRegionBand) override;
  virtual void CenterOn(int tileIndex) override;
  virtual void SetMapViewCellCoordinates(int column, int row) override;
  virtual void RefreshMapTile(short tileIndex) override;
  virtual unsigned char IsTileVisible(short tileIndex) override;
  // Wraps (scrollRowOffset7c+0xe, scrollColOffset7e+0x10) onto the 108x60 hex map via
  // NormalizeWrappedMapCoord108x60 and returns the resulting linear tile index
  // (row*0x6c + col). 0x00568ab0.
  virtual int ComputeWrappedTileIndexFromObjectOffset7C7E();
  // 0x00565fc0 -- Mac CodeWarrior identity: TOceanDialog::InvalidateTile(short).
  // Invalidates the tile's 16x16 cell in the wrapped ocean viewport.
  void InvalidateTile(short tileIndex);
  // Mac oracle: InvalidateZone / BoundingRect. BoundingRect's CRect return is the
  // hidden output pointer seen as the first stack argument in the Windows listing.
  void InvalidateZone(TZone* zone); // 0x565f80
  CRect BoundingRect(TZone* zone);  // 0x566060

  // Nudges scrollRowOffset7c/scrollColOffset7e by +-4 per set bit in directionFlags
  // (bit0/1 adjust the row offset, bit2/3 the column offset), forwards the new (col, row)
  // pair to SetMapViewCellCoordinates, then refreshes the active dialog surface via
  // g_pDisplayMgr->activeDialog->ForceRedraw(). 0x00568a40.
  void ApplyDirectionalNudgeAndRefreshDisplay(unsigned char directionFlags);

  TOceanDialog();
};

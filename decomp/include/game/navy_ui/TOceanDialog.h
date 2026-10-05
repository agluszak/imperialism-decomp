#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/ui_widgets/TWorldView.h"
#include "game/mfc.h"

class TZone;

// VTABLE: IMPERIALISM 0x0065d020
class TOceanDialog : public TWorldView {
public:
  short scrollRowOffset; // +0x7c
  short scrollColOffset; // +0x7e

  DECLARE_DYNCREATE(TOceanDialog)
  virtual ~TOceanDialog() override;

  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;

  virtual void RenderMapOrderEntryTilePreview(TCivUnit* orderEntry, int projectedX, int projectedY,
                                              int flag, short tileIndex) override;
  virtual void RenderTacticalStackCountIndicatorAndUnitBadge(short tileIndex, CRect* dstRect,
                                                             int flag) override;
  virtual void RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, CRect* dstRect,
                                                             bool altOverlay) override;
  virtual void FrameCursorArea() override;
  virtual void ForwardProjectTileIndexToWrappedScreenOffsetByScale(int tileIndex,
                                                                   const CPoint* viewportOrigin,
                                                                   short* outVerticalOffset,
                                                                   short* outHorizontalOffset,
                                                                   int projectionScale) override;
  virtual void ConvertPoint(const CPoint& point, short& outColumn, short& outRow,
                            short& outRegionBand) override;
  virtual void CenterOn(int tileIndex) override;
  virtual void SetMapViewCellCoordinates(int column, int row) override;
  virtual void RefreshMapTile(short tileIndex) override;
  virtual unsigned char IsTileVisible(short tileIndex) override;
  void BuildTileViewportRect(short tileIndex, CRect* outRect);       // 0x5686d0
  int ComputeWrappedTileIndexFromViewportPoint(const CPoint* point); // 0x568840
  virtual int ComputeWrappedTileIndexFromObjectOffset7C7E();
  void InvalidateTile(short tileIndex);
  void InvalidateZone(TZone* zone); // 0x565f80
  CRect BoundingRect(TZone* zone);  // 0x566060

  void ApplyDirectionalNudgeAndRefreshDisplay(unsigned char directionFlags);

  TOceanDialog();
};
ASSERT_SIZE(TOceanDialog, 0x80);

void DrawTileClassCornerTick(short colorCode, int x, int y, unsigned int cornerFlags);
void DrawOceanRouteSegment(short sourceColumn, int sourceRow, short destinationColumn,
                           int destinationRow);

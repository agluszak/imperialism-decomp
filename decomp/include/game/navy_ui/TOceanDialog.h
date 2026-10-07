#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/ui_widgets/TWorldView.h"
#include "game/mfc.h"

class TZone;

// VTABLE: IMPERIALISM 0x0065d020
class TOceanDialog : public TWorldView {
public:
  short scrollRowOffset;
  short scrollColOffset;

  DECLARE_DYNCREATE(TOceanDialog)
  virtual ~TOceanDialog() override;

  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;

  virtual void DrawUnit(TCivUnit* orderEntry, int projectedX, int projectedY, int flag,
                        short tileIndex) override;
  virtual void DrawGarrison(short tileIndex, CRect* dstRect, int flag) override;
  virtual void DrawFleet(short tileIndex, CRect* dstRect, bool altOverlay) override;
  virtual void FrameCursorArea() override;
  virtual void TileID2TileTopLeft(int tileIndex, const CPoint* viewportOrigin,
                                  short* outVerticalOffset, short* outHorizontalOffset,
                                  int projectionScale) override;
  virtual void ConvertPoint(const CPoint& point, short& outColumn, short& outRow,
                            short& outRegionBand) override;
  virtual void CenterOn(int tileIndex) override;
  virtual void SetMapViewCellCoordinates(int column, int row) override;
  virtual void ImmediateDrawTile(short tileIndex) override;
  virtual bool IsTileVisible(short tileIndex) override;
  void BuildTileViewportRect(short tileIndex, CRect* outRect);
  int TileAtPoint(const CPoint* point);
  virtual int GetCenterTile();
  void InvalidateTile(short tileIndex);
  void InvalidateZone(TZone* zone);
  CRect BoundingRect(TZone* zone);

  void ApplyDirectionalNudgeAndRefreshDisplay(unsigned char directionFlags);

  TOceanDialog();
};
ASSERT_SIZE(TOceanDialog, 0x80);

void DrawTileClassCornerTick(short colorCode, int x, int y, unsigned int cornerFlags);
void DrawOceanRouteSegment(short sourceColumn, int sourceRow, short destinationColumn,
                           int destinationRow);

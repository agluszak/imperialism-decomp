#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/map_domain_types.h"
#include "game/ui_core/TView.h"
#include "game/mfc.h"

class TCivUnit;

// VTABLE: IMPERIALISM 0x668cb0
class TWorldView : public TView {
public:
  CPoint viewportOrigin;
  unsigned short hoveredTileCityRecordIndex;
  unsigned short paintedTileCityRecordIndex;
  unsigned short hoveredTileIndex;
  unsigned short paintedHoverTileIndex;
  short hoverRegionBand;
  short activeRegionBand;
  bool alternateOverlayEnabled;
  unsigned short projectionScale;
  unsigned short previewSquareRadius;
  short stridedCellRecordIndex;

  DECLARE_DYNCREATE(TWorldView)
  TWorldView();
  virtual ~TWorldView() override;

  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoKeyEvent(TToolboxEvent* event) override;
  virtual void DoSetCursor(CPoint* point, RgnHandle hitArg) override;
  virtual void AdjustCursor(CPoint* point, RgnHandle hitArg) override;
  virtual void DoPostCreate(int arg) override;
  virtual bool HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) override;

  virtual void SetMapOverlayModeAndRenderPreview(bool alternateOverlay);
  virtual void DrawOverlay();
  virtual void DrawUnit(TCivUnit* orderEntry, int projectedX, int projectedY, int flag,
                        short tileIndex);
  virtual void DrawGarrison(short tileIndex, CRect* dstRect, int flag);
  virtual void DrawFleet(short tileIndex, CRect* dstRect, bool altOverlay);
  virtual void FrameCursorArea();
  virtual void TileID2TileTopLeft(int tileIndex, const CPoint* viewportOrigin,
                                  short* outVerticalOffset, short* outHorizontalOffset,
                                  int projectionScale);
  virtual short PointToTileID(int unusedArg);
  virtual void ConvertPoint(const CPoint& point, short& outColumn, short& outRow,
                            short& outRegionBand);
  virtual void ControlClick(int tileIndex, int dispatchContext);
  virtual void NavalTileClick(int tileIndexArg, int inputFlags);
  virtual void ShiftClick(int stridedRecord, int dispatchContext);
  virtual void CommandOptionClick(int stridedRecord, int dispatchContext);
  virtual void NormalClick(short nTileIndex, int nInputFlags);
  // ABI: overrides reuse the upper word of the promoted stack dword.
  virtual void CenterOn(int tileIndex);
  virtual short GetCentertile();
  virtual void SetMapViewTileIndex(int tileIndex);
  virtual void SetMapViewCellCoordinates(int column, int row);
  virtual void ImmediateDrawTile(short tileIndex);
  virtual bool IsTileVisible(short tileIndex);
  virtual void NoticeTile(int tileIndex);
};
ASSERT_SIZE(TWorldView, 0x7c);

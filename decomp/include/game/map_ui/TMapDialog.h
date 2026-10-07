#pragma once

#include "game/ui_widgets/TWorldView.h"
#include "game/ui_tags_common.h"

struct TQuickDrawSurfaceContext;

void ProjectTileIndexToWrappedScreenOffsetByScale(short tileIndex, const CPoint* viewportOrigin,
                                                  short* outY, short* outX, short scale);
void ProjectMapCoordinatesToScaledViewport(short row, short column, short* outRow, short* outColumn,
                                           const CPoint* viewportOrigin);
void ProjectTileIndexToScaledViewport(short tileIndex, short* outRow, short* outColumn,
                                      const CPoint* viewportOrigin);
void ProjectMapPointToScaledScreenOffset(const CPoint* sourcePoint, const CPoint* rowReference,
                                         short* outY, short* outX);
short GetWrappedHexDirectionColumnDelta(short direction);
void NormalizeProjectionColumnForRowParity(short* column, short* row);
void ProjectTileIndexToMapGridPoint(int tileIndex, int* outX, int* outY, int cellSize,
                                    short referenceColumn, short referenceRow);

struct TMapDialogTileMarker {
  bool flag;
  char pad01;
  short a;
  short b;
  short c;
};

// VTABLE: IMPERIALISM 0x658a58
class TMapDialog : public TWorldView {
public:
  // CreateObject (0x00519c0e) allocates 0x364 bytes for the concrete object.
  TMapDialogTileMarker tileMarkers[90];
  bool suppressMarkerOverlay;
  unsigned char pad34d[3];
  TQuickDrawSurfaceContext* quickDrawSurface;
  short unresolvedWord354; // +0x354 zeroed by the ctor; no confirmed reader yet
  short selectedTileIndex; // +0x356 ctor-init 0xffff (tile-index "none" sentinel)
  bool unresolvedFlag;     // +0x358 zeroed by the ctor; no confirmed reader yet
  unsigned char pad359[3];
  TObject* overlayObject; // Free() dispatches TObject::Free virtually, then clears it.
  bool tileDebugOverlayEnabled;
  unsigned char pad361[3];

  DECLARE_DYNCREATE(TMapDialog)
  TMapDialog();
  virtual ~TMapDialog() override;

  void Free() override; // 0x00519c90: release both owned resources.

  void Draw(RECT* rectBuffer) override;

  virtual void DrawUnit(TCivUnit* orderEntry, int projectedX, int projectedY, int flag,
                        short tileIndex) override;
  virtual void DrawGarrison(short tileIndex, CRect* dstRect, int flag) override;
  virtual void RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, CRect* dstRect,
                                                             bool altOverlay) override;
  virtual void FrameCursorArea() override;
  virtual void TileID2TileTopLeft(int tileIndex, const CPoint* viewportOrigin,
                                  short* outVerticalOffset, short* outHorizontalOffset,
                                  int projectionScale) override;
  virtual void ConvertPoint(const CPoint& point, short& outColumn, short& outRow,
                            short& outRegionBand) override;
  virtual void CenterOn(int tileIndex) override;

  void PopulateMapContextInfoPanelStringsByTileSelection(short tileIndex, int unusedArg);

  virtual void DoPostCreate(int arg) override;

  void ImmediateDrawTile(short tileIndex) override;
  bool IsTileVisible(short tileIndex) override;
  void SetMapViewTileIndex(int tileIndex) override;
  void SetMapViewCellCoordinates(int column, int row) override;
  virtual void FrameNeighbors(short* neighborTiles);
  // Resets the map-tile sprite variants and all 90 transient tile-marker slots to sentinels.
  virtual void FlushCache();
  virtual void DeCache(short tileIndex);
  virtual void InvalidateTile(short tileIndex);
  virtual void DrawOneTile(short tileIndex, short screenY, short screenX);
  virtual void DrawLandBorders(unsigned char borderMask, int screenX, int screenY, short tileIndex);
  virtual void DrawProvinceBorders(unsigned char borderMask, int screenX, int screenY,
                                   short tileIndex);
  virtual void DrawBorder(short relationLevel, int originX, int originY, int nationA, int nationB);
  virtual void DrawMapDialogGuidePatternSetA(int originX, int originY, short variant);
  virtual void DrawMapDialogGuidePatternSetB(int originX, int originY, short variant);
  virtual void DrawMapDialogGuidePatternSetC(int originX, int originY, short variant);
  virtual void DrawMapDialogGuidePatternSetD(int originX, int originY, short variant);
  virtual void DrawMapDialogTileGuidePatternByVariant(int originX, int originY, short variant);
  virtual void DrawMapDialogGuidePatternSetE(int originX, int originY, short variant);
  virtual void DrawMapDialogGuidePatternSetF(int originX, int originY, short variant);
  virtual void DrawMapDialogGuidePatternSetG(int originX, int originY, short variant);
  virtual void DrawMapDialogGuidePatternSetH(int originX, int originY, short variant);
  virtual void DrawMapDialogGuidePatternSetI(int originX, int originY, short variant);
  virtual void DrawSeaZoneBorders(int screenX, int screenY, short tileIndex);
  virtual void DrawSeaZoneBorders(unsigned char edgeMask, int screenX, int screenY,
                                  short tileIndex);
  virtual void DrawRatLine(short col1, int row1, short col2, int row2);
  virtual void DrawHexNeighborConnectionMask(unsigned char connectionMask, int screenX, int screenY,
                                             short tileIndex);
  virtual void DrawGeneratedMapRouteSegmentsAndResetFillColor();
  virtual void DrawTile(short tileIndex, short screenX, short screenY);
  // Exact 64x64 pixel wedges used to blend a neighboring terrain sprite into the base tile.
  virtual void QuickWedgeSE(unsigned char* src, unsigned char* dest, short srcStride,
                            short destStride);
  virtual void QuickWedgeE(unsigned char* src, unsigned char* dest, short srcStride,
                           short destStride);
  virtual void QuickWedgeNE(unsigned char* src, unsigned char* dest, short srcStride,
                            short destStride);
  virtual void QuickWedgeNW(unsigned char* src, unsigned char* dest, short srcStride,
                            short destStride);
  virtual void QuickWedgeW(unsigned char* src, unsigned char* dest, short srcStride,
                           short destStride);
  virtual void QuickWedgeSW(unsigned char* src, unsigned char* dest, short srcStride,
                            short destStride);
  // Coast joins occupy the corner between two adjacent hex directions.
  virtual void CoastWedgeSE(unsigned char* src, unsigned char* dest, short srcStride,
                            short destStride);
  virtual void CoastWedgeNE(unsigned char* src, unsigned char* dest, short srcStride,
                            short destStride);
  virtual void CoastWedgeS(unsigned char* src, unsigned char* dest, short srcStride,
                           short destStride);
  virtual void CoastWedgeN(unsigned char* src, unsigned char* dest, short srcStride,
                           short destStride);
  virtual void CoastWedgeNW(unsigned char* src, unsigned char* dest, short srcStride,
                            short destStride);
  virtual void CoastWedgeSW(unsigned char* src, unsigned char* dest, short srcStride,
                            short destStride);
  virtual void NewCopy64(unsigned char* src, unsigned char* dest, short srcStride,
                         short destStride);
  virtual int GetCenterTile() const;
  virtual void SetMapDialogCellCoordinatesAndRefresh(int col, int row, int mode);
  virtual void UpdateMapInteractionPreviewParityAndRenderTransientSprites(int edgeMask);
};

ASSERT_SIZE(TMapDialog, 0x364);

#ifdef IMPERIALISM_RUNTIME_TESTS
void ObserveStrategicMapResourceTileForRuntimeTest(short tileIndex, short resourceType);
bool WasStrategicMapResourceTileObservedForRuntimeTest();
void ObserveStrategicMapSurveyMissTileForRuntimeTest(short tileIndex);
bool WasStrategicMapSurveyMissTileObservedForRuntimeTest();
void ObserveStrategicMapImprovementTileForRuntimeTest(short tileIndex, short resourceType,
                                                      short improvementClass);
bool WasStrategicMapImprovementTileObservedForRuntimeTest();
#endif

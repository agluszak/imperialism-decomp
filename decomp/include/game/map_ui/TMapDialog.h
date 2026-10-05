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
  bool flag;  // +0x00
  char pad01; // +0x01
  short a;    // +0x02 (init 0xffff)
  short b;    // +0x04 (init 0xffff)
  short c;    // +0x06 (init 0xffff)
};

// VTABLE: IMPERIALISM 0x658a58
class TMapDialog : public TWorldView {
public:
  // CreateObject (0x00519c0e) allocates 0x364 bytes for the concrete object.
  TMapDialogTileMarker tileMarkers[90]; // +0x7c .. +0x34c
  bool suppressMarkerOverlay; // +0x34c
  unsigned char pad34d[3];
  TQuickDrawSurfaceContext* quickDrawSurface350;
  short unresolvedWord354; // +0x354 zeroed by the ctor; no confirmed reader yet
  short selectedTileIndex; // +0x356 ctor-init 0xffff (tile-index "none" sentinel)
  bool unresolvedFlag;     // +0x358 zeroed by the ctor; no confirmed reader yet
  unsigned char pad359[3];
  TObject* overlayObject; // Free() dispatches TObject::Free virtually, then clears it.
  bool tileDebugOverlayEnabled360; // +0x360
  unsigned char pad361[3];

  DECLARE_DYNCREATE(TMapDialog)
  TMapDialog();
  virtual ~TMapDialog() override;

  void Free() override; // slot 0x07 — 0x00519c90: release both owned resources.

  void Draw(RECT* rectBuffer) override;

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

  void PopulateMapContextInfoPanelStringsByTileSelection(short tileIndex, int unusedArg);

  virtual void DoPostCreate(int arg) override;

  void RefreshMapTile(short tileIndex) override;
  unsigned char IsTileVisible(short tileIndex) override;
  void SetMapViewTileIndex(int arg1) override;
  void SetMapViewCellCoordinates(int column, int row) override;
  virtual void FrameNeighbors(short* neighborTiles);
  // Resets the map-tile sprite variants and all 90 transient tile-marker slots to sentinels.
  virtual void ResetAllTileMarkersToSentinel(); // 0x0051e1a0
  virtual void ReleaseTileMarkerForTile(short tileIndex);
  virtual void InvalidateTile(short tileIndex);
  virtual void DrawOneTile(short tileIndex, short screenY, short screenX);
  virtual void DrawNationBorderSegmentsByMask(unsigned char borderMask, int screenX, int screenY,
                                              short tileIndex);
  virtual void DrawCityBorderSegmentsByMask(unsigned char borderMask, int screenX, int screenY,
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
  // Mac CodeWarrior identity: the argument-taking TMapDialog::DrawSeaZoneBorders overload.
  virtual void DrawSeaZoneBorders(unsigned char edgeMask, int screenX, int screenY,
                                  short tileIndex);
  virtual void DrawWrappedMapRouteSegment(short col1, int row1, short col2, int row2);
  virtual void DrawHexNeighborConnectionMask(unsigned char connectionMask, int screenX, int screenY,
                                             short tileIndex);
  virtual void DrawGeneratedMapRouteSegmentsAndResetFillColor();
  // Mac CodeWarrior identity: TMapDialog::DrawTile(short, short, short).
  virtual void DrawTile(short tileIndex, short screenX, short screenY);
  // Exact 64x64 pixel wedges used to blend a neighboring terrain sprite into the base tile.
  virtual void CopyTerrainTransitionMaskDirection2(unsigned char* src, unsigned char* dest,
                                                   short srcStride, short destStride);
  virtual void CopyTerrainTransitionMaskDirection1(unsigned char* src, unsigned char* dest,
                                                   short srcStride, short destStride);
  virtual void CopyTerrainTransitionMaskDirection0(unsigned char* src, unsigned char* dest,
                                                   short srcStride, short destStride);
  virtual void CopyTerrainTransitionMaskDirection5(unsigned char* src, unsigned char* dest,
                                                   short srcStride, short destStride);
  virtual void CopyTerrainTransitionMaskDirection4(unsigned char* src, unsigned char* dest,
                                                   short srcStride, short destStride);
  virtual void CopyTerrainTransitionMaskDirection3(unsigned char* src, unsigned char* dest,
                                                   short srcStride, short destStride);
  // Coast joins occupy the corner between two adjacent hex directions.
  virtual void CopyCoastCornerMaskBetweenDirections1And2(unsigned char* src, unsigned char* dest,
                                                         short srcStride, short destStride);
  virtual void CopyCoastCornerMaskBetweenDirections0And1(unsigned char* src, unsigned char* dest,
                                                         short srcStride, short destStride);
  virtual void CopyCoastCornerMaskBetweenDirections2And3(unsigned char* src, unsigned char* dest,
                                                         short srcStride, short destStride);
  virtual void CopyCoastCornerMaskBetweenDirections5And0(unsigned char* src, unsigned char* dest,
                                                         short srcStride, short destStride);
  virtual void CopyCoastCornerMaskBetweenDirections4And5(unsigned char* src, unsigned char* dest,
                                                         short srcStride, short destStride);
  virtual void CopyCoastCornerMaskBetweenDirections3And4(unsigned char* src, unsigned char* dest,
                                                         short srcStride, short destStride);
  // Mac CodeWarrior identity: TMapDialog::NewCopy64(unsigned char*, unsigned char*, short, short).
  virtual void NewCopy64(unsigned char* src, unsigned char* dest, short srcStride,
                         short destStride);
  // Mac CodeWarrior identity: TMapDialog::GetCenterTile() const.
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

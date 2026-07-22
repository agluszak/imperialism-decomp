#pragma once

#include "game/TWorldView.h"

struct TQuickDrawSurfaceContext;

// Genuine __cdecl free function (0x00512440, owned by TMapDialog.cpp): projects a tile
// index to a wrapped screen offset at the given scale. Note the vertical output comes
// third, the horizontal fourth.
void ProjectTileIndexToWrappedScreenOffsetByScale(short tileIndex, const CPoint* viewportOrigin,
                                                  short* outY, short* outX, short scale);

// One transient tile-marker slot (8 bytes): a flag byte plus three sentinel-initialized
// coordinate/state shorts. The map dialog keeps an array of 90 (0x5a) of these.
struct TMapDialogTileMarker {
  char flag;  // +0x00
  char pad01; // +0x01
  short a;    // +0x02 (init 0xffff)
  short b;    // +0x04 (init 0xffff)
  short c;    // +0x06 (init 0xffff)
};

// VTABLE: IMPERIALISM 0x658a58
class TMapDialog : public TWorldView {
public:
  // CreateObject (0x00519c0e) allocates 0x364 bytes for the concrete object.
  TMapDialogTileMarker tileMarkers7c[90]; // +0x7c .. +0x34c
  // Suppress-tile-marker-rerender gate: Draw (0x51e260) only blits the marker
  // overlay into quickDrawSurface350 while this is 0. Zeroed by the ctor.
  bool suppressMarkerOverlay34C; // +0x34c
  unsigned char pad34d[3];
  // Released (set to null) by Free(); read by RenderMapDialogTerrainOverlayFrameByTileOwner as
  // the source surface for tile-owner/terrain-frame blits.
  TQuickDrawSurfaceContext* quickDrawSurface350;
  short unresolvedWord354;    // +0x354 zeroed by the ctor; no confirmed reader yet
  short selectedTileIndex356; // +0x356 ctor-init 0xffff (tile-index "none" sentinel)
  bool unresolvedFlag358;     // +0x358 zeroed by the ctor; no confirmed reader yet
  unsigned char pad359[3];
  TObject* overlayObject35C; // Free() dispatches TObject::Free virtually, then clears it.
  // Per-tile debug/text-overlay gate read by RenderStrategicMapTileCell (0x51eb40). Zeroed
  // by the ctor.
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
                                                             unsigned char altOverlay) override;
  virtual void RenderStrategicTileSelectionAndNeighborHighlights() override;
  virtual void ForwardProjectTileIndexToWrappedScreenOffsetByScale(int tileIndex,
                                                                   const CPoint* viewportOrigin,
                                                                   short* outVerticalOffset,
                                                                   short* outHorizontalOffset,
                                                                   int projectionScale) override;
  virtual void ConvertPoint(const CPoint& point, short& outColumn, short& outRow,
                            short& outRegionBand) override;
  virtual void CenterOn(int tileIndex) override;

  // Fills the map-context info panel's 'titl' / 'info' / 'loca' text controls for the
  // selected tile (terrain title, city resource counters + edge-resource requirement
  // levels, and the "city, owner" location line). Attributed to TMapDialog by TU/address
  // locality — the asserts cite D:\Ambit\Cross\UMapDlog.cpp and no live caller references
  // the thunk. The second argument is never read. 0x51b1c0, __thiscall, RET 0x8.
  void PopulateMapContextInfoPanelStringsByTileSelection(short tileIndex, int unusedArg);

  virtual void DoPostCreate(int arg) override;

  void RefreshMapTile(short tileIndex) override;
  unsigned char IsTileVisible(short tileIndex) override;
  void SetMapViewTileIndex(int arg1) override;
  void SetMapViewCellCoordinates(int column, int row) override;
  virtual void DrawHexNeighborOutlineFromTileArray(short* neighborTiles);
  // Resets the map-tile sprite variants and all 90 transient tile-marker slots to sentinels.
  virtual void ResetAllTileMarkersToSentinel(); // 0x0051e1a0
  // Releases the transient tile-marker slot the given tile occupies (marks the tile's
  // terrain record slot 0xff and re-sentinels that marker). 0x0051e1f0
  virtual void ReleaseTileMarkerForTile(short tileIndex);
  // Mac CodeWarrior identity: TMapDialog::InvalidateTile(short). Projects the tile into
  // the current viewport, releases its cached marker, and invalidates its 64x64 cell.
  virtual void InvalidateTile(short tileIndex);
  // Renders one 64x64 strategic-map cell into the tile-cache surface. The final two
  // arguments are destination Y/X respectively (the original callers push X, then Y).
  virtual void RenderStrategicMapTileCell(short tileIndex, short screenY, short screenX);
  virtual void DrawNationBorderSegmentsByMask(unsigned char borderMask, int screenX, int screenY,
                                              short tileIndex);
  virtual void DrawCityBorderSegmentsByMask(unsigned char borderMask, int screenX, int screenY,
                                            short tileIndex);
  // Draws a two-toned bilateral-relation marker: the guide pattern selected by
  // relationLevel (0-9) is drawn twice at (originX, originY) — variant 1 tinted for
  // nationA, variant 2 for nationB (0x35 = minor-nation fallback color).
  // Mac CodeWarrior identity: TMapDialog::DrawBorder(short, short, short, short, short).
  // The Windows body keeps the four coordinate/nation arguments as full stack dwords.
  virtual void DrawBorder(short relationLevel, int originX, int originY, int nationA, int nationB);
  virtual void DrawMapDialogGuidePatternSetA_00520970(int originX, int originY, short variant);
  virtual void DrawMapDialogGuidePatternSetB_00520a90(int originX, int originY, short variant);
  virtual void DrawMapDialogGuidePatternSetC_00520c10(int originX, int originY, short variant);
  virtual void DrawMapDialogGuidePatternSetD_00520d20(int originX, int originY, short variant);
  virtual void DrawMapDialogTileGuidePatternByVariant(int originX, int originY, short variant);
  virtual void DrawMapDialogGuidePatternSetE_00520fc0(int originX, int originY, short variant);
  virtual void DrawMapDialogGuidePatternSetF_00521090(int originX, int originY, short variant);
  virtual void DrawMapDialogGuidePatternSetG_005211c0(int originX, int originY, short variant);
  virtual void DrawMapDialogGuidePatternSetH_00521340(int originX, int originY, short variant);
  virtual void DrawMapDialogGuidePatternSetI_00521540(int originX, int originY, short variant);
  // Mac CodeWarrior identity: TMapDialog::DrawSeaZoneBorders. Draws the colored ownership
  // dividers between the six sea zones surrounding one map tile. VC5 emits same-name
  // overloads in reverse declaration order in the vtable, so this declaration intentionally
  // precedes the argument-taking overload whose retail slot comes first.
  virtual void DrawSeaZoneBorders(int screenX, int screenY, short tileIndex);
  // Mac CodeWarrior identity: the argument-taking TMapDialog::DrawSeaZoneBorders overload.
  virtual void DrawSeaZoneBorders(unsigned char edgeMask, int screenX, int screenY,
                                  short tileIndex);
  virtual void DrawWrappedMapRouteSegment(short col1, int row1, short col2, int row2);
  virtual void DrawHexNeighborConnectionMask(unsigned char connectionMask, int screenX, int screenY,
                                             short tileIndex);
  // Draws every generated inter-region route segment in viewport-relative coordinates,
  // then restores the QuickDraw fill color to black.
  virtual void DrawGeneratedMapRouteSegmentsAndResetFillColor();
  virtual void RenderMapTileAtScreenPositionUsingCache(short tileIndex, short screenX,
                                                       short screenY);
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
  virtual void Copy64x64TileBlockWithStrideAdjustment(int* src, int* dest, short srcStride,
                                                      short destStride);
  // Mac CodeWarrior identity: TMapDialog::GetCenterTile() const.
  virtual int GetCenterTile() const;
  virtual void SetMapDialogCellCoordinatesAndRefresh(int col, int row, int mode);
  virtual void UpdateMapInteractionPreviewParityAndRenderTransientSprites(int unusedArg);
};

ASSERT_SIZE(TMapDialog, 0x364);

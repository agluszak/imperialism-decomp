#pragma once

#include "game/TWorldView.h"

struct TQuickDrawSurfaceContext;

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
  int field34c;                           // +0x34c
  // Released (set to null) by Free(); read by RenderMapDialogTerrainOverlayFrameByTileOwner as
  // the source surface for tile-owner/terrain-frame blits.
  TQuickDrawSurfaceContext* quickDrawSurface350;
  unsigned char pad354[0x35c - 0x354];
  void* field35c; // released (set to null) by Free(); no other confirmed reader.
  unsigned char pad360[0x364 - 0x360];

  DECLARE_DYNCREATE(TMapDialog)
  TMapDialog();
  virtual ~TMapDialog() override;

  void Free() override; // slot 0x07 — 0x00519c90: release quickDrawSurface350/field35c.

  void ApplyRectSlot110(RECT* rectBuffer) override;

  void ForwardMapDialogTileCoordUpdateToDerivedHandler(int tileX, int tileY);

  virtual void RenderMapOrderEntryTilePreview(TCivUnit* orderEntry, int arg2, int arg3) override;
  virtual void RenderTacticalStackCountIndicatorAndUnitBadge(short tileIndex, int arg2,
                                                             int arg3) override;
  virtual void RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, void* dstRect,
                                                             unsigned char altOverlay) override;
  virtual void RenderStrategicTileSelectionAndNeighborHighlights() override;
  virtual void ForwardProjectTileIndexToWrappedScreenOffsetByScale(int arg1, int arg2, int arg3,
                                                                   int arg4, int arg5) override;
  void ProjectTileIndexToWrappedScreenOffsetByScale(short tileIndex, short* originXY, short* outX,
                                                    short* outY, short scale);
  virtual void ComputeWrappedMapCellAndRegionBandFromScreenCoord(int overlayRecord, short* outRow,
                                                                 unsigned short* outCol,
                                                                 short* outBand) override;
  virtual void UpdateMapDialogTileRowColumnMarkerAndInvalidate(int arg1) override;

  virtual void NoOpUiLifecycleHook(int arg) override;

  void OrphanRetStub_005966c0(short arg1) override;
  undefined OrphanLeaf_NoCall_Ins02_005966e0(short arg1) override;
  void OrphanRetStub_005966a0(int arg1) override;
  void OrphanRetStub_00596680(int arg1, int arg2) override;
  virtual void DrawHexNeighborOutlineFromTileArray(short* neighborTiles);
  // Resets the map-tile sprite variants and all 90 transient tile-marker slots to sentinels.
  virtual void ResetAllTileMarkersToSentinel(); // 0x0051e1a0
  // Releases the transient tile-marker slot the given tile occupies (marks the tile's
  // terrain record slot 0xff and re-sentinels that marker). 0x0051e1f0
  virtual void ReleaseTileMarkerForTile(short tileIndex);
  virtual undefined UpdateMapDialogProjectedTileMarkerAndInvalidate();
  virtual undefined RenderStrategicMapTileCell();
  virtual undefined EmitHexAdjacencyTransitionEventsByBitmask();
  virtual undefined DrawHexEdgeConnectionGlyphsByMask();
  virtual undefined RenderMapDialogBilateralRelationMarkers();
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
  virtual void DrawMapDialogOwnershipMarkerForNation_00522000(unsigned char edgeMask, int screenX,
                                                              int screenY, short tileIndex);
  virtual undefined RenderMapDialogDiplomacyNeighborRelationHints();
  virtual void DrawMapDialogWrappedTileConnectionMarker_00522c10(short col1, int row1, short col2,
                                                                 int row2);
  virtual void DrawHexNeighborConnectionMask(unsigned char connectionMask, int screenX, int screenY,
                                             short tileIndex);
  virtual undefined WrapperFor_SetQuickDrawFillColor_At00523060();
  virtual undefined UpdateMapOrderEntryTilePreviewSlot();
  virtual undefined OrphanLeaf_NoCall_Ins100_005241b0();
  virtual undefined GetTEventHandlerClassNamePointer();
  virtual undefined VTableSlot97();
  virtual undefined InitializeForeignMinisterStateFlags();
  virtual undefined AddToForeignMinisterCounterAtIndex();
  virtual undefined SetForeignMinisterReadyFlag14();
  virtual undefined SelectCandidateTilesWithLowGroundUnitCount();
  virtual undefined OrphanLeaf_NoCall_Ins07_004d8920_9c();
  virtual undefined OrphanLeaf_NoCall_Ins07_004d8920_9d();
  virtual undefined CopyDiamondMaskBlockKernel();
  virtual undefined CopyDiagonalMaskNarrowingBlockKernel();
  virtual undefined CopyDiagonalMaskWideningBlockKernel();
  virtual void Copy64x64TileBlockWithStrideAdjustment(int* src, int* dest, short srcStride,
                                                      short destStride);
  virtual undefined HasRenderableParentAndContentSlotA2();
  virtual undefined ReleaseRuntimeSelectionOwnerAndDestroyObject(int param_1, int param_2,
                                                                 int param_3);
  virtual undefined UpdateMapInteractionPreviewParityAndRenderTransientSprites();
};

ASSERT_SIZE(TMapDialog, 0x364);

#pragma once

#include "game/TWorldView.h"

// VTABLE: IMPERIALISM 0x658a58
class TMapDialog : public TWorldView {
public:
  DECLARE_DYNCREATE(TMapDialog)
  TMapDialog();
  virtual ~TMapDialog();

  // slot 0x07 — 0x00519c90: release map-dialog quickdraw surface (+0x350) and child state.
  void Free() override;

  void ApplyRectSlot110(RECT* rectBuffer) override;

  void ForwardMapDialogTileCoordUpdateToDerivedHandler(int tileX, int tileY);

  virtual void RenderMapOrderEntryTilePreview(int arg1, int arg2, int arg3) override;
  virtual void RenderTacticalStackCountIndicatorAndUnitBadge(short tileIndex, int arg2,
                                                             int arg3) override;
  virtual void RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, void* dstRect,
                                                             unsigned char altOverlay) override;
  virtual void RenderStrategicTileSelectionAndNeighborHighlights() override;
  virtual void ForwardProjectTileIndexToWrappedScreenOffsetByScale(int arg1, int arg2, int arg3,
                                                                   int arg4, int arg5) override;
  virtual void ComputeWrappedMapCellAndRegionBandFromScreenCoord(int overlayRecord, short* outRow,
                                                                 unsigned short* outCol,
                                                                 short* outBand) override;
  virtual void UpdateMapDialogTileRowColumnMarkerAndInvalidate(int arg1) override;

  virtual void NoOpUiLifecycleHook(int arg) override;

  void OrphanRetStub_005966c0(short arg1) override;
  undefined OrphanLeaf_NoCall_Ins02_005966e0(short arg1) override;
  void OrphanRetStub_005966a0(int arg1) override;
  void OrphanRetStub_00596680(int arg1, int arg2) override;
  virtual undefined DrawHexNeighborOutlineFromTileArray();
  virtual undefined OrphanCallChain_C1_I20_0051e1a0();
  virtual undefined OrphanLeaf_NoCall_Ins21_0051e1f0();
  virtual undefined UpdateMapDialogProjectedTileMarkerAndInvalidate();
  virtual undefined RenderStrategicMapTileCell();
  virtual undefined EmitHexAdjacencyTransitionEventsByBitmask();
  virtual undefined DrawHexEdgeConnectionGlyphsByMask();
  virtual undefined RenderMapDialogBilateralRelationMarkers();
  virtual undefined DrawMapDialogGuidePatternSetA_00520970();
  virtual undefined DrawMapDialogGuidePatternSetB_00520a90();
  virtual undefined DrawMapDialogGuidePatternSetC_00520c10();
  virtual undefined DrawMapDialogGuidePatternSetD_00520d20();
  virtual undefined DrawMapDialogTileGuidePatternByVariant();
  virtual undefined DrawMapDialogGuidePatternSetE_00520fc0();
  virtual undefined DrawMapDialogGuidePatternSetF_00521090();
  virtual undefined DrawMapDialogGuidePatternSetG_005211c0();
  virtual undefined DrawMapDialogGuidePatternSetH_00521340();
  virtual undefined DrawMapDialogGuidePatternSetI_00521540();
  virtual undefined DrawMapDialogOwnershipMarkerForNation_00522000();
  virtual undefined RenderMapDialogDiplomacyNeighborRelationHints();
  virtual undefined DrawMapDialogWrappedTileConnectionMarker_00522c10();
  virtual undefined DrawHexNeighborConnectionMask();
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
  virtual undefined Copy64x64TileBlockWithStrideAdjustment();
  virtual undefined HasRenderableParentAndContentSlotA2();
  virtual undefined ReleaseRuntimeSelectionOwnerAndDestroyObject(int param_1, int param_2,
                                                                 int param_3);
  virtual undefined UpdateMapInteractionPreviewParityAndRenderTransientSprites();
};

#include "game/TMapDialog.h"
#include "game/QuickDrawSurfaceGuard.h"
#include "game/TGlobalMapState.h"
#include "game/TView.h"
#include "game/diplomacy_globals.h"
#include "game/quickdraw_globals.h"
#include "game/trade_quickdraw.h"

extern "C" long _ftol(void);

undefined4 thunk_NormalizeWrappedMapCoord108x60(void);
undefined4 ComputeStridedRecordAddress6C(void);
undefined4 thunk_ProjectTileIndexToWrappedScreenOffsetByScale(void);
undefined4 thunk_SplitTileIndexToRowAndColumn(void);

#define g_wMapDialogTileRowMarker (*reinterpret_cast<short*>(0x006a33b0))
IMPLEMENT_DYNCREATE(TMapDialog, TWorldView)

TMapDialog::TMapDialog() {}

// SYNTHETIC: IMPERIALISM 0x00519C40
// TMapDialog::`scalar deleting destructor'
TMapDialog::~TMapDialog() {}

// FUNCTION: IMPERIALISM 0x00519c90
void TMapDialog::Free() {
  char* objectBytes = reinterpret_cast<char*>(this);
  void** quickDrawSurfaceSlot = reinterpret_cast<void**>(objectBytes + 0x350);
  if (*quickDrawSurfaceSlot != 0) {
    *quickDrawSurfaceSlot = 0;
  }
  *reinterpret_cast<void**>(objectBytes + 0x35c) = 0;
  TView::Free();
}

// FUNCTION: IMPERIALISM 0x00519D30
void TMapDialog::NoOpUiLifecycleHook(int arg) { (void)arg; }

// FUNCTION: IMPERIALISM 0x00519e00
void TMapDialog::RenderStrategicTileSelectionAndNeighborHighlights() {}

// FUNCTION: IMPERIALISM 0x0051a2a0
undefined TMapDialog::DrawHexNeighborOutlineFromTileArray() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0051A900
undefined TMapDialog::UpdateMapDialogProjectedTileMarkerAndInvalidate() { return 0; }

// FUNCTION: IMPERIALISM 0x0051a990
void TMapDialog::ComputeWrappedMapCellAndRegionBandFromScreenCoord(int overlayRecord, short* outRow,
                                                                   unsigned short* outCol,
                                                                   short* outBand) {
  int* tileOffset = reinterpret_cast<int*>(overlayRecord);
  unsigned int roundedCol = static_cast<unsigned int>(_ftol());
  *outCol = static_cast<unsigned short>(roundedCol);
  short rowValue = 0;
  if ((roundedCol & 1) == 0) {
    rowValue = static_cast<short>(_ftol());
  } else {
    rowValue = static_cast<short>(_ftol()) - 1;
  }
  *outRow = rowValue;
  reinterpret_cast<void(__cdecl*)(short*, short*)>(thunk_NormalizeWrappedMapCoord108x60)(
      outRow, reinterpret_cast<short*>(outCol));

  int wrappedY = viewportOffsetY + tileOffset[1];
  unsigned short signY = static_cast<unsigned short>(wrappedY >> 31);
  short bandRow = static_cast<short>(
                      (((static_cast<unsigned short>(wrappedY) ^ signY) - signY) & 0x3f) ^ signY) -
                  static_cast<short>(signY);

  short bandCol = 0;
  if ((*outCol & 1) == 0) {
    int wrappedX = tileOffset[0] + viewportOffsetX;
    unsigned short signX = static_cast<unsigned short>(wrappedX >> 31);
    bandCol = static_cast<short>(
        (((static_cast<unsigned short>(wrappedX) ^ signX) - signX) & 0x3f) ^ signX);
    bandCol = static_cast<short>(bandCol - static_cast<short>(signX));
  } else {
    int wrappedX = tileOffset[0] + 0x20 + viewportOffsetX;
    unsigned short signX = static_cast<unsigned short>(wrappedX >> 31);
    bandCol = static_cast<short>(
        ((((static_cast<unsigned short>(wrappedX) ^ signX) - signX) & 0x3f) ^ signX) -
        static_cast<short>(signX));
    bandCol = static_cast<short>(bandCol - 1);
  }

  if (bandCol < 0x20) {
    *outBand = static_cast<short>((bandRow < 0x20) + 1);
    return;
  }
  *outBand = static_cast<short>((0x1f < bandRow) + 3);
}

// FUNCTION: IMPERIALISM 0x0051aad0
undefined TMapDialog::OrphanRetStub_005966c0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0051ab60
undefined TMapDialog::OrphanLeaf_NoCall_Ins02_005966e0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0051ac40
void TMapDialog::UpdateMapDialogTileRowColumnMarkerAndInvalidate(int arg1) {
  int tileRowOutput[5] = {0};
  reinterpret_cast<void(__fastcall*)(TMapDialog*, int, int, int*, int*)>(
      thunk_SplitTileIndexToRowAndColumn)(this, 0, arg1, reinterpret_cast<int*>(&arg1),
                                          reinterpret_cast<int*>(&tileRowOutput[0]));
  ForwardMapDialogTileCoordUpdateToDerivedHandler(
      tileRowOutput[0] - static_cast<int>(g_wMapDialogTileRowMarker) / 2, arg1 - 3);
  int invalidateRect[3] = {0, 0x1ff, 0x1bf};
  reinterpret_cast<TView*>(this)->InvalidateCityDialogRectRegion(
      reinterpret_cast<RECT*>(&invalidateRect[0]), 1);
}

// FUNCTION: IMPERIALISM 0x0051ace0
undefined TMapDialog::HasRenderableParentAndContentSlotA2() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0051ad70
undefined TMapDialog::OrphanRetStub_005966a0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0051adc0
undefined TMapDialog::OrphanRetStub_00596680() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0051adf0
undefined TMapDialog::ReleaseRuntimeSelectionOwnerAndDestroyObject(int param_1,
                                                                     undefined4 param_2) {
  return 0;
}

void TMapDialog::ForwardMapDialogTileCoordUpdateToDerivedHandler(int tileX, int tileY) {
  typedef void(__fastcall * TileCoordHandlerFn)(TView * self, int unusedEdx, int x, int y,
                                                int mode);
  TView* view = this;
  int* vtable = *reinterpret_cast<int**>(view);
  reinterpret_cast<TileCoordHandlerFn>(vtable[0x28c / 4])(view, 0, tileX, tileY, 0);
}

// FUNCTION: IMPERIALISM 0x0051AF60
undefined TMapDialog::UpdateMapInteractionPreviewParityAndRenderTransientSprites() { return 0; }

// FUNCTION: IMPERIALISM 0x0051e1a0
undefined TMapDialog::OrphanCallChain_C1_I20_0051e1a0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0051e1f0
undefined TMapDialog::OrphanLeaf_NoCall_Ins21_0051e1f0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0051e260
void TMapDialog::ApplyRectSlot110(RECT* rectBuffer) {
  TView::ApplyRectSlot110(rectBuffer);
}

// FUNCTION: IMPERIALISM 0x0051EB40
undefined TMapDialog::RenderStrategicMapTileCell() { return 0; }

// FUNCTION: IMPERIALISM 0x00520670
undefined TMapDialog::RenderMapDialogBilateralRelationMarkers() { return 0; }

// FUNCTION: IMPERIALISM 0x00520970
undefined TMapDialog::DrawMapDialogGuidePatternSetA_00520970() { return 0; }

// FUNCTION: IMPERIALISM 0x00520A90
undefined TMapDialog::DrawMapDialogGuidePatternSetB_00520a90() { return 0; }

// FUNCTION: IMPERIALISM 0x00520C10
undefined TMapDialog::DrawMapDialogGuidePatternSetC_00520c10() { return 0; }

// FUNCTION: IMPERIALISM 0x00520D20
undefined TMapDialog::DrawMapDialogGuidePatternSetD_00520d20() { return 0; }

// FUNCTION: IMPERIALISM 0x00520DE0
undefined TMapDialog::DrawMapDialogTileGuidePatternByVariant() { return 0; }

// FUNCTION: IMPERIALISM 0x00520FC0
undefined TMapDialog::DrawMapDialogGuidePatternSetE_00520fc0() { return 0; }

// FUNCTION: IMPERIALISM 0x00521090
undefined TMapDialog::DrawMapDialogGuidePatternSetF_00521090() { return 0; }

// FUNCTION: IMPERIALISM 0x005211C0
undefined TMapDialog::DrawMapDialogGuidePatternSetG_005211c0() { return 0; }

// FUNCTION: IMPERIALISM 0x00521340
undefined TMapDialog::DrawMapDialogGuidePatternSetH_00521340() { return 0; }

// FUNCTION: IMPERIALISM 0x00521540
undefined TMapDialog::DrawMapDialogGuidePatternSetI_00521540() { return 0; }

// FUNCTION: IMPERIALISM 0x00521680
undefined TMapDialog::DrawHexEdgeConnectionGlyphsByMask() { return 0; }

// FUNCTION: IMPERIALISM 0x00521A40
undefined TMapDialog::EmitHexAdjacencyTransitionEventsByBitmask() { return 0; }

// FUNCTION: IMPERIALISM 0x00522000
undefined TMapDialog::DrawMapDialogOwnershipMarkerForNation_00522000() { return 0; }

// FUNCTION: IMPERIALISM 0x005220F0
undefined TMapDialog::RenderMapDialogDiplomacyNeighborRelationHints() { return 0; }

// FUNCTION: IMPERIALISM 0x00522C10
undefined TMapDialog::DrawMapDialogWrappedTileConnectionMarker_00522c10() { return 0; }

// FUNCTION: IMPERIALISM 0x00522CF0
undefined TMapDialog::DrawHexNeighborConnectionMask() { return 0; }

// FUNCTION: IMPERIALISM 0x00523060
undefined TMapDialog::WrapperFor_SetQuickDrawFillColor_At00523060() { return 0; }

// FUNCTION: IMPERIALISM 0x00523170
undefined TMapDialog::UpdateMapOrderEntryTilePreviewSlot() { return 0; }

// FUNCTION: IMPERIALISM 0x00523640
void TMapDialog::RenderMapOrderEntryTilePreview(int arg1, int arg2, int arg3) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
}

// FUNCTION: IMPERIALISM 0x00523b70
void TMapDialog::RenderTacticalStackCountIndicatorAndUnitBadge() {}

// FUNCTION: IMPERIALISM 0x00523ff0
void TMapDialog::RenderMapDialogTerrainOverlayFrameByTileOwner(short tileIndex, void* dstRect,
                                                               unsigned char altOverlay) {
  void* surfaceContext = reinterpret_cast<void*>(g_pActiveQuickDrawSurfaceContext);
  char* tileRecord =
      reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable) + tileIndex * 0x24;
  char ownerPaletteIndex = tileRecord[0x16];
  if ((ownerPaletteIndex < 0) || ('\x13' <= ownerPaletteIndex)) {
    return;
  }

  struct {
    long left;
    long top;
    long right;
    long bottom;
  } srcRect;

  if (altOverlay == 0) {
    void* quickDrawSurface = *reinterpret_cast<void**>(reinterpret_cast<char*>(this) + 0x350);
    surfaceContext = quickDrawSurface;
    srcRect.left = static_cast<long>(static_cast<short>(ownerPaletteIndex * 0x40));
    srcRect.right = srcRect.left + 0x40;
    srcRect.top = 0;
    srcRect.bottom = 0x40;
    reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x10);
    int strategicBlitSource = *reinterpret_cast<int*>(0x006a21a8 + 0x690);
    reinterpret_cast<void(__stdcall*)(void*, void*, void*, void*, int, void*)>(
        BlitRectWithOptionalTransparency)(reinterpret_cast<void*>(strategicBlitSource + 4),
                                          reinterpret_cast<char*>(surfaceContext) + 4, &srcRect,
                                          dstRect, 0x24, 0);
    reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x13);
    return;
  }

  if (*reinterpret_cast<unsigned char*>(reinterpret_cast<char*>(this) + 0x74) == 0) {
    short terrainFrameIndex = static_cast<short>(tileRecord[0x10]);
    if (terrainFrameIndex == -1) {
      return;
    }
    srcRect.left = static_cast<long>(terrainFrameIndex) << 6;
    srcRect.right = (terrainFrameIndex + 1) * 0x40;
    srcRect.top = 0;
    srcRect.bottom = 0x40;
    void* quickDrawSurface = *reinterpret_cast<void**>(reinterpret_cast<char*>(this) + 0x350);
    reinterpret_cast<void(__stdcall*)(void*, void*, void*, void*, int, void*)>(
        BlitRectWithOptionalTransparency)(
        reinterpret_cast<char*>(quickDrawSurface) + 4,
        reinterpret_cast<char*>(g_pActiveQuickDrawSurfaceContext) + 4, &srcRect, dstRect, 0, 0);
    return;
  }

  srcRect.left = static_cast<long>(static_cast<short>(ownerPaletteIndex * 0x40 + 0x40));
  srcRect.right = srcRect.left + 0x40;
  srcRect.top = 0;
  srcRect.bottom = 0x40;
  reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x10);
  int strategicBlitSource = *reinterpret_cast<int*>(0x006a21a8 + 0x690);
  reinterpret_cast<void(__stdcall*)(void*, void*, void*, void*, int, void*)>(
      BlitRectWithOptionalTransparency)(reinterpret_cast<void*>(strategicBlitSource + 4),
                                        reinterpret_cast<char*>(surfaceContext) + 4, &srcRect,
                                        dstRect, 0x24, 0);
  reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x13);
}

// FUNCTION: IMPERIALISM 0x005241B0
undefined TMapDialog::OrphanLeaf_NoCall_Ins100_005241b0() { return 0; }

// FUNCTION: IMPERIALISM 0x005242F0
undefined TMapDialog::GetTEventHandlerClassNamePointer() { return 0; }

// FUNCTION: IMPERIALISM 0x00524540
undefined TMapDialog::VTableSlot97() { return 0; }

// FUNCTION: IMPERIALISM 0x00524670
undefined TMapDialog::InitializeForeignMinisterStateFlags() { return 0; }

// FUNCTION: IMPERIALISM 0x005247A0
undefined TMapDialog::AddToForeignMinisterCounterAtIndex() { return 0; }

// FUNCTION: IMPERIALISM 0x005249F0
undefined TMapDialog::SetForeignMinisterReadyFlag14() { return 0; }

// FUNCTION: IMPERIALISM 0x00524B30
undefined TMapDialog::SelectCandidateTilesWithLowGroundUnitCount() { return 0; }

// FUNCTION: IMPERIALISM 0x00524C60
undefined TMapDialog::OrphanLeaf_NoCall_Ins07_004d8920_9c() { return 0; }

// FUNCTION: IMPERIALISM 0x00524E70
undefined TMapDialog::OrphanLeaf_NoCall_Ins07_004d8920_9d() { return 0; }

// FUNCTION: IMPERIALISM 0x005250A0
undefined TMapDialog::CopyDiamondMaskBlockKernel() { return 0; }

// FUNCTION: IMPERIALISM 0x005252D0
undefined TMapDialog::CopyDiagonalMaskNarrowingBlockKernel() { return 0; }

// FUNCTION: IMPERIALISM 0x005254A0
undefined TMapDialog::CopyDiagonalMaskWideningBlockKernel() { return 0; }

// FUNCTION: IMPERIALISM 0x00525670
undefined TMapDialog::Copy64x64TileBlockWithStrideAdjustment() { return 0; }

// FUNCTION: IMPERIALISM 0x00525730
void TMapDialog::ForwardProjectTileIndexToWrappedScreenOffsetByScale(int arg1, int arg2, int arg3,
                                                                     int arg4, int arg5) {
  reinterpret_cast<void(__fastcall*)(TMapDialog*, int, int, int, int, int, int)>(
      thunk_ProjectTileIndexToWrappedScreenOffsetByScale)(reinterpret_cast<TMapDialog*>(arg1), 0,
                                                          arg1, arg2, arg3, arg4, arg5);
}

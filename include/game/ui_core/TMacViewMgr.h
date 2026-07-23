
#pragma once

#include "game/app/TObject.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/city_ui/StrategicMapCallbackRecord.h"

namespace turn_event_dialog {
struct CityOrderSource;
}
#include "game/mfc.h"

class TStream;
class TBitmapResourceLoader;
class TView;
class TCity;
class TBuildingView;
class TCityProductionView;
struct TQuickDrawSurfaceContext;
struct TBitmapSurfaceNode;

// Strategic map view / render system (singleton g_pStrategicMapViewSystem @ 0x006a21a8).
// VTABLE: IMPERIALISM 0x00658660
class TMacViewMgr : public TObject {
public:
  DECLARE_DYNCREATE(TMacViewMgr)
  virtual ~TMacViewMgr() override;                 // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x50a180
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x50a140
  virtual void Free() override;                    // slot 0x07 0x509f70
  virtual void BuildStrategicMapCommodityIconAtlasFrom700To722(); // slot 0x0a 0x50a1a0
  virtual void LoadStrategicMapUnitIconAtlas750();                // slot 0x0b 0x50a3b0
  virtual void LoadStrategicMapUnitOverlayAtlas751();             // slot 0x0c 0x50a3e0
  virtual void LoadStrategicMapOverlayAtlas8699();                // slot 0x0d 0x50a410
  virtual void LoadStrategicMapMarkerAtlas1372();                 // slot 0x0e 0x50a440
  virtual void ApplySellOrderRowToNationState(turn_event_dialog::CityOrderSource* orderSource,
                                              int param_2,
                                              short param_3); // slot 0x0f 0x50bbc0
  virtual void SyncSellTaggedChildControlWithNationState(TView* view, short orderSlot,
                                                         short nationIndex);  // slot 0x10 0x50bc50
  virtual void RefreshCityProductionDetailPanelAndArrowWidgets(word param_1); // slot 0x11 0x50bea0
  virtual TView* MakeBookDialog(int dialogId);                                // slot 0x12 0x50be30
  // RET 0x8 = 2 dwords; body waits on this->activeCityProductionView04, args vestigial.
  virtual void DispatchTurnEvent3B8AndWaitForCompletionFlag(int unusedArg1,
                                                            int unusedArg2); // slot 0x13 0x50d310
  // RET 0x1c = 7 dwords (Ghidra recovered only 2); trailing args RET-derived, body partial.
  virtual void ShowGoldDialogForTurnEventContext(int param_1, int param_2, int arg3, int arg4,
                                                 int arg5, int arg6,
                                                 int arg7); // slot 0x14 0x50d470
  // Mac CodeWarrior oracle signatures. `closeAfterOpen` selects the modal path,
  // which consumes the dialog and therefore returns null.
  virtual TBuildingView*
  OpenBuildingWindow(short buildingSlot, TCity* city, unsigned char closeAfterOpen,
                     unsigned char isEmbeddedPage,
                     TCityProductionView* productionView); // slot 0x15 0x50d360
  virtual void OpenConstructionWindow(short buildingSlot, TCity* city,
                                      TCityProductionView* productionView); // slot 0x16 0x50d5b0
  virtual void RefreshActiveCityBuildingActionAvailabilityIndicators();     // slot 0x17 0x50d8d0
  virtual void ClearActiveCityBuildingViewSlot(short buildingSlot);         // slot 0x18 0x50d8f0
  virtual void ClearActiveCityProductionViewAndDiscardRegion();             // slot 0x19 0x50d920
  virtual void BuildStrategicMapRenderAtlasesAndTileMaskCaches();           // slot 0x1a 0x50a9f0
  virtual void RefreshActiveGoldControlAndUiRuntimeState();                 // slot 0x1b 0x50d950
  virtual void RenderTurnEventPalettePreviewSurfaceAndProgress();           // slot 0x1c 0x50b640
  virtual void RebuildMapTileNeighborHighlightPolygonsForAllTiles();        // slot 0x1d 0x50b9e0
  virtual void RebuildNationClipRegionsAndDispatchMapEvent();               // slot 0x1e 0x50bad0
  virtual void BlitMapOverlayGlyphStrip32x24SkipMask10(TBitmapSurfaceNode** dstSurface,
                                                       short param_2, short param_3,
                                                       short param_4); // slot 0x1f 0x50da80
  virtual void DrawStrategicMapUnitIcon(TBitmapSurfaceNode** pDstSurface, short nIconVariant,
                                        short nDstX,
                                        short nYShift); // slot 0x20 0x50dd40
  virtual void DrawStrategicMapUnitIconOverlay(TBitmapSurfaceNode** pDstSurface,
                                               ushort wOverlayIconId, short nVariantRow,
                                               short nDstX,
                                               short nYShift); // slot 0x21 0x50df40
  virtual void CopySpriteSurfaceToStrideBuffer(TBitmapResourceLoader** loaderHandle,
                                               unsigned char* destinationBits,
                                               short destinationStride);    // slot 0x22 0x50d9e0
  virtual void RenderOffscreenBitmapTileSpanAndRestoreContext(int param_1); // slot 0x23 0x50d700
  // RET 0x8 = 2 dwords. arg1 is the (transformed) hit-test point, arg2 the region-slot
  // index — the previous 1-arg `(short)` form mis-attributed the region index to arg1 and
  // dropped the point (caller 0x4f5e00 dispatches slot 0x90 with (&localPoint, index)).
  virtual bool IsPointInsideClipRegionSlot(CPoint* point,
                                           short regionIndex); // slot 0x24 0x50d6c0
  virtual void
  EnsureClipRegionWrapperAtSlotAndMergeSourceRegion(RgnHandle sourceRegion,
                                                    short slotIndex); // slot 0x25 0x50d680
  virtual RgnHandle GetClipRegionSlotByIndex(short index);            // slot 0x26 0x509e10

  TCityProductionView* activeCityProductionView04;
  RgnHandle regionSlots[0x17];
  RgnHandle tileStateSlots[0x180];
  int padding664;
  TQuickDrawSurfaceContext* atlas668;
  TQuickDrawSurfaceContext* atlas66c;
  TQuickDrawSurfaceContext* atlas670;
  TQuickDrawSurfaceContext* atlas674;
  TQuickDrawSurfaceContext* unitIconAtlas;
  TQuickDrawSurfaceContext* unitOverlayAtlas;
  TQuickDrawSurfaceContext* atlas680;
  TQuickDrawSurfaceContext* atlas684;
  TQuickDrawSurfaceContext* atlas688;
  TQuickDrawSurfaceContext* atlas68c;
  TQuickDrawSurfaceContext* atlas690;
  TQuickDrawSurfaceContext* atlas694[8];
  TQuickDrawSurfaceContext* atlas6b4;
  TQuickDrawSurfaceContext* atlas6b8;
  StrategicMapCallbackRecord callback6bc[0x18];
  StrategicMapCallbackRecord callbackB3c[6];
  StrategicMapCallbackRecord callbackC5c[6];
  int fieldD7c;
  int fieldD80;

  TMacViewMgr();
  void InitializeStrategicMapViewSystem();
  void BlitStrategicMapUnitActivityOverlayFrame(TBitmapSurfaceNode** destinationSurface,
                                                short overlayFrameIndex, short destinationX,
                                                short destinationYFromBottom);
  void BuildStrategicMapGaugeAtlasFrom1422And1423();
  void RefreshCityCapabilityUiHandlesForActiveNation();
  void BuildStrategicMapTileOverlayStripSurfaces800To807();
  void ReloadBitmap244AndRefreshUiCaches();
};

// g_pStrategicMapViewSystem — see game/global_data_tables.h.

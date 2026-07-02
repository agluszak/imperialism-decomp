#pragma once

#include "game/TObject.h"
#include "game/ClipStateRegion.h"
#include "game/StrategicMapCallbackRecord.h"
#include "game/mfc.h"

class TStream;
class TBitmapResourceLoader;
class TView;
struct TQuickDrawSurfaceContext;
struct TBitmapSurfaceNode;

// Strategic map view / render system (singleton g_pStrategicMapViewSystem @ 0x006a21a8).
// VTABLE: IMPERIALISM 0x00658660
class TMacViewMgr : public TObject {
public:
  // === BEGIN GENERATED DECLS (TMacViewMgr) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TMacViewMgr)
  virtual ~TMacViewMgr(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x50a180
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x50a140
  virtual void Free() override;                    // slot 0x07 0x509f70
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined BuildStrategicMapCommodityIconAtlasFrom700To722(); // slot 0x0a 0x50a1a0
  virtual undefined LoadStrategicMapUnitIconAtlas750();                // slot 0x0b 0x50a3b0
  virtual undefined LoadStrategicMapUnitOverlayAtlas751();             // slot 0x0c 0x50a3e0
  virtual undefined LoadStrategicMapOverlayAtlas8699();                // slot 0x0d 0x50a410
  virtual undefined LoadStrategicMapMarkerAtlas1372();                 // slot 0x0e 0x50a440
  virtual undefined OrphanCallChain_C4_I35_0050bbc0(int* param_1, undefined4 param_2,
                                                    short param_3); // slot 0x0f 0x50bbc0
  virtual undefined SyncSellTaggedChildControlWithNationState(int* param_1,
                                                              short param_2); // slot 0x10 0x50bc50
  virtual undefined
  RefreshCityProductionDetailPanelAndArrowWidgets(word param_1);   // slot 0x11 0x50bea0
  virtual undefined ResolveTurnEventDialogOrFailAndInvokeSlot9C(); // slot 0x12 0x50be30
  virtual void DispatchTurnEvent3B8AndWaitForCompletionFlag();     // slot 0x13 0x50d310
  virtual undefined OrphanCallChain_C10_I80_0050d470(undefined4 param_1,
                                                     undefined4 param_2); // slot 0x14 0x50d470
  virtual undefined CreateCityBuildingDialogBySlot(int param_1, undefined4 param_2,
                                                   undefined4 param_3);    // slot 0x15 0x50d360
  virtual undefined OrphanCallChain_C9_I49_0050d5b0(undefined4 param_1);   // slot 0x16 0x50d5b0
  virtual void OrphanLeaf_NoCall_Ins06_0050d8d0();                         // slot 0x17 0x50d8d0
  virtual void OrphanLeaf_NoCall_Ins06_0050d8f0(short param_1);            // slot 0x18 0x50d8f0
  virtual void OrphanCallChain_C1_I10_0050d920();                          // slot 0x19 0x50d920
  virtual undefined RenderOffscreenBitmapGridStripAndRestoreContext();     // slot 0x1a 0x50a9f0
  virtual void WrapperFor_CallObjectOffset24Vslot54IfPresent_At0050d950(); // slot 0x1b 0x50d950
  virtual undefined RenderTurnEventPalettePreviewSurfaceAndProgress();     // slot 0x1c 0x50b640
  virtual undefined RebuildMapTileNeighborHighlightPolygonsForAllTiles();  // slot 0x1d 0x50b9e0
  virtual undefined RebuildNationClipRegionsAndDispatchMapEvent();         // slot 0x1e 0x50bad0
  virtual undefined BlitMapOverlayGlyphStrip32x24SkipMask10(TBitmapSurfaceNode** dstSurface,
                                                            short param_2, short param_3,
                                                            short param_4); // slot 0x1f 0x50da80
  virtual void DrawStrategicMapUnitIcon(TBitmapSurfaceNode** pDstSurface, short nIconVariant,
                                        short nDstX,
                                        short nYShift); // slot 0x20 0x50dd40
  virtual void DrawStrategicMapUnitIconOverlay(TBitmapSurfaceNode** pDstSurface,
                                               ushort wOverlayIconId, short nVariantRow,
                                               short nDstX,
                                               short nYShift); // slot 0x21 0x50df40
  virtual undefined CopySpriteSurfaceToStrideBuffer(TBitmapResourceLoader** loaderHandle,
                                                    undefined4* param_2,
                                                    short param_3); // slot 0x22 0x50d9e0
  virtual undefined
  RenderOffscreenBitmapTileSpanAndRestoreContext(int param_1); // slot 0x23 0x50d700
  virtual undefined
  WrapperFor_IsPointInsideHitRegion_At0050d6c0(short param_1); // slot 0x24 0x50d6c0
  virtual undefined
  EnsureClipRegionWrapperAtSlotAndMergeSourceRegion(undefined4 param_1,
                                                    short param_2);      // slot 0x25 0x50d680
  virtual ClipStateRegionWrapper* GetClipRegionSlotByIndex(short index); // slot 0x26 0x509e10
  // === END GENERATED DECLS (TMacViewMgr) ===

  TView* field04;
  ClipStateRegionWrapper* regionSlots[0x17];
  ClipStateRegionWrapper* tileStateSlots[0x180];
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
  void BuildStrategicMapGaugeAtlasFrom1422And1423();
  void RefreshCityCapabilityUiHandlesForActiveNation();
  void BuildStrategicMapTileOverlayStripSurfaces800To807();
  void ReloadBitmap244AndRefreshUiCaches();
};

// g_pStrategicMapViewSystem — see game/global_data_tables.h.

// === BEGIN GENERATED (TMacViewMgr) — refreshed by `just gen-class TMacViewMgr`; do not hand-edit
// ===
// clang-format off
// vtable @ 0x00658660 (39 slots), object size 0xd84, base TObject
//   slot 0x00  byte 0x00  0x00509c80  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x00509e30  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x0050a180  override  WriteTo
//   slot 0x06  byte 0x18  0x0050a140  override  ReadFrom
//   slot 0x07  byte 0x1c  0x00509f70  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0050a1a0  override  BuildStrategicMapCommodityIconAtlasFrom700To722
//   slot 0x0b  byte 0x2c  0x0050a3b0  override  LoadStrategicMapUnitIconAtlas750
//   slot 0x0c  byte 0x30  0x0050a3e0  override  LoadStrategicMapUnitOverlayAtlas751
//   slot 0x0d  byte 0x34  0x0050a410  override  LoadStrategicMapOverlayAtlas8699
//   slot 0x0e  byte 0x38  0x0050a440  override  LoadStrategicMapMarkerAtlas1372
//   slot 0x0f  byte 0x3c  0x0050bbc0  override  OrphanCallChain_C4_I35_0050bbc0
//   slot 0x10  byte 0x40  0x0050bc50  override  SyncSellTaggedChildControlWithNationState
//   slot 0x11  byte 0x44  0x0050bea0  override  RefreshCityProductionDetailPanelAndArrowWidgets
//   slot 0x12  byte 0x48  0x0050be30  override  ResolveTurnEventDialogOrFailAndInvokeSlot9C
//   slot 0x13  byte 0x4c  0x0050d310  override  DispatchTurnEvent3B8AndWaitForCompletionFlag
//   slot 0x14  byte 0x50  0x0050d470  override  OrphanCallChain_C10_I80_0050d470
//   slot 0x15  byte 0x54  0x0050d360  override  CreateCityBuildingDialogBySlot
//   slot 0x16  byte 0x58  0x0050d5b0  override  OrphanCallChain_C9_I49_0050d5b0
//   slot 0x17  byte 0x5c  0x0050d8d0  override  OrphanLeaf_NoCall_Ins06_0050d8d0
//   slot 0x18  byte 0x60  0x0050d8f0  override  OrphanLeaf_NoCall_Ins06_0050d8f0
//   slot 0x19  byte 0x64  0x0050d920  override  OrphanCallChain_C1_I10_0050d920
//   slot 0x1a  byte 0x68  0x0050a9f0  override  RenderOffscreenBitmapGridStripAndRestoreContext
//   slot 0x1b  byte 0x6c  0x0050d950  override  WrapperFor_CallObjectOffset24Vslot54IfPresent_At0050d950
//   slot 0x1c  byte 0x70  0x0050b640  override  RenderTurnEventPalettePreviewSurfaceAndProgress
//   slot 0x1d  byte 0x74  0x0050b9e0  override  RebuildMapTileNeighborHighlightPolygonsForAllTiles
//   slot 0x1e  byte 0x78  0x0050bad0  override  RebuildNationClipRegionsAndDispatchMapEvent
//   slot 0x1f  byte 0x7c  0x0050da80  override  BlitMapOverlayGlyphStrip32x24SkipMask10
//   slot 0x20  byte 0x80  0x0050dd40  override  DrawStrategicMapUnitIcon
//   slot 0x21  byte 0x84  0x0050df40  override  DrawStrategicMapUnitIconOverlay
//   slot 0x22  byte 0x88  0x0050d9e0  override  CopySpriteSurfaceToStrideBuffer
//   slot 0x23  byte 0x8c  0x0050d700  override  RenderOffscreenBitmapTileSpanAndRestoreContext
//   slot 0x24  byte 0x90  0x0050d6c0  override  WrapperFor_IsPointInsideHitRegion_At0050d6c0
//   slot 0x25  byte 0x94  0x0050d680  override  EnsureClipRegionWrapperAtSlotAndMergeSourceRegion
//   slot 0x26  byte 0x98  0x00509e10  override  GetClipRegionSlotByIndex
// object size 0xd84 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TMacViewMgr) ===

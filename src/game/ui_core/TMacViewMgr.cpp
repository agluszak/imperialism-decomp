#include "game/ui_core/TMacViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/map/map_overlay_geometry.h"

#include <new>

#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/app/TAnimation.h"
#include "game/app/TAnimator.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_core/TBitmapResourceLoader.h"
#include "game/city_ui/TBuildingConstructionView.h"
#include "game/city_ui/TBuildingView.h"
#include "game/gfx/CDib.h"
#include "game/city/TCity.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/ui_core/TControl.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/map/TMapMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_widgets/TMyStaticText.h"
#include "game/ui_widgets/TTradeCluster.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_widgets/TTransportPicture.h"
#include "game/ui_screens/TRightLeftView.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_screens/TSetupRandomMapPicture.h"
#include "game/ui_core/TStaticText.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_core/TTurnEventDialogFactoryRegistry.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/ui_message_pump.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/mfc.h"
#include "game/ui_screens/turn_flow_cooldown.h"
#include "game/ui_text_label_helpers_decls.h"
#include "decomp_types.h"
#include <string.h>

// Genuine __cdecl(void*, int) heap-block reallocator; cast at call sites (same pattern
// as TAutoGreatPower.cpp/TCountry.cpp). Returns the new block, or 0 on failure.

// These are file-scope helpers only so the three big refresh bodies can share them; the
// original inlines every one of them. The build uses /Ob1, which inlines ONLY
// inline-marked functions, so a plain `static` helper compiles to a CALL the original
// does not have -- 0x50bea0 spent four of them (see the decomp-loop big-functions note on
// monolithic bodies). __inline is what folds them back into the caller.
namespace {

static __inline TTransportPicture* ResolveTaggedPanelOrFail(TView* hostView, unsigned int tag) {
  TTransportPicture* panel = static_cast<TTransportPicture*>(hostView->ResolveControlByTag(tag));
  if (panel == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  return panel;
}

static __inline TControl* ResolveTaggedChildOrFail(TControl* panel, unsigned int tag) {
  TControl* child = static_cast<TControl*>(panel->ResolveControlByTag(tag));
  if (child == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  return child;
}

static __inline void CopyViewLayoutFieldsToStack(int* layout0, int* layout1, TControl* srcControl) {
  TView* srcView = srcControl;
  layout0[0] = srcView->ownerLocalX;
  layout0[1] = srcView->ownerLocalY;
  layout1[0] = srcView->frameWidth34;
  layout1[1] = srcView->frameHeight38;
}

static __inline void ScanBracketExpressionsInto(CString* dest, const CString& templateText,
                                                const CString& token1, const CString& token2,
                                                const CString& token3) {
  // The scanner is variadic: omitting these three source CString values made [1]-[3]
  // consume unrelated stack slots and corrupted the transport ledger hover text.
  scanBracketExpressions(g_pSimMgr, dest, static_cast<LPCSTR>(templateText),
                         static_cast<LPCSTR>(token1), static_cast<LPCSTR>(token2),
                         static_cast<LPCSTR>(token3));
}

static __inline unsigned char QueryPointInsideHitRegion(CPoint* point, RgnHandle region) {
  return PtInRgn(point, region);
}

static __inline void InvokeBuildHexNeighborHighlightPolygonForTile(short tileId, int tileIndex) {
  BuildHexNeighborHighlightPolygonForTile(tileId, tileIndex);
}

// The loader's original vtable has no destructor slot; every caller owns this exact type.
IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
static __inline void ReleaseBitmapLoaderHandle(TBitmapResourceLoader** loaderHandle) {
  if (loaderHandle == nullptr) {
    return;
  }
  delete *loaderHandle;
  delete loaderHandle;
}
IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE

static __inline void ResolveAndBlitBitmapResourceToActiveAtlas(int resourceId, RECT* dstRect) {
  TBitmapResourceLoader** loaderHandle = CreateBitmapResourceLoaderHandle(resourceId);
  TBitmapResourceLoader* loader = loaderHandle != 0 ? *loaderHandle : 0;
  if (loader != 0) {
    loader->EnsureBitmapResourceLoadedAndCopyRectSize();
    loader->flags |= 1;
    BlitBitmapResourceLoaderToActiveDc(loaderHandle, dstRect);
    loader->ReleaseBitmapResource();
    loader->flags &= static_cast<unsigned char>(~1);
  }
  ReleaseBitmapLoaderHandle(loaderHandle);
}

} // namespace

// SYNTHETIC: IMPERIALISM 0x00509c00
// TMacViewMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x00509c80
// TMacViewMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMacViewMgr, TObject)

// FUNCTION: IMPERIALISM 0x00509ca0
TMacViewMgr::TMacViewMgr() : TObject() {
  activeCityProductionView04 = 0;
  int index = 0;
  while (index < 0x17) {
    regionSlots[index] = 0;
    ++index;
  }
  index = 0;
  while (index < 0x180) {
    tileStateSlots[index] = 0;
    ++index;
  }
  fieldD7c = 0;
  fieldD80 = 0;
  atlas668 = 0;
  atlas674 = 0;
  unitIconAtlas = 0;
  unitOverlayAtlas = 0;
  atlas670 = 0;
  atlas66c = 0;
  atlas680 = 0;
  atlas684 = 0;
  atlas6b4 = 0;
  atlas6b8 = 0;
  atlas688 = 0;
  atlas68c = 0;
  atlas690 = 0;
  index = 0;
  while (index < 8) {
    atlas694[index] = 0;
    ++index;
  }
}

// FUNCTION: IMPERIALISM 0x00509e10
RgnHandle TMacViewMgr::GetClipRegionSlotByIndex(short index) {
  return regionSlots[index];
}

// SYNTHETIC: IMPERIALISM 0x00509e30
// TMacViewMgr::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00509e60
TMacViewMgr::~TMacViewMgr() {}

// FUNCTION: IMPERIALISM 0x00509f20
void TMacViewMgr::IMacViewMgr() {
  g_pAssetMgr->OpenFilesFor(3);
  BuildStrategicMapCommodityIconAtlasFrom700To722();
  LoadStrategicMapUnitIconAtlas750();
  LoadStrategicMapUnitOverlayAtlas751();
  LoadStrategicMapOverlayAtlas8699();
  BuildStrategicMapGaugeAtlasFrom1422And1423();
  RefreshCityCapabilityUiHandlesForActiveNation();
  BuildStrategicMapTileOverlayStripSurfaces800To807();
}

// FUNCTION: IMPERIALISM 0x00509f70
void TMacViewMgr::Free() {
  int index = 0;
  while (index < 0x17) {
    if (regionSlots[index] != 0) {
      DisposeRgn(regionSlots[index]);
      regionSlots[index] = 0;
    }
    ++index;
  }
  index = 0;
  while (index < 0x180) {
    if (tileStateSlots[index] != 0) {
      DisposeRgn(tileStateSlots[index]);
      tileStateSlots[index] = 0;
    }
    ++index;
  }
  g_pDisplayMgr->RemoveGWorld(unitIconAtlas);
  g_pDisplayMgr->RemoveGWorld(unitOverlayAtlas);
  g_pDisplayMgr->RemoveGWorld(atlas674);
  g_pDisplayMgr->RemoveGWorld(atlas668);
  g_pDisplayMgr->RemoveGWorld(atlas66c);
  g_pDisplayMgr->RemoveGWorld(atlas670);
  g_pDisplayMgr->RemoveGWorld(atlas680);
  g_pDisplayMgr->RemoveGWorld(atlas688);
  g_pDisplayMgr->RemoveGWorld(atlas68c);
  g_pDisplayMgr->RemoveGWorld(atlas690);
  g_pDisplayMgr->RemoveGWorld(atlas684);
  g_pDisplayMgr->RemoveGWorld(atlas6b4);
  g_pDisplayMgr->RemoveGWorld(atlas6b8);
  index = 0;
  while (index < 8) {
    g_pDisplayMgr->RemoveGWorld(atlas694[index]);
    ++index;
  }
  g_pMacViewMgr = 0;
  delete this;
}

// FUNCTION: IMPERIALISM 0x0050a140
void TMacViewMgr::ReadFrom(TStream* stream) {
  activeCityProductionView04 = 0;
  TObject::ReadFrom(stream);
  RebuildMapTileNeighborHighlightPolygonsForAllTiles();
  RenderTurnEventPalettePreviewSurfaceAndProgress();
  RefreshCityCapabilityUiHandlesForActiveNation();
}

// FUNCTION: IMPERIALISM 0x0050a180
void TMacViewMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
}

// FUNCTION: IMPERIALISM 0x0050a1a0
void TMacViewMgr::BuildStrategicMapCommodityIconAtlasFrom700To722() {
  RECT atlasBounds;
  TQuickDrawSurfaceContext* savedContext;
  int savedFlags;
  TBitmapSurfaceNode** atlasSurface;
  unsigned char* pixelBuffer;
  unsigned int pixelCount;
  int commodityIndex;
  int stridePixels;
  unsigned char* dstCursor;
  atlasBounds.left = 0;
  atlasBounds.top = 0;
  atlasBounds.right = 0x2e0;
  atlasBounds.bottom = 0x18;
  g_pDisplayMgr->MakeNewGWorld(atlas674, 8, atlasBounds);
  GetGWorld(&savedContext, &savedFlags);
  SetGWorld(atlas674, savedFlags);
  atlasSurface = static_cast<TBitmapSurfaceNode**>(GetGWorldPixMap(atlas674));
  LockPixels(atlasSurface);
  ResetQuickDrawStrokeState();
  pixelBuffer = GetPixBaseAddr(atlasSurface);
  pixelCount = (atlasBounds.right - atlasBounds.left) * (atlasBounds.bottom - atlasBounds.top);
  memset(pixelBuffer, 0, pixelCount);
  stridePixels = static_cast<short>(static_cast<ushort>((*atlasSurface)->stride) & 0x3fff);
  dstCursor = pixelBuffer - 0x20;
  commodityIndex = 0;
  while (commodityIndex < 0x17) {
    TBitmapResourceLoader** loaderHandle = CreateBitmapResourceLoaderHandle(commodityIndex + 700);
    if (loaderHandle != nullptr && *loaderHandle != 0) {
      TBitmapResourceLoader* loader = *loaderHandle;
      loader->EnsureBitmapResourceLoadedAndCopyRectSize();
      loader->flags |= 1;
      dstCursor += 0x20;
      CopySpriteSurfaceToStrideBuffer(loaderHandle, dstCursor, static_cast<short>(stridePixels));
      loader->ReleaseBitmapResource();
      loader->flags &= static_cast<unsigned char>(~1);
    }
    ReleaseBitmapLoaderHandle(loaderHandle);
    commodityIndex = commodityIndex + 1;
  }
  UnlockPixels(GetGWorldPixMap(atlas674));
  SetGWorld(savedContext, savedFlags);
}

// FUNCTION: IMPERIALISM 0x0050a3b0
void TMacViewMgr::LoadStrategicMapUnitIconAtlas750() {
  unitIconAtlas = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x2ee);
}

// FUNCTION: IMPERIALISM 0x0050a3e0
void TMacViewMgr::LoadStrategicMapUnitOverlayAtlas751() {
  unitOverlayAtlas = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x2ef);
}

// FUNCTION: IMPERIALISM 0x0050a410
void TMacViewMgr::LoadStrategicMapOverlayAtlas8699() {
  atlas680 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x21fb);
}

// FUNCTION: IMPERIALISM 0x0050a440
void TMacViewMgr::LoadStrategicMapMarkerAtlas1372() {
  atlas684 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x55c);
}

// FUNCTION: IMPERIALISM 0x0050a470
void TMacViewMgr::BuildStrategicMapGaugeAtlasFrom1422And1423() {
  RECT atlasBounds;
  TQuickDrawSurfaceContext* savedContext;
  int savedFlags;
  atlasBounds.left = 0;
  atlasBounds.top = 0;
  atlasBounds.right = 0x500;
  atlasBounds.bottom = 0x10;
  g_pDisplayMgr->MakeNewGWorld(atlas688, 8, atlasBounds);
  GetGWorld(&savedContext, &savedFlags);
  SetGWorld(atlas688, savedFlags);
  LockPixels(GetGWorldPixMap(atlas688));
  ResetQuickDrawStrokeState();
  ResolveAndBlitBitmapResourceToActiveAtlas(0x58e, &atlasBounds);
  ResolveAndBlitBitmapResourceToActiveAtlas(0x58f, &atlasBounds);
  UnlockPixels(GetGWorldPixMap(atlas688));
  SetGWorld(savedContext, savedFlags);
}

// FUNCTION: IMPERIALISM 0x0050a6a0
void TMacViewMgr::RefreshCityCapabilityUiHandlesForActiveNation() {
  short nationId;
  unsigned int variant;
  if (IsTurnFlowCooldownActiveAndResetExpiredState() != 0) {
    return;
  }
  if (this == 0 || g_pTechMgr == 0) {
    return;
  }
  if (atlas68c != 0) {
    g_pDisplayMgr->RemoveGWorld(atlas68c);
  }
  if (atlas690 != 0) {
    g_pDisplayMgr->RemoveGWorld(atlas690);
  }
  nationId = g_pSimMgr->GetActiveNationId();
  if (nationId < 0) {
    return;
  }
  g_pAssetMgr->OpenFilesFor(3);
  nationId = g_pSimMgr->GetActiveNationId();
  variant = g_pTechMgr->orderCapRows277[nationId].techStatusByTechId[0x0f] != 0;
  nationId = g_pSimMgr->GetActiveNationId();
  if (g_pTechMgr->orderCapRows277[nationId].techStatusByTechId[0x18] != 0) {
    variant = 2;
  }
  nationId = g_pSimMgr->GetActiveNationId();
  atlas68c = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(nationId + 0x579 + variant * 7);
  nationId = g_pSimMgr->GetActiveNationId();
  atlas690 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(nationId + 0x564 + variant * 7);
}

// Listing 0x0050a820 inlines the loader's exact-type non-virtual destructor.
IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
// FUNCTION: IMPERIALISM 0x0050a820
void TMacViewMgr::BuildStrategicMapTileOverlayStripSurfaces800To807() {
  TQuickDrawSurfaceContext* savedContext;
  int savedFlags;
  int stripIndex;
  GetGWorld(&savedContext, &savedFlags);
  stripIndex = 0;
  while (stripIndex < 8) {
    TBitmapResourceLoader** loaderHandle = CreateBitmapResourceLoaderHandle(stripIndex + 800);
    if (*loaderHandle == 0) {
      return;
    }
    TBitmapResourceLoader* loader = *loaderHandle;
    RECT resourceBounds;
    CopyRect(&resourceBounds, &loader->bitmapRect);
    g_pDisplayMgr->MakeNewGWorld(atlas694[stripIndex], 8, resourceBounds);
    SetGWorld(atlas694[stripIndex], savedFlags);
    LockPixels(GetGWorldPixMap(atlas694[stripIndex]));
    QDLoadResource(loaderHandle);
    if (*loaderHandle != 0) {
      loader = *loaderHandle;
      loader->EnsureBitmapResourceLoadedAndCopyRectSize();
      loader->flags |= 1;
      ResetQuickDrawStrokeState();
      BlitBitmapResourceLoaderToActiveDc(loaderHandle, &resourceBounds);
      if (stripIndex == 0) {
        (*GetGWorldPixMap(atlas694[stripIndex]))->dib->FlipScanlineOrder();
      }
      loader = *loaderHandle;
      loader->ReleaseBitmapResource();
      loader->flags &= 0xfe;
      delete loader;
      delete loaderHandle;
    }
    UnlockPixels(GetGWorldPixMap(atlas694[stripIndex]));
    stripIndex = stripIndex + 1;
  }
  SetGWorld(savedContext, savedFlags);
}
IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE

// FUNCTION: IMPERIALISM 0x0050a9f0
void TMacViewMgr::BuildStrategicMapRenderAtlasesAndTileMaskCaches() {
  RECT atlasBounds;
  TQuickDrawSurfaceContext* savedContext;
  int savedFlags;
  int dstX;
  int resourceId;
  int index;
  atlasBounds.left = 0;
  atlasBounds.top = 0;
  atlasBounds.right = 0xcc0;
  atlasBounds.bottom = 0x40;
  g_pDisplayMgr->MakeNewGWorld(atlas668, 8, atlasBounds);
  GetGWorld(&savedContext, &savedFlags);
  SetGWorld(atlas668, savedFlags);
  LockPixels(GetGWorldPixMap(atlas668));
  ResetQuickDrawStrokeState();
  // atlas668 is a single 51-cell horizontal strip. The returned tile offsets are byte
  // offsets into this row, so wrapping the resources into multiple rows corrupts every
  // lookup after the second cell.
  dstX = 0;
  index = 0;
  while (index < 0x2a) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(10000 + index, &blitRect);
    dstX = dstX + 0x40;
    index = index + 1;
  }
  index = 0;
  while (index < 4) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(0x276e + index, &blitRect);
    dstX = dstX + 0x40;
    index = index + 1;
  }
  index = 0;
  while (index < 4) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(0x2774 + index, &blitRect);
    dstX = dstX + 0x40;
    index = index + 1;
  }
  {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(0x277e, &blitRect);
  }
  UnlockPixels(GetGWorldPixMap(atlas668));
  SetGWorld(savedContext, savedFlags);

  atlasBounds.right = 0xa80;
  g_pDisplayMgr->MakeNewGWorld(atlas66c, 8, atlasBounds);
  GetGWorld(&savedContext, &savedFlags);
  SetGWorld(atlas66c, savedFlags);
  LockPixels(GetGWorldPixMap(atlas66c));
  ResetQuickDrawStrokeState();
  dstX = 0;
  resourceId = 0x190;
  while (resourceId < 0x1ab) {
    if (resourceId != 0x195 && resourceId != 0x19e && resourceId != 0x1a7) {
      RECT blitRect;
      blitRect.left = dstX;
      blitRect.top = 0;
      blitRect.right = dstX + 0x40;
      blitRect.bottom = 0x40;
      ResolveAndBlitBitmapResourceToActiveAtlas(resourceId, &blitRect);
    }
    dstX = dstX + 0x40;
    resourceId = resourceId + 1;
  }
  resourceId = 0x226;
  while (resourceId < 0x22e) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(resourceId, &blitRect);
    dstX = dstX + 0x40;
    resourceId = resourceId + 1;
  }
  resourceId = 0x230;
  while (resourceId < 0x233) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(resourceId, &blitRect);
    dstX = dstX + 0x40;
    resourceId = resourceId + 1;
  }
  index = 0;
  while (index < 2) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(0x2778 + index, &blitRect);
    dstX = dstX + 0x40;
    index = index + 1;
  }
  index = 0;
  while (index < 2) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(0x242 + index, &blitRect);
    dstX = dstX + 0x40;
    index = index + 1;
  }
  UnlockPixels(GetGWorldPixMap(atlas66c));
  SetGWorld(savedContext, savedFlags);

  atlasBounds.right = 0xd7;
  atlasBounds.bottom = 0x78;
  g_pDisplayMgr->MakeNewGWorld(atlas670, 8, atlasBounds);
  atlasBounds.right = 0x90;
  atlasBounds.bottom = 0x26;
  g_pDisplayMgr->MakeNewGWorld(atlas6b4, 8, atlasBounds);
  GetGWorld(&savedContext, &savedFlags);
  SetGWorld(atlas6b4, savedFlags);
  LockPixels(GetGWorldPixMap(atlas6b4));
  ResetQuickDrawStrokeState();
  dstX = 0;
  resourceId = 0x23a;
  while (resourceId < 0x242) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 0x12;
    blitRect.bottom = 0x26;
    ResolveAndBlitBitmapResourceToActiveAtlas(resourceId, &blitRect);
    dstX = dstX + 0x12;
    resourceId = resourceId + 1;
  }
  UnlockPixels(GetGWorldPixMap(atlas6b4));
  SetGWorld(savedContext, savedFlags);

  if (atlas6b8 != 0) {
    g_pDisplayMgr->RemoveGWorld(atlas6b8);
  }
  atlasBounds.left = 0;
  atlasBounds.top = 0;
  atlasBounds.right = 0x48;
  atlasBounds.bottom = 6;
  g_pDisplayMgr->MakeNewGWorld(atlas6b8, 8, atlasBounds);
  GetGWorld(&savedContext, &savedFlags);
  SetGWorld(atlas6b8, savedFlags);
  LockPixels(GetGWorldPixMap(atlas6b8));
  ResetQuickDrawStrokeState();
  ResolveAndBlitBitmapResourceToActiveAtlas(0x244, &atlasBounds);
  UnlockPixels(GetGWorldPixMap(atlas6b8));
  SetGWorld(savedContext, savedFlags);

  index = 0;
  while (index < 0x10) {
    strategicTileMasks6bc[index].BuildBitmapMaskOpcodeBufferFromResourceRows(index + 0x2740, 0x40,
                                                                             0x40, 0x1680, 0x10);
    index = index + 1;
  }
  resourceId = 0x2760;
  while (resourceId < 0x2766) {
    strategicTileMasks6bc[0x18 + resourceId - 0x2760].BuildBitmapMaskOpcodeBufferFromResourceRows(
        resourceId - 0x26, 0x40, 0x40, 0x1680, 0x10);
    strategicTileMasks6bc[0x1e + resourceId - 0x2760].BuildBitmapMaskOpcodeBufferFromResourceRows(
        resourceId, 0x40, 0x40, 0x1680, 0x10);
    resourceId = resourceId + 1;
  }
  index = 0x10;
  while (index < 0x18) {
    strategicTileMasks6bc[index].BuildBitmapMaskOpcodeBufferFromResourceRows(index + 0x2756, 0x40,
                                                                             0x40, 0x1680, 0x10);
    index = index + 1;
  }
}

// FUNCTION: IMPERIALISM 0x0050b5b0
void TMacViewMgr::ReloadBitmap244AndRefreshUiCaches() {
  g_pAssetMgr->OpenFilesFor(3);
  if (atlas6b8 != 0) {
    g_pDisplayMgr->RemoveGWorld(atlas6b8);
  }
  atlas6b8 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x244);
  if (atlas688 != 0) {
    g_pDisplayMgr->RemoveGWorld(atlas688);
  }
  LoadStrategicMapOverlayAtlas8699();
}

// FUNCTION: IMPERIALISM 0x0050b640
void TMacViewMgr::RenderTurnEventPalettePreviewSurfaceAndProgress() {
  RECT fillRect;
  TQuickDrawSurfaceContext* savedContext;
  int savedFlags;
  TBitmapSurfaceNode** surfaceObject;
  unsigned char* pixelBase;
  unsigned int strideBytes;
  int tileIndex;
  int colOffset;
  unsigned char paletteByte;
  short terrainCode;
  unsigned char* scratchBuffer;
  fillRect.left = 0;
  fillRect.top = 0;
  fillRect.right = 0xd7;
  fillRect.bottom = 0x78;
  GetGWorld(&savedContext, &savedFlags);
  SetGWorld(atlas670, savedFlags);
  surfaceObject = static_cast<TBitmapSurfaceNode**>(GetGWorldPixMap(atlas670));
  LockPixels(surfaceObject);
  ResetQuickDrawStrokeState();
  pixelBase = GetPixBaseAddr(surfaceObject);
  strideBytes = static_cast<ushort>((*surfaceObject)->stride) & 0x3fff;
  SetQuickDrawStrokeColor(0xffffff);
  g_pViewMgr->SetForeColor(0x32);
  FillRectWithQuickDrawBrushAndContextOffset(&fillRect);
  colOffset = 0;
  tileIndex = 0;
  while (tileIndex < 0x1950) {
    terrainCode = g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04;
    if (terrainCode < 0x17) {
      if (terrainCode == 0) {
        terrainCode = 0x3e;
      }
      paletteByte =
          static_cast<unsigned char>(g_pViewMgr->GetColor(static_cast<short>(terrainCode)));
      pixelBase[colOffset] = paletteByte;
      pixelBase[colOffset + 1] = paletteByte;
      pixelBase[strideBytes + colOffset] = paletteByte;
      pixelBase[strideBytes + colOffset + 1] = paletteByte;
    }
    colOffset = colOffset + 2;
    if (colOffset == 0xd8) {
      colOffset = 0;
      pixelBase = pixelBase + strideBytes * 2;
    }
    tileIndex = tileIndex + 1;
  }
  // The original keeps two distinct pointers here: a fresh surface base for both
  // 216x120 copies, and base+two rows for the interior smoothing pass. Reusing the
  // latter for the copies shifts the mini-map by two rows and reads/writes beyond the
  // 120-row surface, which shows up as stray pixels around the atlas edge.
  unsigned char* surfaceBase = GetPixBaseAddr(surfaceObject);
  unsigned char* smoothingBase = surfaceBase + strideBytes * 2;
  scratchBuffer = new unsigned char[0x6540];
  if (scratchBuffer == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  {
    int copyRow = 0;
    unsigned char* scratchCursor = scratchBuffer;
    while (copyRow < 0x78) {
      unsigned char* srcCursor = GetPixBaseAddr(surfaceObject) + copyRow * strideBytes;
      int copyCol = 0;
      while (copyCol < 0xd8) {
        *scratchCursor = srcCursor[copyCol];
        scratchCursor = scratchCursor + 1;
        copyCol = copyCol + 1;
      }
      copyRow = copyRow + 1;
    }
  }
  {
    // rowStart tracks the row origin (advances by strideBytes once per outer
    // iteration); compareRow is a fresh per-row cursor reset from it -- the original
    // (pcVar9/pcVar10 at 0x0050b640) keeps these separate so the inner loop's 214
    // single-byte steps never bleed into the row stride advance.
    unsigned char* rowStart = smoothingBase + 1;
    unsigned char* scratchRow = scratchBuffer + 0x1b1;
    int edgeRow = 0x70;
    while (edgeRow != 0) {
      int edgeCol = 0xd6;
      unsigned char* compareRow = rowStart;
      while (edgeCol != 0) {
        unsigned char centerPixel = compareRow[0];
        unsigned char neighborPixel;
        if ((compareRow[-static_cast<int>(strideBytes)] != centerPixel) &&
            ((neighborPixel = compareRow[-1], neighborPixel != centerPixel) ||
             (neighborPixel = compareRow[1], neighborPixel != centerPixel))) {
          scratchRow[0] = neighborPixel;
        }
        if ((compareRow[strideBytes] != centerPixel) &&
            ((neighborPixel = compareRow[-1], neighborPixel != centerPixel) ||
             (neighborPixel = compareRow[1], neighborPixel != centerPixel))) {
          scratchRow[0] = neighborPixel;
        }
        compareRow = compareRow + 1;
        scratchRow = scratchRow + 1;
        edgeCol = edgeCol - 1;
      }
      rowStart = rowStart + strideBytes;
      // The inner loop already advances scratchRow by 214 bytes. The retail ADD
      // ESI,2 at 0x50b866 completes the 216-byte row stride; adding three here
      // shifts every following row and scatters isolated nation-color pixels.
      scratchRow = scratchRow + 2;
      edgeRow = edgeRow - 1;
    }
  }
  {
    int copyRow = 0;
    unsigned char* scratchCursor = scratchBuffer;
    while (copyRow < 0x78) {
      unsigned char* dstCursor = GetPixBaseAddr(surfaceObject) + copyRow * strideBytes;
      int copyCol = 0;
      while (copyCol < 0xd8) {
        dstCursor[copyCol] = scratchCursor[0];
        scratchCursor = scratchCursor + 1;
        copyCol = copyCol + 1;
      }
      copyRow = copyRow + 1;
    }
  }
  delete[] scratchBuffer;
  SetQuickDrawFillColor(0);
  UnlockPixels(GetGWorldPixMap(atlas670));
  SetGWorld(savedContext, savedFlags);
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  (*GetGWorldPixMap(atlas670))->dib->FlipScanlineOrder();
  g_pGlobalMapState->strategicMapPalettePreviewReady = 1;
}

// FUNCTION: IMPERIALISM 0x0050b9e0
void TMacViewMgr::RebuildMapTileNeighborHighlightPolygonsForAllTiles() {
  int cityRecordIndex = 0;
  RgnHandle* tileSlot = tileStateSlots;
  while (cityRecordIndex < 0x180) {
    Province& cityRecord = g_pGlobalMapState->cityScoreTable[cityRecordIndex];
    if (cityRecord.ownerNationCode00 != -1) {
      if (*tileSlot != 0) {
        DisposeRgn(*tileSlot);
        *tileSlot = 0;
      }
      *tileSlot = NewRgn();
      OpenRgn();
      char neighborCount = cityRecord.linkedRegionCount;
      int neighborIndex = 0;
      if (neighborCount > 0) {
        StrategicTileIndex* neighborCursor = cityRecord.linkedTileIndices42;
        while (neighborIndex < neighborCount) {
          InvokeBuildHexNeighborHighlightPolygonForTile(neighborCursor[0], cityRecordIndex);
          neighborIndex = neighborIndex + 1;
          neighborCursor = neighborCursor + 1;
        }
      }
      CloseRgn(*tileSlot);
    }
    cityRecordIndex = cityRecordIndex + 1;
    tileSlot = tileSlot + 1;
  }
  RebuildNationClipRegionsAndDispatchMapEvent();
}

// FUNCTION: IMPERIALISM 0x0050bad0
void TMacViewMgr::RebuildNationClipRegionsAndDispatchMapEvent() {
  if (g_pSimMgr->numGreatPowers == 1) {
    g_pGameFlowState->DispatchTaggedGameStateEvent1F20(kControlTagRege, 0, 0xfffffffd);
  }
  if (tileStateSlots[0] != 0) {
    RgnHandle regionWrapper = NewRgn();
    int nationIndex = 0;
    while (nationIndex < 0x17) {
      SetEmptyRgn(regionWrapper);
      int cityRecordIndex = 0;
      RgnHandle* tileSlot = tileStateSlots;
      while (cityRecordIndex < 0x180) {
        if (g_pGlobalMapState->cityScoreTable[cityRecordIndex].ownerNationCode00 == nationIndex) {
          UnionRgn(regionWrapper, *tileSlot, regionWrapper);
        }
        cityRecordIndex = cityRecordIndex + 1;
        tileSlot = tileSlot + 1;
      }
      EnsureClipRegionWrapperAtSlotAndMergeSourceRegion(regionWrapper,
                                                        static_cast<short>(nationIndex));
      nationIndex = nationIndex + 1;
    }
    DisposeRgn(regionWrapper);
    RenderTurnEventPalettePreviewSurfaceAndProgress();
  }
}

// FUNCTION: IMPERIALISM 0x0050bbc0
void TMacViewMgr::ApplySellOrderRowToNationState(TTradeCluster* orderSource, int orderSlot,
                                                 short nationSlot) {
  if (orderSource->IsSelectionAllowed() != 0) {
    g_apNationStates[nationSlot]->SetItemPotentials(static_cast<short>(orderSlot), -1);
    return;
  }
  g_apNationStates[nationSlot]->SetItemPotentials(
      static_cast<short>(orderSlot), static_cast<short>(orderSource->GetTradeSellControlValue()));
}

// FUNCTION: IMPERIALISM 0x0050bc50
void TMacViewMgr::SyncSellTaggedChildControlWithNationState(TView* view, short orderSlot,
                                                            short nationIndex) {
  TTradeCluster* row = static_cast<TTradeCluster*>(view);
  view->DoPostCreate(0);
  row->tradeMetricSlot = orderSlot;
  if (g_pTechMgr->perTechUnlockFlag180[TTechMgr::kProductionOrderTechId] == 0 &&
      (orderSlot == 6 || orderSlot == 0xc)) {
    view->Show(0, 0);
  }
  short sellCount = g_apNationStates[nationIndex]->GetTradeOffersFor(orderSlot);
  // The clamp branch resets the nation index used by the trailing capacity check below to
  // 0 (matches the original: it reuses the same stack slot that held nationIndex).
  short effectiveNationIndex = nationIndex;
  if (sellCount > 0 && g_apNationStates[nationIndex]->merchantCapacity == 0) {
    g_apNationStates[nationIndex]->SetItemPotentials(orderSlot, 0);
    sellCount = 0;
    effectiveNationIndex = 0;
  }
  TNumberText* sellControl = static_cast<TNumberText*>(view->ResolveControlByTag(kControlTagSell));
  if (sellControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  if (sellCount < 0) {
    row->SetTradeBidControlBitmap();
    sellControl->SetControlValue(0, 0);
    sellControl->Show(0, 1);
  } else {
    row->DoControlAction();
  }
  if (sellCount > 0) {
    row->SetTradeOfferControlBitmap();
    sellControl->SetControlValue(sellCount, 0);
    sellControl->Show(1, 1);
    return;
  }
  if (g_apNationStates[effectiveNationIndex]->merchantCapacity != 0) {
    row->SetTradeOfferSecondaryBitmap();
  }
  sellControl->SetControlValue(0, 0);
  sellControl->Show(0, 1);
}

// FUNCTION: IMPERIALISM 0x0050be30
TView* TMacViewMgr::MakeBookDialog(int dialogId) {
  TView* dialog = g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(
      static_cast<TurnEventId>(dialogId), 0);
  if (dialog == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UMacViewMgr.cpp", 0x917);
  }
  dialog->Open();
  return dialog;
}

// Refreshes one ledger row of the transport screen -- or the capacity total when
// resourceSlot is -1. The caller walks every row, so this is where an unavailable good
// gets greyed out. RET 0xc proves three arguments: the port previously declared one and
// looked the nation up with `g_apNationStates[resourceSlot]`, indexing the nation table
// with a resource index, which handed every row another nation's non-zero needs and left
// the whole ledger enabled.
// FUNCTION: IMPERIALISM 0x0050bea0
void TMacViewMgr::RefreshCityProductionDetailPanelAndArrowWidgets(short resourceSlot,
                                                                  short nationIndex,
                                                                  TView* hostView) {
  TGreatPower* nation = g_apNationStates[nationIndex];
  CString scratch38;

  if (resourceSlot == -1) {
    TTransportPicture* panel = ResolveTaggedPanelOrFail(hostView, kControlTagTota);
    g_pSimMgr->GetString(0x2735, 0, &scratch38);
    SetControlHoverHelpText(scratch38, panel);

    TMyStaticText* textEntry = new TMyStaticText();

    int textOffset[2] = {0xa2, 0x14};
    int textSize[2] = {0x3c, 0xb};
    textEntry->IStaticText(panel, textOffset, textSize, 5, 5, -1, 0);

    TextStyle styleDescriptor;
    BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xa, 0x2b67);
    textEntry->InstallTextStyle(styleDescriptor, 0);
    textEntry->SetTextAlignmentAndMaybeRefresh(0, 0);
    textEntry->controlTag = kControlTagText;

    g_pSimMgr->GetString(0x2735, 1, &scratch38);
    SetControlHoverHelpText(scratch38, textEntry);

    short needCap = nation != 0 ? nation->transportCapacity : 0;
    panel->splitValue94 = nation != 0 ? nation->reservedTransportCapacity : 0;
    panel->splitValue96 = needCap;
    panel->splitLimit98 = static_cast<short>(-1);
    return;
  }

  if (resourceSlot == 1 || resourceSlot == 7 || resourceSlot == 10 || resourceSlot == 0x10 ||
      resourceSlot == 0x14) {
    return;
  }

  TCity* city = nation != 0 ? nation->city : 0;
  CString formatCurrent;
  CString formatTarget;
  CString formatProduction;
  CString formatField;
  CString bracketScratch;
  CString displayText;
  CString itemName;
  CString hoverTemplate;

  int summaryTag = g_pTradeSummarySelectionMap[resourceSlot];
  TTransportPicture* panel =
      ResolveTaggedPanelOrFail(hostView, static_cast<unsigned int>(summaryTag));

  short needTarget = 0;
  short needCurrent = 0;
  short showArrowWidgets = 0;
  short deficitCount = 0;
  short formatFieldValue = 0;
  bool useBracketOnlyPath = false;
  bool useProductionTailPath = false;

  switch (resourceSlot) {
  case 0:
    needTarget = static_cast<short>(nation->needTargetByType[0] + nation->needTargetByType[1]);
    needCurrent = static_cast<short>(nation->needCurrentByType[0] + nation->needCurrentByType[1]);
    g_pSimMgr->GetString(0x2735, 2, &itemName);
    {
      int production = city->GetBuildingType(0);
      deficitCount =
          static_cast<short>(production * 2 - city->cityStockCottonB6 - city->cityStockWoolB8);
      formatCurrent.Format(g_szDecimalFormat, static_cast<int>(city->cityStockCottonB6) +
                                                  static_cast<int>(city->cityStockWoolB8));
      formatProduction.Format(g_szDecimalFormat, production * 2);
      g_pSimMgr->GetString(0x2719, 0, &displayText);
    }
    break;
  case 2:
    needTarget = nation->needTargetByType[2];
    needCurrent = nation->needCurrentByType[2];
    g_pSimMgr->GetStringPrelude(resourceSlot, &itemName);
    {
      int production = city->GetBuildingType(4);
      deficitCount = static_cast<short>(production * 2 - city->cityStockTimberBA);
      formatCurrent.Format(g_szDecimalFormat, static_cast<int>(city->cityStockTimberBA));
      formatTarget.Format(g_szDecimalFormat, production * 2);
      g_pSimMgr->GetString(0x2719, 4, &displayText);
      formatFieldValue = city->cityStockTimberBA;
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 3:
  case 4:
    needTarget = nation->needTargetByType[resourceSlot];
    needCurrent = nation->needCurrentByType[resourceSlot];
    g_pSimMgr->GetStringPrelude(resourceSlot, &itemName);
    {
      int production = city->GetBuildingType(2);
      deficitCount = static_cast<short>(production - (&city->cityStockCottonB6)[resourceSlot]);
      formatCurrent.Format(g_szDecimalFormat,
                           static_cast<int>((&city->cityStockCottonB6)[resourceSlot]));
      formatTarget.Format(g_szDecimalFormat, production);
      g_pSimMgr->GetString(0x2719, 2, &displayText);
      formatFieldValue = (&city->cityStockCottonB6)[resourceSlot];
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 5:
    needTarget = nation->needTargetByType[5];
    needCurrent = nation->needCurrentByType[5];
    g_pSimMgr->GetStringPrelude(resourceSlot, &itemName);
    formatCurrent.Format(g_szDecimalFormat, static_cast<int>(needCurrent));
    formatTarget.Format(g_szDecimalFormat, static_cast<int>(needTarget));
    g_pSimMgr->GetString(0x2719, 1, &displayText);
    useBracketOnlyPath = true;
    break;
  case 6:
    needTarget = nation->needTargetByType[6];
    needCurrent = nation->needCurrentByType[6];
    g_pSimMgr->GetStringPrelude(resourceSlot, &itemName);
    {
      int production = city->GetBuildingType(6);
      deficitCount = static_cast<short>(production * 2 - city->cityStockOilC2);
      formatCurrent.Format(g_szDecimalFormat, static_cast<int>(city->cityStockOilC2));
      formatTarget.Format(g_szDecimalFormat, production * 2);
      g_pSimMgr->GetString(0x2719, 6, &displayText);
      formatFieldValue = city->cityStockOilC2;
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 8:
    needTarget = nation->needTargetByType[8];
    needCurrent = nation->needCurrentByType[8];
    g_pSimMgr->GetStringPrelude(resourceSlot, &itemName);
    {
      int production = city->GetBuildingType(1);
      deficitCount = static_cast<short>(production * 2 - city->cityStockFabricC6);
      formatCurrent.Format(g_szDecimalFormat, static_cast<int>(city->cityStockFabricC6));
      formatTarget.Format(g_szDecimalFormat, production * 2);
      g_pSimMgr->GetString(0x2719, 1, &displayText);
      formatFieldValue = city->cityStockFabricC6;
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 9:
    needTarget = nation->needTargetByType[9];
    needCurrent = nation->needCurrentByType[9];
    g_pSimMgr->GetStringPrelude(resourceSlot, &itemName);
    {
      int production = city->GetBuildingType(5);
      deficitCount = static_cast<short>(production * 2 - city->cityStockLumberC8);
      formatCurrent.Format(g_szDecimalFormat, static_cast<int>(city->cityStockLumberC8));
      formatTarget.Format(g_szDecimalFormat, production * 2);
      g_pSimMgr->GetString(0x2719, 5, &displayText);
      formatFieldValue = city->cityStockLumberC8;
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 0xb:
    needTarget = nation->needTargetByType[0xb];
    needCurrent = nation->needCurrentByType[0xb];
    g_pSimMgr->GetStringPrelude(resourceSlot, &itemName);
    {
      int production = city->GetBuildingType(3);
      deficitCount = static_cast<short>(production * 2 - city->cityStockSteelCC);
      formatCurrent.Format(g_szDecimalFormat, static_cast<int>(city->cityStockSteelCC));
      formatTarget.Format(g_szDecimalFormat, production * 2);
      g_pSimMgr->GetString(0x2719, 3, &displayText);
      formatFieldValue = city->cityStockSteelCC;
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 0xc:
    needTarget = nation->needTargetByType[0xc];
    needCurrent = nation->needCurrentByType[0xc];
    g_pSimMgr->GetStringPrelude(resourceSlot, &itemName);
    {
      int production = city->GetBuildingType(0xb);
      deficitCount = static_cast<short>(production * 2 - city->cityStockFuelCE);
      formatCurrent.Format(g_szDecimalFormat, static_cast<int>(city->cityStockFuelCE));
      formatTarget.Format(g_szDecimalFormat, production * 2);
      g_pSimMgr->GetString(0x2719, 0xb, &displayText);
      formatFieldValue = city->cityStockFuelCE;
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 0xd:
  case 0xe:
  case 0xf:
    needTarget = nation->needTargetByType[resourceSlot];
    needCurrent = nation->needCurrentByType[resourceSlot];
    g_pSimMgr->GetStringPrelude(resourceSlot, &itemName);
    formatCurrent.Format(g_szDecimalFormat, static_cast<int>(needCurrent));
    formatTarget.Format(g_szDecimalFormat, static_cast<int>(needTarget));
    g_pSimMgr->GetString(0x2719, 8, &displayText);
    useBracketOnlyPath = true;
    break;
  case 0x11:
  case 0x12:
    needTarget = nation->needTargetByType[resourceSlot];
    needCurrent = nation->needCurrentByType[resourceSlot];
    g_pSimMgr->GetStringPrelude(resourceSlot, &itemName);
    {
      short* summary = city->GetCitySummaryRecordSlot74();
      short summaryValue = summary[resourceSlot];
      formatTarget.Format(g_szDecimalFormat, static_cast<int>(summaryValue));
      deficitCount = static_cast<short>(summaryValue - (&city->cityStockCottonB6)[resourceSlot]);
      formatCurrent.Format(g_szDecimalFormat,
                           static_cast<int>((&city->cityStockCottonB6)[resourceSlot]));
      g_pSimMgr->GetString(0x2735, 7, &displayText);
      showArrowWidgets = 1;
    }
    break;
  case 0x13:
    needTarget =
        static_cast<short>(nation->needTargetByType[0x13] + nation->needTargetByType[0x14]);
    needCurrent =
        static_cast<short>(nation->needCurrentByType[0x13] + nation->needCurrentByType[0x14]);
    g_pSimMgr->GetString(0x2735, 3, &itemName);
    {
      short* summary = city->GetCitySummaryRecordSlot74();
      short summaryValue = summary[0x14];
      formatTarget.Format(g_szDecimalFormat, static_cast<int>(summaryValue));
      deficitCount =
          static_cast<short>(summaryValue - city->cityStockFishDC - city->cityStockLivestockDE);
      formatFieldValue = static_cast<short>(city->cityStockFishDC + city->cityStockLivestockDE);
      formatCurrent.Format(g_szDecimalFormat, static_cast<int>(formatFieldValue));
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 0x15:
    needTarget = nation->needTargetByType[0x15];
    needCurrent = nation->needCurrentByType[0x15];
    g_pSimMgr->GetStringPrelude(resourceSlot, &itemName);
    g_pSimMgr->NumToCurrency(500, &formatCurrent);
    useBracketOnlyPath = true;
    break;
  case 0x16:
    needTarget = nation->needTargetByType[0x16];
    needCurrent = nation->needCurrentByType[0x16];
    g_pSimMgr->GetStringPrelude(resourceSlot, &itemName);
    g_pSimMgr->NumToCurrency(200, &formatCurrent);
    useBracketOnlyPath = true;
    break;
  default:
    needTarget = static_cast<short>(resourceSlot);
    needCurrent = static_cast<short>(resourceSlot);
    showArrowWidgets = static_cast<short>(resourceSlot);
    deficitCount = static_cast<short>(resourceSlot);
    break;
  }

  short hoverTemplateIndex = 7;
  if (resourceSlot == 5 || (resourceSlot >= 0xd && resourceSlot <= 0xf)) {
    hoverTemplateIndex = 8;
  } else if (resourceSlot == 0x13) {
    hoverTemplateIndex = 10;
  } else if (resourceSlot == 0x15 || resourceSlot == 0x16) {
    hoverTemplateIndex = 9;
  }
  if (resourceSlot == 0) {
    formatTarget = formatProduction;
  } else if (useProductionTailPath) {
    formatField.Format(g_szDecimalFormat, static_cast<int>(formatFieldValue));
    formatCurrent = formatField;
  }
  g_pSimMgr->GetString(0x2735, hoverTemplateIndex, &hoverTemplate);
  ScanBracketExpressionsInto(&bracketScratch, hoverTemplate, itemName, formatCurrent, formatTarget);
  displayText = bracketScratch;
  if (useBracketOnlyPath) {
    showArrowWidgets = 0;
  }

  if (showArrowWidgets == 0) {
    panel->splitLimit98 = static_cast<short>(-1);
  } else if (deficitCount < 1) {
    panel->splitLimit98 = 0;
  } else {
    panel->splitLimit98 = deficitCount;
  }

  SetControlHoverHelpText(displayText, panel);

  // A row with nothing available is greyed out and loses its stepper arrows entirely:
  // the original calls slot 7 (`CALL [edx+0x1c]` at 0x0050cae2 / 0x0050cb1c), which is
  // TView::Free -- destroying the placeholder control -- not slot 0x1c
  // BecameWindowTarget at vtable offset 0x70. Confusing the slot index with the byte
  // offset left every placeholder arrow sprite alive on screen.
  if (needCurrent == 0) {
    panel->Show(0, 0);
    TControl* leftArrow = ResolveTaggedChildOrFail(panel, kControlTagLeft);
    leftArrow->Free();
    TControl* rightArrow = ResolveTaggedChildOrFail(panel, kControlTagRght);
    rightArrow->Free();
    return;
  }

  // Same slot-7 Free: the placeholder 'left'/'rght' controls are destroyed after their
  // layout is copied, and a live TRightLeftView is built in each one's place.
  TControl* leftSource = ResolveTaggedChildOrFail(panel, kControlTagLeft);
  int leftLayout0[2];
  int leftLayout1[2];
  CopyViewLayoutFieldsToStack(leftLayout0, leftLayout1, leftSource);
  leftSource->Free();

  TRightLeftView* leftView = new TRightLeftView();
  leftView->InitializeUiResourceEntryFrameAndParent(0, panel, leftLayout1, leftLayout0, 5, 5, 0);
  leftView->controlTag = kControlTagLeft;

  TControl* rightSource = ResolveTaggedChildOrFail(panel, kControlTagRght);
  int rightLayout0[2];
  int rightLayout1[2];
  CopyViewLayoutFieldsToStack(rightLayout0, rightLayout1, rightSource);
  rightSource->Free();

  TRightLeftView* rightView = new TRightLeftView();
  rightView->InitializeUiResourceEntryFrameAndParent(0, panel, rightLayout1, rightLayout0, 5, 5, 0);
  rightView->controlTag = kControlTagRght;

  TMyStaticText* textEntry = new TMyStaticText();

  int textOffset[2] = {0x98, 0x12};
  int textSize[2] = {0x46, 0xb};
  textEntry->IStaticText(panel, textOffset, textSize, 5, 5, -1, 0);

  TextStyle styleDescriptor;
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xa, 0x2b67);
  textEntry->InstallTextStyle(styleDescriptor, 0);
  textEntry->SetTextAlignmentAndMaybeRefresh(0, 0);
  textEntry->controlTag = kControlTagText;

  g_pSimMgr->GetString(0x2735, 4, &scratch38);
  SetControlHoverHelpText(scratch38, textEntry);

  if (resourceSlot == 0x15 || resourceSlot == 0x16) {
    TMyStaticText* valueEntry = new TMyStaticText();

    int valueOffset[2] = {0x32, 0x14};
    int valueSize[2] = {0x3c, 0xb};
    valueEntry->IStaticText(panel, valueOffset, valueSize, 5, 5, -1, 0);
    valueEntry->InstallTextStyle(styleDescriptor, 0);
    valueEntry->SetTextAlignmentAndMaybeRefresh(0, 0);
    valueEntry->controlTag = kControlTagValu;
  }

  panel->resourceMetricSlot92 = static_cast<short>(resourceSlot);
  panel->splitValue94 = needTarget;
  panel->splitValue96 = needCurrent;
}

// FUNCTION: IMPERIALISM 0x0050d310
void TMacViewMgr::DispatchTurnEvent3B8AndWaitForCompletionFlag(int unusedArg1, int unusedArg2) {
  TView* dialog = activeCityProductionView04;
  g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventCitySiteSelector), 0);
  short completionFlag = static_cast<short>(dialog->lastIdleTick);
  while (completionFlag == 0) {
    PumpUiMessagesAndBackgroundTasks(1);
    completionFlag = static_cast<short>(dialog->lastIdleTick);
  }
}

// FUNCTION: IMPERIALISM 0x0050d360
TBuildingView* TMacViewMgr::OpenBuildingWindow(short buildingSlot, TCity* city,
                                               unsigned char closeAfterOpen,
                                               unsigned char isEmbeddedPage,
                                               TCityProductionView* productionView) {
  TWindow* dialog = g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(
      static_cast<TurnEventId>(buildingSlot + kTurnEventTextileMill));
  TBuildingView* buildingView =
      static_cast<TBuildingView*>(dialog->ResolveControlByTag(kControlTagDialog));
  if (buildingView == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUMacViewMgr_00696D68, 0xb4f);
  }
  buildingView->ApplyCityViewSelectionPayloadAndRefreshControls(city, isEmbeddedPage != 0,
                                                                productionView, buildingSlot);
  dialog->controlValue3c = 0x65;
  if (closeAfterOpen != 0) {
    dialog->SetModality(1);
    dialog->PoseModally();
    dialog->Close();
    dialog->Free();
    return 0;
  }
  dialog->Open();
  return buildingView;
}

// FUNCTION: IMPERIALISM 0x0050d470
TBuildingView* TMacViewMgr::RestoreBuildingWindowAtSavedPosition(
    short buildingSlot, TCity* city, unsigned char closeAfterOpen, unsigned char isEmbeddedPage,
    TCityProductionView* productionView, short savedX, short savedY) {
  TWindow* dialog = g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(
      static_cast<TurnEventId>(buildingSlot + kTurnEventTextileMill));
  TBuildingView* buildingView =
      static_cast<TBuildingView*>(dialog->ResolveControlByTag(kControlTagDialog));
  if (buildingView == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUMacViewMgr_00696D68, 0xb62);
  }
  buildingView->ApplyCityViewSelectionPayloadAndRefreshControls(city, isEmbeddedPage != 0,
                                                                productionView, buildingSlot);
  dialog->controlValue3c = 0x65;
  CPoint placement(savedX, savedY);
  dialog->Locate(placement, 0);
  if (closeAfterOpen != 0) {
    dialog->SetModality(1);
    dialog->PoseModally();
    dialog->Close();
    dialog->Free();
    return 0;
  }
  dialog->Open();
  return buildingView;
}

// FUNCTION: IMPERIALISM 0x0050d5b0
void TMacViewMgr::OpenConstructionWindow(short buildingSlot, TCity* city,
                                         TCityProductionView* productionView) {
  TWindow* dialog =
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventGenericCreator);
  TBuildingConstructionView* constructionView =
      static_cast<TBuildingConstructionView*>(dialog->ResolveControlByTag(kControlTagDialog));
  if (constructionView == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUMacViewMgr_00696D68, 0xb98);
  }
  constructionView->StuffValues(buildingSlot, city, productionView);
  dialog->SetModality(1);
  unsigned long dialogAction = dialog->PoseModally();
  dialog->Close();
  constructionView->DoClosingAction(dialogAction);
  dialog->Free();
}

// FUNCTION: IMPERIALISM 0x0050d680
void TMacViewMgr::EnsureClipRegionWrapperAtSlotAndMergeSourceRegion(RgnHandle sourceRegion,
                                                                    short slotIndex) {
  if (regionSlots[slotIndex] == 0) {
    regionSlots[slotIndex] = NewRgn();
  }
  CopyRgn(sourceRegion, regionSlots[slotIndex]);
}

// FUNCTION: IMPERIALISM 0x0050d6c0
unsigned char TMacViewMgr::IsPointInsideClipRegionSlot(CPoint* point, short regionIndex) {
  if (regionSlots[regionIndex] != 0) {
    return QueryPointInsideHitRegion(point, regionSlots[regionIndex]);
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x0050d700
void TMacViewMgr::RenderOffscreenBitmapTileSpanAndRestoreContext(int param_1) {
  TQuickDrawSurfaceContext* savedContext;
  int savedFlags;
  RECT resourceBounds;
  // The original reuses the incoming argument's stack slot as the out-context of
  // MakeNewGWorld; the previous port misread that slot as
  // resourceBounds.right and passed the rect width around as a "context".
  TQuickDrawSurfaceContext* tileSurface = 0;
  regionSlots[param_1] = NewRgn();
  GetGWorld(&savedContext, &savedFlags);
  TBitmapResourceLoader** loaderHandle = CreateBitmapResourceLoaderHandle(param_1 + 4000);
  CopyRect(&resourceBounds, &(*loaderHandle)->bitmapRect);
  g_pDisplayMgr->MakeNewGWorld(tileSurface, 1, resourceBounds);
  SetGWorld(tileSurface, savedFlags);
  LockPixels(GetGWorldPixMap(tileSurface));
  QDLoadResource(loaderHandle);
  TBitmapResourceLoader* loader = *loaderHandle;
  if (loader != 0) {
    loader->EnsureBitmapResourceLoadedAndCopyRectSize();
    loader->flags |= 1;
    ResetQuickDrawStrokeState();
    BlitBitmapResourceLoaderToActiveDc(loaderHandle, &resourceBounds);
  }
  ReleaseBitmapLoaderHandle(loaderHandle);
  TBitmapSurfaceNode** surfaceHandle =
      static_cast<TBitmapSurfaceNode**>(GetGWorldPixMap(tileSurface));
  // The region rebuild consumes the node itself (it reads node->dib at +0x1c).
  if (BitMapToRegion(regionSlots[param_1], *surfaceHandle) != 0) {
    BitMapToRegion(regionSlots[param_1], *surfaceHandle);
    BitMapToRegion(regionSlots[param_1], *surfaceHandle);
  }
  g_pDisplayMgr->RemoveGWorld(tileSurface);
  // Faithful to the original: the slot is already zeroed here, so this reads
  // *(0 + 0x24) — benign on the Win9x null page the game shipped against.
  UnlockPixels(GetGWorldPixMap(tileSurface));
  SetGWorld(savedContext, savedFlags);
}

// FUNCTION: IMPERIALISM 0x0050d8d0
void TMacViewMgr::RefreshActiveCityBuildingActionAvailabilityIndicators() {
  if (activeCityProductionView04 != 0) {
    activeCityProductionView04->UpdateToolbar();
  }
}

// FUNCTION: IMPERIALISM 0x0050d8f0
void TMacViewMgr::ClearActiveCityBuildingViewSlot(short buildingSlot) {
  if (activeCityProductionView04 != 0) {
    activeCityProductionView04->buildingViewsAC[buildingSlot] = 0;
  }
}

// FUNCTION: IMPERIALISM 0x0050d920
void TMacViewMgr::ClearActiveCityProductionViewAndDiscardRegion() {
  if (activeCityProductionView04 != 0) {
    activeCityProductionView04->CloseAndSaveWindows();
  }
  activeCityProductionView04 = 0;
}

// FUNCTION: IMPERIALISM 0x0050d950
void TMacViewMgr::RefreshActiveGoldControlAndUiRuntimeState() {
  TView* hostView = g_pDisplayMgr->activeDialog;
  TPicture* goldControl = static_cast<TPicture*>(hostView->ResolveControlByTag(kControlTagDialog));
  if (goldControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  goldControl->ResetPictureResourceEntry();
  goldControl->SetPictureResourceIdAndRefresh(0, 0);
  g_pUiAnimator->FreeUiTransientRegistryPayloads();
}

// FUNCTION: IMPERIALISM 0x0050d9e0
void TMacViewMgr::CopySpriteSurfaceToStrideBuffer(TBitmapResourceLoader** loaderHandle,
                                                  unsigned char* destinationBits,
                                                  short destinationStride) {
  CDib* dib = (*loaderHandle)->bitmapResource;
  unsigned char* sourceRow = static_cast<unsigned char*>(dib->m_dibBits);
  unsigned int rowWidth = dib->m_pInfoHeader->bmiHeader.biWidth;
  short sourceStride = static_cast<short>((rowWidth + 3) & ~3);
  int rowCount = dib->m_pInfoHeader->bmiHeader.biHeight;
  if (rowCount < 1) {
    rowCount = -rowCount;
  }
  while (rowCount != 0) {
    memcpy(destinationBits, sourceRow, rowWidth);
    destinationBits += destinationStride;
    sourceRow += sourceStride;
    --rowCount;
  }
}

// FUNCTION: IMPERIALISM 0x0050da80
void TMacViewMgr::BlitMapOverlayGlyphStrip32x24SkipMask10(TBitmapSurfaceNode** dstSurface,
                                                          short param_2, short param_3,
                                                          short param_4) {
  TBitmapSurfaceNode** atlasSurface;
  short srcRowOffset;
  if (param_2 < 100) {
    atlasSurface = static_cast<TBitmapSurfaceNode**>(GetGWorldPixMap(atlas674));
    srcRowOffset = static_cast<short>(param_2 << 5);
  } else {
    atlasSurface = static_cast<TBitmapSurfaceNode**>(GetGWorldPixMap(atlas680));
    srcRowOffset = static_cast<short>((param_2 - 100) * 0x20);
  }
  ushort dstStrideRaw = static_cast<ushort>((*dstSurface)->stride);
  LockPixels(atlasSurface);
  unsigned char* srcPixels = GetPixBaseAddr(atlasSurface);
  ushort srcStrideRaw = static_cast<ushort>((*atlasSurface)->stride);
  unsigned char* dstPixels = GetPixBaseAddr(dstSurface);
  int dstStrideBytes = static_cast<short>(dstStrideRaw & 0x3fff);
  unsigned char* srcRow = srcPixels + srcRowOffset;
  unsigned char* dstRow = dstPixels + param_4 * dstStrideBytes + param_3;
  int rowsRemaining = 0x18;
  do {
    if (srcRow[0] != '\x10')
      dstRow[0] = srcRow[0];
    if (srcRow[1] != '\x10')
      dstRow[1] = srcRow[1];
    if (srcRow[2] != '\x10')
      dstRow[2] = srcRow[2];
    if (srcRow[3] != '\x10')
      dstRow[3] = srcRow[3];
    if (srcRow[4] != '\x10')
      dstRow[4] = srcRow[4];
    if (srcRow[5] != '\x10')
      dstRow[5] = srcRow[5];
    if (srcRow[6] != '\x10')
      dstRow[6] = srcRow[6];
    if (srcRow[7] != '\x10')
      dstRow[7] = srcRow[7];
    if (srcRow[8] != '\x10')
      dstRow[8] = srcRow[8];
    if (srcRow[9] != '\x10')
      dstRow[9] = srcRow[9];
    if (srcRow[10] != '\x10')
      dstRow[10] = srcRow[10];
    if (srcRow[0x0b] != '\x10')
      dstRow[0x0b] = srcRow[0x0b];
    if (srcRow[0x0c] != '\x10')
      dstRow[0x0c] = srcRow[0x0c];
    if (srcRow[0x0d] != '\x10')
      dstRow[0x0d] = srcRow[0x0d];
    if (srcRow[0x0e] != '\x10')
      dstRow[0x0e] = srcRow[0x0e];
    if (srcRow[0x0f] != '\x10')
      dstRow[0x0f] = srcRow[0x0f];
    if (srcRow[0x10] != '\x10')
      dstRow[0x10] = srcRow[0x10];
    if (srcRow[0x11] != '\x10')
      dstRow[0x11] = srcRow[0x11];
    if (srcRow[0x12] != '\x10')
      dstRow[0x12] = srcRow[0x12];
    if (srcRow[0x13] != '\x10')
      dstRow[0x13] = srcRow[0x13];
    if (srcRow[0x14] != '\x10')
      dstRow[0x14] = srcRow[0x14];
    if (srcRow[0x15] != '\x10')
      dstRow[0x15] = srcRow[0x15];
    if (srcRow[0x16] != '\x10')
      dstRow[0x16] = srcRow[0x16];
    if (srcRow[0x17] != '\x10')
      dstRow[0x17] = srcRow[0x17];
    if (srcRow[0x18] != '\x10')
      dstRow[0x18] = srcRow[0x18];
    if (srcRow[0x19] != '\x10')
      dstRow[0x19] = srcRow[0x19];
    if (srcRow[0x1a] != '\x10')
      dstRow[0x1a] = srcRow[0x1a];
    if (srcRow[0x1b] != '\x10')
      dstRow[0x1b] = srcRow[0x1b];
    if (srcRow[0x1c] != '\x10')
      dstRow[0x1c] = srcRow[0x1c];
    if (srcRow[0x1d] != '\x10')
      dstRow[0x1d] = srcRow[0x1d];
    if (srcRow[0x1e] != '\x10')
      dstRow[0x1e] = srcRow[0x1e];
    if (srcRow[0x1f] != '\x10')
      dstRow[0x1f] = srcRow[0x1f];
    rowsRemaining = rowsRemaining - 1;
    dstRow = dstRow + dstStrideBytes;
    srcRow = srcRow + static_cast<short>(srcStrideRaw & 0x3fff);
  } while (rowsRemaining != 0);
  UnlockPixels(atlasSurface);
}

// FUNCTION: IMPERIALISM 0x0050dd40
void TMacViewMgr::DrawStrategicMapUnitIcon(TBitmapSurfaceNode** pDstSurface, short nIconVariant,
                                           short nDstX, short nYShift) {
  TBitmapSurfaceNode** atlasSurface =
      static_cast<TBitmapSurfaceNode**>(GetGWorldPixMap(unitIconAtlas));
  LockPixels(atlasSurface);
  unsigned char* srcPixels = GetPixBaseAddr(atlasSurface);
  ushort srcStrideRaw = static_cast<ushort>((*atlasSurface)->stride);
  unsigned char* dstPixels = GetPixBaseAddr(pDstSurface);
  int dstStrideBytes = static_cast<short>(static_cast<ushort>((*pDstSurface)->stride) & 0x3fff);
  unsigned char* srcRow = srcPixels + static_cast<short>(nIconVariant * 0x14);
  unsigned char* dstRow = dstPixels + (0x28 - nYShift) * dstStrideBytes + static_cast<int>(nDstX);
  int rowsRemaining = 0x18;
  do {
    if (srcRow[0] != '\x10')
      dstRow[0] = srcRow[0];
    if (srcRow[1] != '\x10')
      dstRow[1] = srcRow[1];
    if (srcRow[2] != '\x10')
      dstRow[2] = srcRow[2];
    if (srcRow[3] != '\x10')
      dstRow[3] = srcRow[3];
    if (srcRow[4] != '\x10')
      dstRow[4] = srcRow[4];
    if (srcRow[5] != '\x10')
      dstRow[5] = srcRow[5];
    if (srcRow[6] != '\x10')
      dstRow[6] = srcRow[6];
    if (srcRow[7] != '\x10')
      dstRow[7] = srcRow[7];
    if (srcRow[8] != '\x10')
      dstRow[8] = srcRow[8];
    if (srcRow[9] != '\x10')
      dstRow[9] = srcRow[9];
    if (srcRow[0x0a] != '\x10')
      dstRow[0x0a] = srcRow[0x0a];
    if (srcRow[0x0b] != '\x10')
      dstRow[0x0b] = srcRow[0x0b];
    if (srcRow[0x0c] != '\x10')
      dstRow[0x0c] = srcRow[0x0c];
    if (srcRow[0x0d] != '\x10')
      dstRow[0x0d] = srcRow[0x0d];
    if (srcRow[0x0e] != '\x10')
      dstRow[0x0e] = srcRow[0x0e];
    if (srcRow[0x0f] != '\x10')
      dstRow[0x0f] = srcRow[0x0f];
    if (srcRow[0x10] != '\x10')
      dstRow[0x10] = srcRow[0x10];
    if (srcRow[0x11] != '\x10')
      dstRow[0x11] = srcRow[0x11];
    if (srcRow[0x12] != '\x10')
      dstRow[0x12] = srcRow[0x12];
    if (srcRow[0x13] != '\x10')
      dstRow[0x13] = srcRow[0x13];
    rowsRemaining = rowsRemaining - 1;
    dstRow = dstRow + dstStrideBytes;
    srcRow = srcRow + static_cast<short>(srcStrideRaw & 0x3fff);
  } while (rowsRemaining != 0);
  UnlockPixels(atlasSurface);
}

// FUNCTION: IMPERIALISM 0x0050df40
void TMacViewMgr::DrawStrategicMapUnitIconOverlay(TBitmapSurfaceNode** pDstSurface,
                                                  ushort wOverlayIconId, short nVariantRow,
                                                  short nDstX, short nYShift) {
  TBitmapSurfaceNode** atlasSurface = GetGWorldPixMap(unitOverlayAtlas);
  if (nVariantRow <= 0) {
    return;
  }
  short overlaySourceOffset = g_anStrategicMapOverlaySourceRowByIconId[wOverlayIconId];
  if (overlaySourceOffset < 0) {
    return;
  }
  LockPixels(atlasSurface);
  unsigned char* srcPixels = GetPixBaseAddr(atlasSurface);
  ushort srcStrideRaw = static_cast<ushort>((*atlasSurface)->stride);
  unsigned char* dstPixels = GetPixBaseAddr(pDstSurface);
  int dstStrideBytes = static_cast<short>(static_cast<ushort>((*pDstSurface)->stride) & 0x3fff);
  unsigned char* srcRow =
      srcPixels + static_cast<short>(overlaySourceOffset - 0x26 + nVariantRow * 0x26);
  unsigned char* dstRow = dstPixels + (0x26 - nYShift) * dstStrideBytes + static_cast<int>(nDstX);
  int rowsRemaining = 0x1a;
  do {
    int colsRemaining = 0x26;
    unsigned char* dstPixel = dstRow;
    unsigned char* srcPixel = srcRow;
    do {
      if (*srcPixel != '\x10') {
        *dstPixel = *srcPixel;
      }
      ++srcPixel;
      ++dstPixel;
      colsRemaining = colsRemaining - 1;
    } while (colsRemaining != 0);
    rowsRemaining = rowsRemaining - 1;
    dstRow = dstRow + dstStrideBytes;
    srcRow = srcRow + static_cast<short>(srcStrideRaw & 0x3fff);
  } while (rowsRemaining != 0);
  UnlockPixels(atlasSurface);
}

// FUNCTION: IMPERIALISM 0x0050e070
void TMacViewMgr::BlitStrategicMapUnitActivityOverlayFrame(TBitmapSurfaceNode** destinationSurface,
                                                           short overlayFrameIndex,
                                                           short destinationX,
                                                           short destinationYFromBottom) {
  TBitmapSurfaceNode** atlasSurface = GetGWorldPixMap(unitOverlayAtlas);
  unsigned short destinationStride =
      static_cast<unsigned short>((*destinationSurface)->stride) & 0x3fff;
  LockPixels(atlasSurface);
  unsigned char* sourcePixels = GetPixBaseAddr(atlasSurface);
  unsigned short sourceStride = static_cast<unsigned short>((*atlasSurface)->stride) & 0x3fff;
  unsigned char* destinationPixels = GetPixBaseAddr(destinationSurface);

  unsigned char* sourceRow = sourcePixels + static_cast<short>((overlayFrameIndex + 0x1b) * 0x26);
  unsigned char* destinationRow =
      destinationPixels + (0x26 - destinationYFromBottom) * destinationStride + destinationX;
  int rowsRemaining = 0x1a;
  do {
    int columnsRemaining = 0x26;
    do {
      if (*sourceRow != 0x10) {
        *destinationRow = *sourceRow;
      }
      ++sourceRow;
      ++destinationRow;
      --columnsRemaining;
    } while (columnsRemaining != 0);
    destinationRow += destinationStride - 0x26;
    sourceRow += sourceStride - 0x26;
    --rowsRemaining;
  } while (rowsRemaining != 0);
  UnlockPixels(atlasSurface);
}

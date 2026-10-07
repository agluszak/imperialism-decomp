#include "game/nation_domain_types.h"
#include "game/resource_domain_types.h"
#include "game/map_domain_types.h"
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
#include "game/gfx/TResourceMgr.h"
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

// ABI: __cdecl(void*, int) heap reallocator; returns the new block or 0.

namespace {

static TTransportPicture* ResolveTaggedPanelOrFail(TView* hostView, unsigned int tag, int line) {
  TTransportPicture* panel = static_cast<TTransportPicture*>(hostView->FindSubView(tag));
  if (panel == 0) {
    FailNilPointerWithAssert(s_SourcePathUMacViewMgr, line);
  }
  return panel;
}

static TControl* ResolveTaggedChildOrFail(TControl* panel, unsigned int tag, int line) {
  TControl* child = static_cast<TControl*>(panel->FindSubView(tag));
  if (child == 0) {
    FailNilPointerWithAssert(s_SourcePathUMacViewMgr, line);
  }
  return child;
}

static void CopyViewLayoutFieldsToStack(int* layout0, int* layout1, TControl* srcControl) {
  TView* srcView = srcControl;
  layout0[0] = srcView->ownerLocalX;
  layout0[1] = srcView->ownerLocalY;
  layout1[0] = srcView->frameWidth;
  layout1[1] = srcView->frameHeight;
}

static void ScanBracketExpressionsInto(CString* dest, const CString& templateText,
                                       const CString& token1, const CString& token2,
                                       const CString& token3) {
  scanBracketExpressions(g_pSimMgr, dest, static_cast<LPCSTR>(templateText),
                         static_cast<LPCSTR>(token1), static_cast<LPCSTR>(token2),
                         static_cast<LPCSTR>(token3));
}

// The loader's original vtable has no destructor slot; every caller owns this exact type.
IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
static void ReleaseBitmapLoaderHandle(TBitmapResourceLoader** loaderHandle) {
  if (loaderHandle == NULL) {
    return;
  }
  delete *loaderHandle;
  delete loaderHandle;
}
IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE

static void ResolveAndBlitBitmapResourceToActiveAtlas(int resourceId, RECT* dstRect) {
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

IMPLEMENT_DYNCREATE(TMacViewMgr, TObject)

// FUNCTION: IMPERIALISM 0x00509ca0
TMacViewMgr::TMacViewMgr() : TObject() {
  activeCityProductionView = 0;
  int index = 0;
  while (index < 0x17) {
    countryRegions[index] = 0;
    ++index;
  }
  index = 0;
  while (index < kProvinceCount) {
    tileStateSlots[index] = 0;
    ++index;
  }
  fieldD7c = 0;
  fieldD80 = 0;
  terrainTileWorld = 0;
  commodityIconWorld = 0;
  unitIconAtlas = 0;
  unitOverlayAtlas = 0;
  miniMapWorld = 0;
  improvementTileWorld = 0;
  flagWorld = 0;
  markerWorld = 0;
  stackBadgeWorld = 0;
  mapArtWorld = 0;
  gaugeWorld = 0;
  nationFleetWorld = 0;
  nationUnitWorld = 0;
  index = 0;
  while (index < 8) {
    tileOverlayStripWorlds[index] = 0;
    ++index;
  }
}

// FUNCTION: IMPERIALISM 0x00509e10
RgnHandle TMacViewMgr::GetCountryRegion(short index) {
  return countryRegions[index];
}

// FUNCTION: IMPERIALISM 0x00509e60
TMacViewMgr::~TMacViewMgr() {}

// FUNCTION: IMPERIALISM 0x00509f20
void TMacViewMgr::IMacViewMgr() {
  g_pAssetMgr->OpenFilesFor(3);
  CreateCommodityIconsGWorld();
  LoadStrategicMapUnitIconAtlas750();
  LoadStrategicMapUnitOverlayAtlas751();
  CreateMiniFlagsGWorld();
  BuildStrategicMapGaugeAtlasFrom1422And1423();
  RefreshCityCapabilityUiHandlesForActiveNation();
  CreateIndexedGWorlds();
}

// FUNCTION: IMPERIALISM 0x00509f70
void TMacViewMgr::Free() {
  int index = 0;
  while (index < 0x17) {
    if (countryRegions[index] != 0) {
      DisposeRgn(countryRegions[index]);
      countryRegions[index] = 0;
    }
    ++index;
  }
  index = 0;
  while (index < kProvinceCount) {
    if (tileStateSlots[index] != 0) {
      DisposeRgn(tileStateSlots[index]);
      tileStateSlots[index] = 0;
    }
    ++index;
  }
  g_pDisplayMgr->RemoveGWorld(unitIconAtlas);
  g_pDisplayMgr->RemoveGWorld(unitOverlayAtlas);
  g_pDisplayMgr->RemoveGWorld(commodityIconWorld);
  g_pDisplayMgr->RemoveGWorld(terrainTileWorld);
  g_pDisplayMgr->RemoveGWorld(improvementTileWorld);
  g_pDisplayMgr->RemoveGWorld(miniMapWorld);
  g_pDisplayMgr->RemoveGWorld(flagWorld);
  g_pDisplayMgr->RemoveGWorld(gaugeWorld);
  g_pDisplayMgr->RemoveGWorld(nationFleetWorld);
  g_pDisplayMgr->RemoveGWorld(nationUnitWorld);
  g_pDisplayMgr->RemoveGWorld(markerWorld);
  g_pDisplayMgr->RemoveGWorld(stackBadgeWorld);
  g_pDisplayMgr->RemoveGWorld(mapArtWorld);
  index = 0;
  while (index < 8) {
    g_pDisplayMgr->RemoveGWorld(tileOverlayStripWorlds[index]);
    ++index;
  }
  g_pMacViewMgr = 0;
  delete this;
}

// FUNCTION: IMPERIALISM 0x0050a140
void TMacViewMgr::ReadFrom(TStream* stream) {
  activeCityProductionView = 0;
  TObject::ReadFrom(stream);
  GenerateRegions();
  GenerateMiniMap();
  RefreshCityCapabilityUiHandlesForActiveNation();
}

// FUNCTION: IMPERIALISM 0x0050a180
void TMacViewMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
}

// FUNCTION: IMPERIALISM 0x0050a1a0
void TMacViewMgr::CreateCommodityIconsGWorld() {
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
  g_pDisplayMgr->MakeNewGWorld(commodityIconWorld, 8, atlasBounds);
  GetGWorld(&savedContext, &savedFlags);
  SetGWorld(commodityIconWorld, savedFlags);
  atlasSurface = GetGWorldPixMap(commodityIconWorld);
  LockPixels(atlasSurface);
  ResetQuickDrawStrokeState();
  pixelBuffer = GetPixBaseAddr(atlasSurface);
  pixelCount = (atlasBounds.right - atlasBounds.left) * (atlasBounds.bottom - atlasBounds.top);
  memset(pixelBuffer, 0, pixelCount);
  stridePixels = static_cast<short>(static_cast<ushort>((*atlasSurface)->stride) & 0x3fff);
  dstCursor = pixelBuffer - 0x20;
  commodityIndex = 0;
  while (commodityIndex < kResourceKindCount) {
    TBitmapResourceLoader** loaderHandle = CreateBitmapResourceLoaderHandle(commodityIndex + 700);
    if (loaderHandle != NULL && *loaderHandle != 0) {
      TBitmapResourceLoader* loader = *loaderHandle;
      loader->EnsureBitmapResourceLoadedAndCopyRectSize();
      loader->flags |= 1;
      dstCursor += 0x20;
      FastDrawPicture(loaderHandle, dstCursor, static_cast<short>(stridePixels));
      loader->ReleaseBitmapResource();
      loader->flags &= static_cast<unsigned char>(~1);
    }
    ReleaseBitmapLoaderHandle(loaderHandle);
    ++commodityIndex;
  }
  UnlockPixels(GetGWorldPixMap(commodityIconWorld));
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
void TMacViewMgr::CreateMiniFlagsGWorld() {
  flagWorld = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x21fb);
}

// FUNCTION: IMPERIALISM 0x0050a440
void TMacViewMgr::LoadStrategicMapMarkerAtlas1372() {
  markerWorld = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x55c);
}

IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
// FUNCTION: IMPERIALISM 0x0050a470
void TMacViewMgr::BuildStrategicMapGaugeAtlasFrom1422And1423() {
  RECT atlasBounds;
  RECT blitRect;
  TQuickDrawSurfaceContext* savedContext;
  int savedFlags;
  atlasBounds.left = 0;
  atlasBounds.top = 0;
  atlasBounds.right = 0x500;
  atlasBounds.bottom = 0x10;
  g_pDisplayMgr->MakeNewGWorld(gaugeWorld, 8, atlasBounds);
  GetGWorld(&savedContext, &savedFlags);
  SetGWorld(gaugeWorld, savedFlags);
  LockPixels(GetGWorldPixMap(gaugeWorld));
  ResetQuickDrawStrokeState();

  TBitmapResourceLoader** firstLoaderHandle = CreateBitmapResourceLoaderHandle(0x58e);
  TBitmapResourceLoader* firstLoader = *firstLoaderHandle;
  if (firstLoader != 0) {
    firstLoader->EnsureBitmapResourceLoadedAndCopyRectSize();
    firstLoader->flags |= 1;
    CopyRect(&blitRect, &firstLoader->bitmapRect);
    BlitBitmapResourceLoaderToActiveDc(firstLoaderHandle, &blitRect);
    firstLoader->ReleaseBitmapResource();
    firstLoader->flags &= static_cast<unsigned char>(~1);
  }
  delete *firstLoaderHandle;
  delete firstLoaderHandle;

  TBitmapResourceLoader** secondLoaderHandle = CreateBitmapResourceLoaderHandle(0x58f);
  TBitmapResourceLoader* secondLoader = *secondLoaderHandle;
  if (secondLoader != 0) {
    secondLoader->EnsureBitmapResourceLoadedAndCopyRectSize();
    secondLoader->flags |= 1;
    CopyRect(&blitRect, &secondLoader->bitmapRect);
    OffsetRect(&blitRect, 0x400, 0);
    BlitBitmapResourceLoaderToActiveDc(secondLoaderHandle, &blitRect);
    secondLoader->ReleaseBitmapResource();
    secondLoader->flags &= static_cast<unsigned char>(~1);
  }
  delete *secondLoaderHandle;
  delete secondLoaderHandle;

  UnlockPixels(GetGWorldPixMap(gaugeWorld));
  SetGWorld(savedContext, savedFlags);
}
IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE

// FUNCTION: IMPERIALISM 0x0050a6a0
void TMacViewMgr::RefreshCityCapabilityUiHandlesForActiveNation() {
  short nationId;
  unsigned int variant;
  if (IsTurnFlowCooldownActiveAndResetExpiredState()) {
    return;
  }
  if (this == 0 || g_pTechMgr == 0) {
    return;
  }
  if (nationFleetWorld != 0) {
    g_pDisplayMgr->RemoveGWorld(nationFleetWorld);
  }
  if (nationUnitWorld != 0) {
    g_pDisplayMgr->RemoveGWorld(nationUnitWorld);
  }
  nationId = g_pSimMgr->GetPlayerCountry();
  if (nationId < 0) {
    return;
  }
  g_pAssetMgr->OpenFilesFor(3);
  nationId = g_pSimMgr->GetPlayerCountry();
  variant = g_pTechMgr->orderCapRows277[nationId].techStatusByTechId[0x0f] != 0;
  nationId = g_pSimMgr->GetPlayerCountry();
  if (g_pTechMgr->orderCapRows277[nationId].techStatusByTechId[0x18] != 0) {
    variant = 2;
  }
  nationId = g_pSimMgr->GetPlayerCountry();
  nationFleetWorld =
      LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(nationId + 0x579 + variant * 7);
  nationId = g_pSimMgr->GetPlayerCountry();
  nationUnitWorld =
      LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(nationId + 0x564 + variant * 7);
}

IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
// FUNCTION: IMPERIALISM 0x0050a820
void TMacViewMgr::CreateIndexedGWorlds() {
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
    g_pDisplayMgr->MakeNewGWorld(tileOverlayStripWorlds[stripIndex], 8, resourceBounds);
    SetGWorld(tileOverlayStripWorlds[stripIndex], savedFlags);
    LockPixels(GetGWorldPixMap(tileOverlayStripWorlds[stripIndex]));
    QDLoadResource(loaderHandle);
    if (*loaderHandle != 0) {
      loader = *loaderHandle;
      loader->EnsureBitmapResourceLoadedAndCopyRectSize();
      loader->flags |= 1;
      ResetQuickDrawStrokeState();
      BlitBitmapResourceLoaderToActiveDc(loaderHandle, &resourceBounds);
      if (stripIndex == 0) {
        (*GetGWorldPixMap(tileOverlayStripWorlds[stripIndex]))->dib->FlipScanlineOrder();
      }
      loader = *loaderHandle;
      loader->ReleaseBitmapResource();
      loader->flags &= 0xfe;
      delete loader;
      delete loaderHandle;
    }
    UnlockPixels(GetGWorldPixMap(tileOverlayStripWorlds[stripIndex]));
    ++stripIndex;
  }
  SetGWorld(savedContext, savedFlags);
}
IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE

// FUNCTION: IMPERIALISM 0x0050a9f0
void TMacViewMgr::CreateMapArtStorage() {
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
  g_pDisplayMgr->MakeNewGWorld(terrainTileWorld, 8, atlasBounds);
  GetGWorld(&savedContext, &savedFlags);
  SetGWorld(terrainTileWorld, savedFlags);
  LockPixels(GetGWorldPixMap(terrainTileWorld));
  ResetQuickDrawStrokeState();
  dstX = 0;
  index = 0;
  while (index < 0x2a) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(10000 + index, &blitRect);
    dstX += 0x40;
    ++index;
  }
  index = 0;
  while (index < 4) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(0x276e + index, &blitRect);
    dstX += 0x40;
    ++index;
  }
  index = 0;
  while (index < 4) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(0x2774 + index, &blitRect);
    dstX += 0x40;
    ++index;
  }
  {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(0x277e, &blitRect);
  }
  UnlockPixels(GetGWorldPixMap(terrainTileWorld));
  SetGWorld(savedContext, savedFlags);

  atlasBounds.right = 0xa80;
  g_pDisplayMgr->MakeNewGWorld(improvementTileWorld, 8, atlasBounds);
  GetGWorld(&savedContext, &savedFlags);
  SetGWorld(improvementTileWorld, savedFlags);
  LockPixels(GetGWorldPixMap(improvementTileWorld));
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
    dstX += 0x40;
    ++resourceId;
  }
  resourceId = 0x226;
  while (resourceId < 0x22e) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(resourceId, &blitRect);
    dstX += 0x40;
    ++resourceId;
  }
  resourceId = 0x230;
  while (resourceId < 0x233) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(resourceId, &blitRect);
    dstX += 0x40;
    ++resourceId;
  }
  index = 0;
  while (index < 2) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(0x2778 + index, &blitRect);
    dstX += 0x40;
    ++index;
  }
  index = 0;
  while (index < 2) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(0x242 + index, &blitRect);
    dstX += 0x40;
    ++index;
  }
  UnlockPixels(GetGWorldPixMap(improvementTileWorld));
  SetGWorld(savedContext, savedFlags);

  atlasBounds.right = 0xd7;
  atlasBounds.bottom = 0x78;
  g_pDisplayMgr->MakeNewGWorld(miniMapWorld, 8, atlasBounds);
  atlasBounds.right = 0x90;
  atlasBounds.bottom = 0x26;
  g_pDisplayMgr->MakeNewGWorld(stackBadgeWorld, 8, atlasBounds);
  GetGWorld(&savedContext, &savedFlags);
  SetGWorld(stackBadgeWorld, savedFlags);
  LockPixels(GetGWorldPixMap(stackBadgeWorld));
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
    dstX += 0x12;
    ++resourceId;
  }
  UnlockPixels(GetGWorldPixMap(stackBadgeWorld));
  SetGWorld(savedContext, savedFlags);

  if (mapArtWorld != 0) {
    g_pDisplayMgr->RemoveGWorld(mapArtWorld);
  }
  atlasBounds.left = 0;
  atlasBounds.top = 0;
  atlasBounds.right = 0x48;
  atlasBounds.bottom = 6;
  g_pDisplayMgr->MakeNewGWorld(mapArtWorld, 8, atlasBounds);
  GetGWorld(&savedContext, &savedFlags);
  SetGWorld(mapArtWorld, savedFlags);
  LockPixels(GetGWorldPixMap(mapArtWorld));
  ResetQuickDrawStrokeState();
  ResolveAndBlitBitmapResourceToActiveAtlas(0x244, &atlasBounds);
  UnlockPixels(GetGWorldPixMap(mapArtWorld));
  SetGWorld(savedContext, savedFlags);

  index = 0;
  while (index < 0x10) {
    strategicTileMasks[index].BuildBitmapMaskOpcodeBufferFromResourceRows(index + 0x2740, 0x40,
                                                                          0x40, 0x1680, 0x10);
    ++index;
  }
  resourceId = 0x2760;
  while (resourceId < 0x2766) {
    strategicTileMasks[0x18 + resourceId - 0x2760].BuildBitmapMaskOpcodeBufferFromResourceRows(
        resourceId - 0x26, 0x40, 0x40, 0x1680, 0x10);
    strategicTileMasks[0x1e + resourceId - 0x2760].BuildBitmapMaskOpcodeBufferFromResourceRows(
        resourceId, 0x40, 0x40, 0x1680, 0x10);
    ++resourceId;
  }
  index = 0x10;
  while (index < 0x18) {
    strategicTileMasks[index].BuildBitmapMaskOpcodeBufferFromResourceRows(index + 0x2756, 0x40,
                                                                          0x40, 0x1680, 0x10);
    ++index;
  }
}

// FUNCTION: IMPERIALISM 0x0050b5b0
void TMacViewMgr::ReloadMapArtAtlases() {
  g_pAssetMgr->OpenFilesFor(3);
  if (mapArtWorld != 0) {
    g_pDisplayMgr->RemoveGWorld(mapArtWorld);
  }
  mapArtWorld = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x244);
  if (gaugeWorld != 0) {
    g_pDisplayMgr->RemoveGWorld(gaugeWorld);
  }
  CreateMiniFlagsGWorld();
}

// FUNCTION: IMPERIALISM 0x0050b640
void TMacViewMgr::GenerateMiniMap() {
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
  SetGWorld(miniMapWorld, savedFlags);
  surfaceObject = GetGWorldPixMap(miniMapWorld);
  LockPixels(surfaceObject);
  ResetQuickDrawStrokeState();
  pixelBase = GetPixBaseAddr(surfaceObject);
  strideBytes = static_cast<ushort>((*surfaceObject)->stride) & 0x3fff;
  SetQuickDrawStrokeColor(0xffffff);
  g_pViewMgr->SetForeColor(0x32);
  FillRectWithQuickDrawBrushAndContextOffset(&fillRect);
  colOffset = 0;
  tileIndex = 0;
  while (tileIndex < kStrategicTileCount) {
    terrainCode = g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag;
    if (terrainCode < 0x17) {
      if (terrainCode == 0) {
        terrainCode = 0x3e;
      }
      paletteByte = static_cast<unsigned char>(g_pViewMgr->GetColor(terrainCode));
      pixelBase[colOffset] = paletteByte;
      pixelBase[colOffset + 1] = paletteByte;
      pixelBase[strideBytes + colOffset] = paletteByte;
      pixelBase[strideBytes + colOffset + 1] = paletteByte;
    }
    colOffset += 2;
    if (colOffset == 0xd8) {
      colOffset = 0;
      pixelBase = pixelBase + strideBytes * 2;
    }
    ++tileIndex;
  }
  unsigned char* surfaceBase = GetPixBaseAddr(surfaceObject);
  unsigned char* smoothingBase = surfaceBase + strideBytes * 2;
  scratchBuffer = new unsigned char[0x6540];
  if (scratchBuffer == 0) {
    FailNilPointerWithAssert(s_SourcePathUMacViewMgr, 0x7e3);
  }
  {
    int copyRow = 0;
    unsigned char* scratchCursor = scratchBuffer;
    while (copyRow < 0x78) {
      unsigned char* srcCursor = GetPixBaseAddr(surfaceObject) + copyRow * strideBytes;
      int copyCol = 0;
      while (copyCol < 0xd8) {
        *scratchCursor = srcCursor[copyCol];
        ++scratchCursor;
        ++copyCol;
      }
      ++copyRow;
    }
  }
  {
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
        ++compareRow;
        ++scratchRow;
        --edgeCol;
      }
      rowStart += strideBytes;
      scratchRow += 2;
      --edgeRow;
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
        ++scratchCursor;
        ++copyCol;
      }
      ++copyRow;
    }
  }
  delete[] scratchBuffer;
  SetQuickDrawFillColor(0);
  UnlockPixels(GetGWorldPixMap(miniMapWorld));
  SetGWorld(savedContext, savedFlags);
  if (g_pActiveRandomMapSetupPicture != 0) {
    g_pActiveRandomMapSetupPicture->SpinYourGlobe();
  }
  (*GetGWorldPixMap(miniMapWorld))->dib->FlipScanlineOrder();
  g_pGlobalMapState->strategicMapPalettePreviewReady = true;
}

// FUNCTION: IMPERIALISM 0x0050b9e0
void TMacViewMgr::GenerateRegions() {
  int cityRecordIndex = 0;
  RgnHandle* tileSlot = tileStateSlots;
  while (cityRecordIndex < kProvinceCount) {
    Province& cityRecord = g_pGlobalMapState->cityScoreTable[cityRecordIndex];
    if (cityRecord.ownerNationCode != -1) {
      if (*tileSlot != 0) {
        DisposeRgn(*tileSlot);
        *tileSlot = 0;
      }
      *tileSlot = NewRgn();
      OpenRgn();
      char neighborCount = cityRecord.linkedRegionCount;
      int neighborIndex = 0;
      if (neighborCount > 0) {
        StrategicTileIndex* neighborCursor = cityRecord.linkedTileIndices;
        while (neighborIndex < neighborCount) {
          BuildHexNeighborHighlightPolygonForTile(neighborCursor[0], cityRecordIndex);
          ++neighborIndex;
          ++neighborCursor;
        }
      }
      CloseRgn(*tileSlot);
    }
    ++cityRecordIndex;
    ++tileSlot;
  }
  RegenerateCountryRegions();
}

// FUNCTION: IMPERIALISM 0x0050bad0
void TMacViewMgr::RegenerateCountryRegions() {
  if (g_pSimMgr->numGreatPowers == 1) {
    g_pGameFlowState->SendGameControl(kControlTagRege, 0, 0xfffffffd);
  }
  if (tileStateSlots[0] != 0) {
    RgnHandle regionWrapper = NewRgn();
    int nationIndex = 0;
    while (nationIndex < kNationSlotCount) {
      SetEmptyRgn(regionWrapper);
      int cityRecordIndex = 0;
      RgnHandle* tileSlot = tileStateSlots;
      while (cityRecordIndex < kProvinceCount) {
        if (g_pGlobalMapState->cityScoreTable[cityRecordIndex].ownerNationCode == nationIndex) {
          UnionRgn(regionWrapper, *tileSlot, regionWrapper);
        }
        ++cityRecordIndex;
        ++tileSlot;
      }
      SetCountryRgn(regionWrapper, static_cast<short>(nationIndex));
      ++nationIndex;
    }
    DisposeRgn(regionWrapper);
    GenerateMiniMap();
  }
}

// FUNCTION: IMPERIALISM 0x0050bbc0
void TMacViewMgr::GetTradeCluster(TTradeCluster* orderSource, int orderSlot, short nationSlot) {
  if (orderSource->IsSelectionAllowed()) {
    g_apNationStates[nationSlot]->SetItemPotentials(static_cast<short>(orderSlot), -1);
    return;
  }
  g_apNationStates[nationSlot]->SetItemPotentials(
      static_cast<short>(orderSlot), static_cast<short>(orderSource->GetTradeSellControlValue()));
}

// FUNCTION: IMPERIALISM 0x0050bc50
void TMacViewMgr::ShowTradeCluster(TView* view, short orderSlot, short nationIndex) {
  TTradeCluster* row = static_cast<TTradeCluster*>(view);
  view->DoPostCreate(0);
  row->tradeMetricSlot = orderSlot;
  if (g_pTechMgr->perTechUnlockFlag[TTechMgr::kProductionOrderTechId] == 0 &&
      (orderSlot == 6 || orderSlot == 0xc)) {
    view->Show(0, 0);
  }
  short sellCount = g_apNationStates[nationIndex]->GetTradeOffersFor(orderSlot);
  short effectiveNationIndex = nationIndex;
  if (sellCount > 0 && g_apNationStates[nationIndex]->merchantCapacity == 0) {
    g_apNationStates[nationIndex]->SetItemPotentials(orderSlot, 0);
    sellCount = 0;
    effectiveNationIndex = 0;
  }
  TNumberText* sellControl = static_cast<TNumberText*>(view->FindSubView(kControlTagSell));
  if (sellControl == 0) {
    FailNilPointerWithAssert(s_SourcePathUMacViewMgr, 0x8e4);
  }
  if (sellCount < 0) {
    row->ShowBidCard();
    sellControl->SetControlValue(0, 0);
    sellControl->Show(0, 1);
  } else {
    row->DoControlAction();
  }
  if (sellCount > 0) {
    row->ShowOfferCard();
    sellControl->SetControlValue(sellCount, 0);
    sellControl->Show(1, 1);
    return;
  }
  if (g_apNationStates[effectiveNationIndex]->merchantCapacity != 0) {
    row->ShowOfferHandle();
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

// FUNCTION: IMPERIALISM 0x0050bea0
void TMacViewMgr::ShowTransportEntry(short resourceSlot, short nationIndex, TView* hostView) {
  TGreatPower* nation = g_apNationStates[nationIndex];
  CString scratch38;

  if (resourceSlot == -1) {
    TTransportPicture* panel = ResolveTaggedPanelOrFail(hostView, kControlTagTota, 0x93a);
    g_pSimMgr->GetString(0x2735, 0, &scratch38);
    SetControlHoverHelpText(scratch38, panel);

    TMyStaticText* textEntry = new TMyStaticText();

    int textOffset[2] = {0xa2, 0x14};
    int textSize[2] = {0x3c, 0xb};
    textEntry->IStaticText(panel, textOffset, textSize, 5, 5, -1, 0);

    TextStyle styleDescriptor;
    BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xa, 0x2b67);
    textEntry->InstallTextStyle(styleDescriptor, 0);
    textEntry->SetJustification(0, false);
    textEntry->controlTag = kControlTagText;

    g_pSimMgr->GetString(0x2735, 1, &scratch38);
    SetControlHoverHelpText(scratch38, textEntry);

    short needCap = nation != 0 ? nation->transportCapacity : 0;
    panel->splitValue94 = nation != 0 ? nation->reservedTransportCapacity : 0;
    panel->splitValue96 = needCap;
    panel->splitLimit = -1;
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
      ResolveTaggedPanelOrFail(hostView, static_cast<unsigned int>(summaryTag), 0x95e);

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
      deficitCount = static_cast<short>(production * 2 - city->stockByType[kResourceCotton] -
                                        city->stockByType[kResourceWool]);
      formatCurrent.Format(g_szDecimalFormat,
                           static_cast<int>(city->stockByType[kResourceCotton]) +
                               static_cast<int>(city->stockByType[kResourceWool]));
      formatProduction.Format(g_szDecimalFormat, production * 2);
      g_pSimMgr->GetString(0x2719, 0, &displayText);
    }
    break;
  case 2:
    needTarget = nation->needTargetByType[2];
    needCurrent = nation->needCurrentByType[2];
    g_pSimMgr->GetCommodityName(resourceSlot, &itemName);
    {
      int production = city->GetBuildingType(4);
      deficitCount = static_cast<short>(production * 2 - city->stockByType[kResourceTimber]);
      formatCurrent.Format(g_szDecimalFormat, static_cast<int>(city->stockByType[kResourceTimber]));
      formatTarget.Format(g_szDecimalFormat, production * 2);
      g_pSimMgr->GetString(0x2719, 4, &displayText);
      formatFieldValue = city->stockByType[kResourceTimber];
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 3:
  case 4:
    needTarget = nation->needTargetByType[resourceSlot];
    needCurrent = nation->needCurrentByType[resourceSlot];
    g_pSimMgr->GetCommodityName(resourceSlot, &itemName);
    {
      int production = city->GetBuildingType(2);
      deficitCount = static_cast<short>(production - city->stockByType[resourceSlot]);
      formatCurrent.Format(g_szDecimalFormat, static_cast<int>(city->stockByType[resourceSlot]));
      formatTarget.Format(g_szDecimalFormat, production);
      g_pSimMgr->GetString(0x2719, 2, &displayText);
      formatFieldValue = city->stockByType[resourceSlot];
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 5:
    needTarget = nation->needTargetByType[5];
    needCurrent = nation->needCurrentByType[5];
    g_pSimMgr->GetCommodityName(resourceSlot, &itemName);
    formatCurrent.Format(g_szDecimalFormat, static_cast<int>(needCurrent));
    formatTarget.Format(g_szDecimalFormat, static_cast<int>(needTarget));
    g_pSimMgr->GetString(0x2719, 1, &displayText);
    useBracketOnlyPath = true;
    break;
  case 6:
    needTarget = nation->needTargetByType[6];
    needCurrent = nation->needCurrentByType[6];
    g_pSimMgr->GetCommodityName(resourceSlot, &itemName);
    {
      int production = city->GetBuildingType(6);
      deficitCount = static_cast<short>(production * 2 - city->stockByType[kResourceOil]);
      formatCurrent.Format(g_szDecimalFormat, static_cast<int>(city->stockByType[kResourceOil]));
      formatTarget.Format(g_szDecimalFormat, production * 2);
      g_pSimMgr->GetString(0x2719, 6, &displayText);
      formatFieldValue = city->stockByType[kResourceOil];
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 8:
    needTarget = nation->needTargetByType[8];
    needCurrent = nation->needCurrentByType[8];
    g_pSimMgr->GetCommodityName(resourceSlot, &itemName);
    {
      int production = city->GetBuildingType(1);
      deficitCount = static_cast<short>(production * 2 - city->stockByType[kResourceFabric]);
      formatCurrent.Format(g_szDecimalFormat, static_cast<int>(city->stockByType[kResourceFabric]));
      formatTarget.Format(g_szDecimalFormat, production * 2);
      g_pSimMgr->GetString(0x2719, 1, &displayText);
      formatFieldValue = city->stockByType[kResourceFabric];
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 9:
    needTarget = nation->needTargetByType[9];
    needCurrent = nation->needCurrentByType[9];
    g_pSimMgr->GetCommodityName(resourceSlot, &itemName);
    {
      int production = city->GetBuildingType(5);
      deficitCount = static_cast<short>(production * 2 - city->stockByType[kResourceLumber]);
      formatCurrent.Format(g_szDecimalFormat, static_cast<int>(city->stockByType[kResourceLumber]));
      formatTarget.Format(g_szDecimalFormat, production * 2);
      g_pSimMgr->GetString(0x2719, 5, &displayText);
      formatFieldValue = city->stockByType[kResourceLumber];
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 0xb:
    needTarget = nation->needTargetByType[0xb];
    needCurrent = nation->needCurrentByType[0xb];
    g_pSimMgr->GetCommodityName(resourceSlot, &itemName);
    {
      int production = city->GetBuildingType(3);
      deficitCount = static_cast<short>(production * 2 - city->stockByType[kResourceSteel]);
      formatCurrent.Format(g_szDecimalFormat, static_cast<int>(city->stockByType[kResourceSteel]));
      formatTarget.Format(g_szDecimalFormat, production * 2);
      g_pSimMgr->GetString(0x2719, 3, &displayText);
      formatFieldValue = city->stockByType[kResourceSteel];
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 0xc:
    needTarget = nation->needTargetByType[0xc];
    needCurrent = nation->needCurrentByType[0xc];
    g_pSimMgr->GetCommodityName(resourceSlot, &itemName);
    {
      int production = city->GetBuildingType(0xb);
      deficitCount = static_cast<short>(production * 2 - city->stockByType[kResourceFuel]);
      formatCurrent.Format(g_szDecimalFormat, static_cast<int>(city->stockByType[kResourceFuel]));
      formatTarget.Format(g_szDecimalFormat, production * 2);
      g_pSimMgr->GetString(0x2719, 0xb, &displayText);
      formatFieldValue = city->stockByType[kResourceFuel];
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 0xd:
  case 0xe:
  case 0xf:
    needTarget = nation->needTargetByType[resourceSlot];
    needCurrent = nation->needCurrentByType[resourceSlot];
    g_pSimMgr->GetCommodityName(resourceSlot, &itemName);
    formatCurrent.Format(g_szDecimalFormat, static_cast<int>(needCurrent));
    formatTarget.Format(g_szDecimalFormat, static_cast<int>(needTarget));
    g_pSimMgr->GetString(0x2719, 8, &displayText);
    useBracketOnlyPath = true;
    break;
  case 0x11:
  case 0x12:
    needTarget = nation->needTargetByType[resourceSlot];
    needCurrent = nation->needCurrentByType[resourceSlot];
    g_pSimMgr->GetCommodityName(resourceSlot, &itemName);
    {
      short* summary = city->GetUnmetNeeds();
      short summaryValue = summary[resourceSlot];
      formatTarget.Format(g_szDecimalFormat, static_cast<int>(summaryValue));
      deficitCount = static_cast<short>(summaryValue - city->stockByType[resourceSlot]);
      formatCurrent.Format(g_szDecimalFormat, static_cast<int>(city->stockByType[resourceSlot]));
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
      short* summary = city->GetUnmetNeeds();
      short summaryValue = summary[0x14];
      formatTarget.Format(g_szDecimalFormat, static_cast<int>(summaryValue));
      deficitCount = static_cast<short>(summaryValue - city->stockByType[kResourceFish] -
                                        city->stockByType[kResourceLivestock]);
      formatFieldValue = static_cast<short>(city->stockByType[kResourceFish] +
                                            city->stockByType[kResourceLivestock]);
      formatCurrent.Format(g_szDecimalFormat, static_cast<int>(formatFieldValue));
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 0x15:
    needTarget = nation->needTargetByType[0x15];
    needCurrent = nation->needCurrentByType[0x15];
    g_pSimMgr->GetCommodityName(resourceSlot, &itemName);
    g_pSimMgr->NumToCurrency(500, &formatCurrent);
    useBracketOnlyPath = true;
    break;
  case 0x16:
    needTarget = nation->needTargetByType[0x16];
    needCurrent = nation->needCurrentByType[0x16];
    g_pSimMgr->GetCommodityName(resourceSlot, &itemName);
    g_pSimMgr->NumToCurrency(200, &formatCurrent);
    useBracketOnlyPath = true;
    break;
  default:
    needTarget = resourceSlot;
    needCurrent = resourceSlot;
    showArrowWidgets = resourceSlot;
    deficitCount = resourceSlot;
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
    panel->splitLimit = -1;
  } else if (deficitCount < 1) {
    panel->splitLimit = 0;
  } else {
    panel->splitLimit = deficitCount;
  }

  SetControlHoverHelpText(displayText, panel);

  if (needCurrent == 0) {
    panel->Show(0, 0);
    TControl* leftArrow = ResolveTaggedChildOrFail(panel, kControlTagLeft, 0xae8);
    leftArrow->Free();
    TControl* rightArrow = ResolveTaggedChildOrFail(panel, kControlTagRght, 0xaec);
    rightArrow->Free();
    return;
  }

  TControl* leftSource = ResolveTaggedChildOrFail(panel, kControlTagLeft, 0xaf2);
  int leftLayout0[2];
  int leftLayout1[2];
  CopyViewLayoutFieldsToStack(leftLayout0, leftLayout1, leftSource);
  leftSource->Free();

  TRightLeftView* leftView = new TRightLeftView();
  leftView->InitializeUiResourceEntryFrameAndParent(0, panel, leftLayout1, leftLayout0, 5, 5, 0);
  leftView->controlTag = kControlTagLeft;

  TControl* rightSource = ResolveTaggedChildOrFail(panel, kControlTagRght, 0xafc);
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
  textEntry->SetJustification(0, false);
  textEntry->controlTag = kControlTagText;

  g_pSimMgr->GetString(0x2735, 4, &scratch38);
  SetControlHoverHelpText(scratch38, textEntry);

  if (resourceSlot == 0x15 || resourceSlot == 0x16) {
    TMyStaticText* valueEntry = new TMyStaticText();

    int valueOffset[2] = {0x32, 0x14};
    int valueSize[2] = {0x3c, 0xb};
    valueEntry->IStaticText(panel, valueOffset, valueSize, 5, 5, -1, 0);
    valueEntry->InstallTextStyle(styleDescriptor, 0);
    valueEntry->SetJustification(0, false);
    valueEntry->controlTag = kControlTagValu;
  }

  panel->resourceMetricSlot = resourceSlot;
  panel->splitValue94 = needTarget;
  panel->splitValue96 = needCurrent;
}

// FUNCTION: IMPERIALISM 0x0050d310
void TMacViewMgr::SelectCitySite(int unusedArg1, int unusedArg2) {
  TView* dialog = activeCityProductionView;
  g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventCitySiteSelector), 0);
  short completionFlag = dialog->lastIdleTick;
  while (completionFlag == 0) {
    PumpUiMessagesAndBackgroundTasks(1);
    completionFlag = static_cast<short>(dialog->lastIdleTick);
  }
}

// FUNCTION: IMPERIALISM 0x0050d360
TBuildingView* TMacViewMgr::OpenBuildingWindow(short buildingSlot, TCity* city, bool closeAfterOpen,
                                               bool isEmbeddedPage,
                                               TCityProductionView* productionView) {
  TWindow* dialog = g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(
      static_cast<TurnEventId>(buildingSlot + kTurnEventTextileMill));
  TBuildingView* buildingView = static_cast<TBuildingView*>(dialog->FindSubView(kControlTagDialog));
  if (buildingView == 0) {
    FailNilPointerWithAssert(s_SourcePathUMacViewMgr, 0xb4f);
  }
  buildingView->ApplyCityViewSelectionPayloadAndRefreshControls(city, isEmbeddedPage,
                                                                productionView, buildingSlot);
  dialog->controlValue = 0x65;
  if (closeAfterOpen) {
    dialog->SetModality(true);
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
    short buildingSlot, TCity* city, bool closeAfterOpen, bool isEmbeddedPage,
    TCityProductionView* productionView, short savedX, short savedY) {
  TWindow* dialog = g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(
      static_cast<TurnEventId>(buildingSlot + kTurnEventTextileMill));
  TBuildingView* buildingView = static_cast<TBuildingView*>(dialog->FindSubView(kControlTagDialog));
  if (buildingView == 0) {
    FailNilPointerWithAssert(s_SourcePathUMacViewMgr, 0xb62);
  }
  buildingView->ApplyCityViewSelectionPayloadAndRefreshControls(city, isEmbeddedPage,
                                                                productionView, buildingSlot);
  dialog->controlValue = 0x65;
  CPoint placement(savedX, savedY);
  dialog->Locate(placement, false);
  if (closeAfterOpen) {
    dialog->SetModality(true);
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
      static_cast<TBuildingConstructionView*>(dialog->FindSubView(kControlTagDialog));
  if (constructionView == 0) {
    FailNilPointerWithAssert(s_SourcePathUMacViewMgr, 0xb98);
  }
  constructionView->StuffValues(buildingSlot, city, productionView);
  dialog->SetModality(true);
  unsigned long dialogAction = dialog->PoseModally();
  dialog->Close();
  constructionView->DoClosingAction(dialogAction);
  dialog->Free();
}

// FUNCTION: IMPERIALISM 0x0050d680
void TMacViewMgr::SetCountryRgn(RgnHandle sourceRegion, short slotIndex) {
  if (countryRegions[slotIndex] == 0) {
    countryRegions[slotIndex] = NewRgn();
  }
  CopyRgn(sourceRegion, countryRegions[slotIndex]);
}

// FUNCTION: IMPERIALISM 0x0050d6c0
unsigned char TMacViewMgr::PtInCountry(CPoint* point, short regionIndex) {
  if (countryRegions[regionIndex] != 0) {
    return PtInRgn(point, countryRegions[regionIndex]);
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x0050d700
void TMacViewMgr::MakeCountryRegion(int country) {
  TQuickDrawSurfaceContext* savedContext;
  int savedFlags;
  RECT resourceBounds;
  TQuickDrawSurfaceContext* tileSurface = 0;
  countryRegions[country] = NewRgn();
  GetGWorld(&savedContext, &savedFlags);
  TBitmapResourceLoader** loaderHandle = CreateBitmapResourceLoaderHandle(country + 4000);
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
  TBitmapSurfaceNode** surfaceHandle = GetGWorldPixMap(tileSurface);
  // The region rebuild consumes the node itself (it reads node->dib at +0x1c).
  if (BitMapToRegion(countryRegions[country], *surfaceHandle) != 0) {
    BitMapToRegion(countryRegions[country], *surfaceHandle);
    BitMapToRegion(countryRegions[country], *surfaceHandle);
  }
  g_pDisplayMgr->RemoveGWorld(tileSurface);
  UnlockPixels(GetGWorldPixMap(tileSurface));
  SetGWorld(savedContext, savedFlags);
}

// FUNCTION: IMPERIALISM 0x0050d8d0
void TMacViewMgr::UpdateCityScreen() {
  if (activeCityProductionView != 0) {
    activeCityProductionView->UpdateToolbar();
  }
}

// FUNCTION: IMPERIALISM 0x0050d8f0
void TMacViewMgr::CloseBuilding(short buildingSlot) {
  if (activeCityProductionView != 0) {
    activeCityProductionView->buildingViews[buildingSlot] = 0;
  }
}

// FUNCTION: IMPERIALISM 0x0050d920
void TMacViewMgr::ClearActiveCityProductionViewAndDiscardRegion() {
  if (activeCityProductionView != 0) {
    activeCityProductionView->CloseAndSaveWindows();
  }
  activeCityProductionView = 0;
}

// FUNCTION: IMPERIALISM 0x0050d950
void TMacViewMgr::RefreshActiveGoldControlAndUiRuntimeState() {
  TView* hostView = g_pDisplayMgr->activeDialog;
  TPicture* goldControl = static_cast<TPicture*>(hostView->FindSubView(kControlTagDialog));
  if (goldControl == 0) {
    FailNilPointerWithAssert(s_SourcePathUMacViewMgr, 0xc27);
  }
  goldControl->ReleasePicture();
  goldControl->SetPictureRsrcID(0, 0);
  g_pUiAnimator->FreeAllAnis();
}

// FUNCTION: IMPERIALISM 0x0050d9e0
void TMacViewMgr::FastDrawPicture(TBitmapResourceLoader** loaderHandle,
                                  unsigned char* destinationBits, short destinationStride) {
  CDib* dib = (*loaderHandle)->bitmapResource;
  unsigned char* sourceRow = static_cast<unsigned char*>(dib->m_dibBits);
  unsigned int rowWidth = dib->m_pInfoHeader->bmiHeader.biWidth;
  short sourceStride = (rowWidth + 3) & ~3;
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
void TMacViewMgr::CopyMapIcon(TBitmapSurfaceNode** dstSurface, short iconIndex, short x, short y) {
  TBitmapSurfaceNode** atlasSurface;
  short srcRowOffset;
  if (iconIndex < 100) {
    atlasSurface = GetGWorldPixMap(commodityIconWorld);
    srcRowOffset = static_cast<short>(iconIndex << 5);
  } else {
    atlasSurface = GetGWorldPixMap(flagWorld);
    srcRowOffset = static_cast<short>((iconIndex - 100) * 0x20);
  }
  ushort dstStrideRaw = static_cast<ushort>((*dstSurface)->stride);
  LockPixels(atlasSurface);
  unsigned char* srcPixels = GetPixBaseAddr(atlasSurface);
  ushort srcStrideRaw = static_cast<ushort>((*atlasSurface)->stride);
  unsigned char* dstPixels = GetPixBaseAddr(dstSurface);
  int dstStrideBytes = static_cast<short>(dstStrideRaw & 0x3fff);
  unsigned char* srcRow = srcPixels + srcRowOffset;
  unsigned char* dstRow = dstPixels + y * dstStrideBytes + x;
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
    --rowsRemaining;
    dstRow += dstStrideBytes;
    srcRow = srcRow + static_cast<short>(srcStrideRaw & 0x3fff);
  } while (rowsRemaining != 0);
  UnlockPixels(atlasSurface);
}

// FUNCTION: IMPERIALISM 0x0050dd40
void TMacViewMgr::DrawStrategicMapUnitIcon(TBitmapSurfaceNode** pDstSurface, short nIconVariant,
                                           short nDstX, short nYShift) {
  TBitmapSurfaceNode** atlasSurface = GetGWorldPixMap(unitIconAtlas);
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
    --rowsRemaining;
    dstRow += dstStrideBytes;
    srcRow = srcRow + static_cast<short>(srcStrideRaw & 0x3fff);
  } while (rowsRemaining != 0);
  UnlockPixels(atlasSurface);
}

// FUNCTION: IMPERIALISM 0x0050df40
void TMacViewMgr::CopyDevelopmentIcon(TBitmapSurfaceNode** pDstSurface, ushort wOverlayIconId,
                                      short nVariantRow, short nDstX, short nYShift) {
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
    unsigned char* dstPixel = dstRow;
    unsigned char* srcPixel = srcRow;
    for (int i = 0; i < 0x26; ++i) {
      if (*srcPixel != '\x10') {
        *dstPixel = *srcPixel;
      }
      ++srcPixel;
      ++dstPixel;
    }
    --rowsRemaining;
    dstRow += dstStrideBytes;
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
  for (int rowsRemaining = 0; rowsRemaining < 0x1a; ++rowsRemaining) {
    for (int columnsRemaining = 0; columnsRemaining < 0x26; ++columnsRemaining) {
      if (*sourceRow != 0x10) {
        *destinationRow = *sourceRow;
      }
      ++sourceRow;
      ++destinationRow;
    }
    destinationRow += destinationStride - 0x26;
    sourceRow += sourceStride - 0x26;
  }
  UnlockPixels(atlasSurface);
}

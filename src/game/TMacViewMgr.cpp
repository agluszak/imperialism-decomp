#include <stdlib.h>

#include "game/TMacViewMgr.h"
#include "game/map_overlay_geometry.h"

#include "game/turn_event_dialog_provisional.h"

#include <new>

#include "game/bitmap_descriptor_helpers.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/quickdraw_regions.h"
#include "game/TAnimation.h"
#include "game/TAssetMgr.h"
#include "game/TCity.h"
#include "game/TControl.h"
#include "game/TDisplayMgr.h"
#include "game/TGlobalMapState.h"
#include "game/TGreatPower.h"
#include "game/TMyStaticText.h"
#include "game/TRightLeftView.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/TTechMgr.h"
#include "game/TTurnEventDialogFactoryRegistry.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TView.h"
#include "game/ui_control_tags.h"
#include "game/UiRuntimeContext.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_invalidation_guard.h"
#include "game/TMultiplayerMgr.h"
#include "game/mfc.h"
#include "game/turn_flow_cooldown.h"
#include "game/ui_text_label_helpers_decls.h"
#include "decomp_types.h"
#include <string.h>

undefined4 RebuildSurfaceRowsWithTemporaryRowBuffer(void);
undefined4 CallObjectOffset24Vslot54IfPresent(void);
// Genuine __cdecl(void*, int) heap-block reallocator; cast at call sites (same pattern
// as TAutoGreatPower.cpp/TCountry.cpp). Returns the new block, or 0 on failure.

namespace {

const unsigned int kAddrStrategicMapOverlaySourceRowByIconId = 0x00696d20;
const unsigned int kAddrDecimalFormat = 0x0069430c;

static void SetPanelShortField(TControl* panel, int offset, short value) {
  *reinterpret_cast<short*>(reinterpret_cast<char*>(panel) + offset) = value;
}

static TControl* ResolveTaggedPanelOrFail(TView* hostView, unsigned int tag) {
  TControl* panel = static_cast<TControl*>(hostView->ResolveControlByTag(tag));
  if (panel == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  return panel;
}

static TControl* ResolveTaggedChildOrFail(TControl* panel, unsigned int tag) {
  TControl* child = static_cast<TControl*>(panel->ResolveControlByTag(tag));
  if (child == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  return child;
}

static void CopyViewLayoutFieldsToStack(int* layout0, int* layout1, TControl* srcControl) {
  TView* srcView = srcControl;
  layout0[0] = srcView->ownerLocalX;
  layout0[1] = srcView->ownerLocalY;
  layout1[0] = srcView->frameWidth34;
  layout1[1] = srcView->frameHeight38;
}

static void ScanBracketExpressionsInto(CString* dest, const CString& templateText) {
  scanBracketExpressions(g_pSimMgr, dest, static_cast<LPCSTR>(templateText));
}

static undefined4 QueryPointInsideHitRegion(short x, short y, RgnHandle region) {
  CPoint point;
  point.x = x;
  point.y = y;
  return PtInRgn(&point, region);
}

static void InvokeBuildHexNeighborHighlightPolygonForTile(short tileId, int tileIndex) {
  BuildHexNeighborHighlightPolygonForTile(tileId, tileIndex);
}

static void InvokeCallObjectOffset24Vslot54IfPresent(void) {
  reinterpret_cast<void(__cdecl*)(void)>(
      reinterpret_cast<void (*)()>(CallObjectOffset24Vslot54IfPresent))();
}

void ReleaseBitmapLoaderHandle(TBitmapResourceLoader** loaderHandle) {
  if (loaderHandle == nullptr) {
    return;
  }
  delete *loaderHandle;
  ::operator delete(loaderHandle);
}

void ResolveAndBlitBitmapResourceToActiveAtlas(int resourceId, RECT* dstRect) {
  TBitmapResourceLoader** loaderHandle = CreateBitmapResourceLoaderHandle(resourceId);
  if (*loaderHandle != 0) {
    BlitBitmapResourceLoaderToActiveDc(loaderHandle, dstRect);
  }
  ReleaseBitmapLoaderHandle(loaderHandle);
}

// Provisional turn-event dialog / GOLD control interfaces are shared with TViewMgr.cpp
// via one header so the two copies can't drift (bd imperialism-decomp-hpd.7).
using turn_event_dialog::CityOrderSource;
using turn_event_dialog::GoldDialogControl;
using turn_event_dialog::TurnEventDialogNode;

} // namespace

// FUNCTION: IMPERIALISM 0x00430750
StrategicMapCallbackRecord::~StrategicMapCallbackRecord() {
  subobjectDispatchTable1c = 0x006404a8;
  if (ownedBuffer20 != 0) {
    delete[] ownedBuffer20;
  }
  dispatchTable00 = 0x006404a4;
  if (ownedBuffer04 != 0) {
    delete[] ownedBuffer04;
  }
}

// FUNCTION: IMPERIALISM 0x004d4b90
StrategicMapCallbackRecord::StrategicMapCallbackRecord() {
  ownedBuffer04 = 0;
  bufferCapacity08 = 0;
  committedLength0c = 0;
  dispatchTable00 = 0x006404a4;
  appendCursor10 = 0;
  alignmentCursor14 = 0;
  hadTrailingPadding18 = 0;
  ownedBuffer20 = 0;
  cursorBufferSize24 = 0;
  cursorBufferInitialized28 = 0;
  subobjectDispatchTable1c = 0x006404a8;
  lastBoundSurface2c = 0;
}

// FUNCTION: IMPERIALISM 0x004d4e40
unsigned char* StrategicMapCallbackRecord::EnsureOpcodeBufferByteAtIndex(int index) {
  if (index >= bufferCapacity08) {
    int required = index + 1;
    int newCapacity = required + required;
    if (newCapacity < required) {
      newCapacity = required;
    }

    char* newBuffer = new char[newCapacity];
    if (ownedBuffer04 != 0 && committedLength0c > 0) {
      memcpy(newBuffer, ownedBuffer04, committedLength0c);
    }
    delete[] ownedBuffer04;
    ownedBuffer04 = newBuffer;
    bufferCapacity08 = newCapacity;
  }

  if (index >= committedLength0c) {
    committedLength0c = index + 1;
  }
  return reinterpret_cast<unsigned char*>(ownedBuffer04 + index);
}

// FUNCTION: IMPERIALISM 0x004d5090
void StrategicMapCallbackRecord::BuildBitmapMaskOpcodeBufferFromResourceRows(int resourceId,
                                                                             int width, int height,
                                                                             int surface,
                                                                             int transparentPixel) {
  lastBoundSurface2c = surface;

  CDib* dib = g_pModuleLibraryCacheState->LoadBmpResourceByIdCached(
      static_cast<unsigned short>(resourceId));
  unsigned char* row = static_cast<unsigned char*>(dib->m_dibBits);
  int sourceRowStride = (dib->m_pInfoHeader->bmiHeader.biWidth + 3) & 0xfffffffc;
  int skippedPixels = 0;

  int y = 0;
  while (y < height) {
    int x = 0;
    while (x < width) {
      unsigned char pixel = row[x];
      if (pixel == static_cast<unsigned char>(transparentPixel)) {
        skippedPixels = skippedPixels + 1;
      } else {
        if (skippedPixels > 0x7f) {
          AppendOpcodeByte(0x05);
          AppendOpcodeBytePair(skippedPixels >> 0x10);
          AppendOpcodeBytePair(skippedPixels);
          skippedPixels = 0;
        }
        AppendOpcodeByte(0xc6);
        AppendOpcodeByte(0x40);
        AppendOpcodeByte(skippedPixels);
        AppendOpcodeByte(pixel);
        skippedPixels = 0;
      }
      x = x + 1;
    }
    row = row + sourceRowStride;
    y = y + 1;
  }

  g_pModuleLibraryCacheState->ReleaseRecordById(static_cast<short>(resourceId));
  AppendOpcodeByte(0xc3);
  FinalizeOpcodeBufferAlignment();
}

// FUNCTION: IMPERIALISM 0x004d5580
StrategicMapCallbackRecord* StrategicMapCallbackRecord::AppendOpcodeByte(int value) {
  unsigned int index = static_cast<unsigned int>(appendCursor10);
  int newCount = index + 1;
  appendCursor10 = newCount;
  if (index >= static_cast<unsigned int>(bufferCapacity08)) {
    unsigned int grownCapacity = static_cast<unsigned int>(newCount) * 2;
    unsigned int clampedCapacity = grownCapacity;
    if (0x7fffffff < grownCapacity) {
      clampedCapacity = 0x7fffffff;
    }
    char* grown = static_cast<char*>(realloc(ownedBuffer04, grownCapacity));
    if (grown == 0) {
      ownedBuffer04 = static_cast<char*>(realloc(ownedBuffer04, newCount));
      bufferCapacity08 = newCount;
    } else {
      ownedBuffer04 = grown;
      bufferCapacity08 = clampedCapacity;
    }
  }
  if (index >= static_cast<unsigned int>(committedLength0c)) {
    committedLength0c = newCount;
  }
  ownedBuffer04[index] = static_cast<char>(value);
  return this;
}

// FUNCTION: IMPERIALISM 0x004d5610
void StrategicMapCallbackRecord::AppendOpcodeBytePair(int value) {
  AppendOpcodeByte((value >> 8) & 0xff);
  AppendOpcodeByte(value & 0xff);
}

// FUNCTION: IMPERIALISM 0x004d5720
void StrategicMapCallbackRecord::FinalizeOpcodeBufferAlignment() {
  while (((reinterpret_cast<unsigned int>(ownedBuffer04) + alignmentCursor14) & 3) != 0) {
    AppendOpcodeByte(0);
    alignmentCursor14 = (alignmentCursor14 + 1) & 3;
  }
  if (alignmentCursor14 != 0) {
    hadTrailingPadding18 = 1;
  }
}

// SYNTHETIC: IMPERIALISM 0x00509c00
// TMacViewMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x00509c80
// TMacViewMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMacViewMgr, TObject)

// FUNCTION: IMPERIALISM 0x00509ca0
TMacViewMgr::TMacViewMgr() : TObject() {
  field04 = 0;
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
TMacViewMgr::~TMacViewMgr() {}

// FUNCTION: IMPERIALISM 0x00509f20
void TMacViewMgr::InitializeStrategicMapViewSystem() {
  g_pUiViewManager->NoOpRuntimeUiCallback_005df3f0(3);
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
  g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&unitIconAtlas);
  g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&unitOverlayAtlas);
  g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&atlas674);
  g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&atlas668);
  g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&atlas66c);
  g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&atlas670);
  g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&atlas680);
  g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&atlas688);
  g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&atlas68c);
  g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&atlas690);
  g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&atlas684);
  g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&atlas6b4);
  g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&atlas6b8);
  index = 0;
  while (index < 8) {
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&atlas694[index]);
    ++index;
  }
  g_pStrategicMapViewSystem = 0;
  delete this;
}

// FUNCTION: IMPERIALISM 0x0050a140
void TMacViewMgr::ReadFrom(TStream* stream) {
  field04 = 0;
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
undefined TMacViewMgr::BuildStrategicMapCommodityIconAtlasFrom700To722() {
  RECT atlasBounds;
  TQuickDrawSurfaceContext* savedContext;
  int savedFlags;
  TBitmapSurfaceNode** atlasSurface;
  int* pixelBuffer;
  undefined4* clearCursor;
  uint clearWords;
  uint clearRemainder;
  int commodityIndex;
  int stridePixels;
  undefined4* dstCursor;
  atlasBounds.left = 0;
  atlasBounds.top = 0;
  atlasBounds.right = 0x2e0;
  atlasBounds.bottom = 0x18;
  g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&atlas674, 8, &atlasBounds);
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  SetActiveQuickDrawSurfaceContext(atlas674, savedFlags);
  atlasSurface = static_cast<TBitmapSurfaceNode**>(GetSurfaceNodeSlot(atlas674));
  ReturnConstantTrueQuickDrawFlag(atlasSurface);
  ResetQuickDrawStrokeState();
  pixelBuffer = reinterpret_cast<int*>(GetSurfaceNodePixelBits(atlasSurface));
  clearWords = (atlasBounds.right - atlasBounds.left) * (atlasBounds.bottom - atlasBounds.top);
  clearCursor = reinterpret_cast<undefined4*>(pixelBuffer);
  while (clearWords >= 4) {
    *clearCursor = 0;
    clearCursor = clearCursor + 1;
    clearWords = clearWords - 4;
  }
  clearRemainder = clearWords;
  while (clearRemainder != 0) {
    *(unsigned char*)clearCursor = 0;
    clearCursor = reinterpret_cast<undefined4*>((int)clearCursor + 1);
    clearRemainder = clearRemainder - 1;
  }
  stridePixels = static_cast<short>(static_cast<ushort>((*atlasSurface)->stride) & 0x3fff);
  dstCursor = reinterpret_cast<undefined4*>(pixelBuffer) - 2;
  commodityIndex = 0;
  while (commodityIndex < 0x17) {
    TBitmapResourceLoader** loaderHandle = CreateBitmapResourceLoaderHandle(commodityIndex + 700);
    if (loaderHandle != nullptr && *loaderHandle != 0) {
      dstCursor = dstCursor + 2;
      CopySpriteSurfaceToStrideBuffer(loaderHandle, dstCursor, static_cast<short>(stridePixels));
    }
    ReleaseBitmapLoaderHandle(loaderHandle);
    commodityIndex = commodityIndex + 1;
  }
  NoOpQuickDrawLifecycleHookB(GetSurfaceNodeSlot(atlas674));
  SetActiveQuickDrawSurfaceContext(savedContext, savedFlags);
  return 0;
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
  g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&atlas688, 8, &atlasBounds);
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  SetActiveQuickDrawSurfaceContext(atlas688, savedFlags);
  ReturnConstantTrueQuickDrawFlag(GetSurfaceNodeSlot(atlas688));
  ResetQuickDrawStrokeState();
  ResolveAndBlitBitmapResourceToActiveAtlas(0x58e, &atlasBounds);
  ResolveAndBlitBitmapResourceToActiveAtlas(0x58f, &atlasBounds);
  NoOpQuickDrawLifecycleHookB(GetSurfaceNodeSlot(atlas688));
  SetActiveQuickDrawSurfaceContext(savedContext, savedFlags);
}

// FUNCTION: IMPERIALISM 0x0050a6a0
void TMacViewMgr::RefreshCityCapabilityUiHandlesForActiveNation() {
  short nationId;
  unsigned int variant;
  if (IsTurnCooldownCounterActiveOrResetFlag() != 0) {
    return;
  }
  if (this == 0 || g_pCityOrderCapabilityState == 0) {
    return;
  }
  if (atlas68c != 0) {
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&atlas68c);
  }
  if (atlas690 != 0) {
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&atlas690);
  }
  nationId = g_pSimMgr->GetActiveNationId();
  if (nationId < 0) {
    return;
  }
  g_pUiViewManager->NoOpRuntimeUiCallback_005df3f0(3);
  nationId = g_pSimMgr->GetActiveNationId();
  variant = g_pCityOrderCapabilityState->orderCapRows277[nationId].techStatusByTechId[0x0f] != 0;
  nationId = g_pSimMgr->GetActiveNationId();
  if (g_pCityOrderCapabilityState->orderCapRows277[nationId].techStatusByTechId[0x18] != 0) {
    variant = 2;
  }
  nationId = g_pSimMgr->GetActiveNationId();
  atlas68c = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(nationId + 0x579 + variant * 7);
  nationId = g_pSimMgr->GetActiveNationId();
  atlas690 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(nationId + 0x564 + variant * 7);
}

// FUNCTION: IMPERIALISM 0x0050a820
void TMacViewMgr::BuildStrategicMapTileOverlayStripSurfaces800To807() {
  TQuickDrawSurfaceContext* savedContext;
  int savedFlags;
  int stripIndex;
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  stripIndex = 0;
  while (stripIndex < 8) {
    TBitmapResourceLoader** loaderHandle = CreateBitmapResourceLoaderHandle(stripIndex + 800);
    if (*loaderHandle == 0) {
      return;
    }
    TBitmapResourceLoader* loader = *loaderHandle;
    RECT resourceBounds;
    CopyRect(&resourceBounds, &loader->bitmapRect);
    g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&atlas694[stripIndex], 8,
                                                           &resourceBounds);
    SetActiveQuickDrawSurfaceContext(atlas694[stripIndex], savedFlags);
    ReturnConstantTrueQuickDrawFlag(GetSurfaceNodeSlot(atlas694[stripIndex]));
    QDLoadResource(loaderHandle);
    if (*loaderHandle != 0) {
      loader = *loaderHandle;
      loader->EnsureBitmapResourceLoadedAndCopyRectSize();
      loader->flags |= 1;
      ResetQuickDrawStrokeState();
      BlitBitmapResourceLoaderToActiveDc(loaderHandle, &resourceBounds);
      if (stripIndex == 0) {
        RebuildSurfaceRowsWithTemporaryRowBuffer();
      }
      loader = *loaderHandle;
      loader->ReleaseBitmapResource();
      loader->flags &= 0xfe;
      delete loader;
      ::operator delete(loaderHandle);
    }
    NoOpQuickDrawLifecycleHookB(GetSurfaceNodeSlot(atlas694[stripIndex]));
    stripIndex = stripIndex + 1;
  }
  SetActiveQuickDrawSurfaceContext(savedContext, savedFlags);
}

// FUNCTION: IMPERIALISM 0x0050a9f0
undefined TMacViewMgr::RenderOffscreenBitmapGridStripAndRestoreContext() {
  RECT atlasBounds;
  TQuickDrawSurfaceContext* savedContext;
  int savedFlags;
  int dstX;
  int dstY;
  int resourceId;
  int index;
  atlasBounds.left = 0;
  atlasBounds.top = 0;
  atlasBounds.right = 0xcc0;
  atlasBounds.bottom = 0x40;
  g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&atlas668, 8, &atlasBounds);
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  SetActiveQuickDrawSurfaceContext(atlas668, savedFlags);
  ReturnConstantTrueQuickDrawFlag(GetSurfaceNodeSlot(atlas668));
  ResetQuickDrawStrokeState();
  dstX = 0;
  dstY = 0;
  index = 0;
  while (index < 0x2a) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = dstY;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = dstY + 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(10000 + index, &blitRect);
    dstX = dstX + 0x40;
    if (dstX >= 0x80) {
      dstX = 0;
      dstY = dstY + 0x40;
    }
    index = index + 1;
  }
  dstX = 0;
  dstY = 0;
  index = 0;
  while (index < 4) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = dstY;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = dstY + 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(0x276e + index, &blitRect);
    dstX = dstX + 0x40;
    index = index + 1;
  }
  dstX = 0;
  dstY = 0;
  index = 0;
  while (index < 4) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = dstY;
    blitRect.right = dstX + 0x40;
    blitRect.bottom = dstY + 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(0x2774 + index, &blitRect);
    dstX = dstX + 0x40;
    index = index + 1;
  }
  {
    RECT blitRect;
    blitRect.left = 0;
    blitRect.top = 0;
    blitRect.right = 0x40;
    blitRect.bottom = 0x40;
    ResolveAndBlitBitmapResourceToActiveAtlas(0x277e, &blitRect);
  }
  NoOpQuickDrawLifecycleHookB(GetSurfaceNodeSlot(atlas668));
  SetActiveQuickDrawSurfaceContext(savedContext, savedFlags);

  atlasBounds.right = 0xa80;
  g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&atlas66c, 8, &atlasBounds);
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  SetActiveQuickDrawSurfaceContext(atlas66c, savedFlags);
  ReturnConstantTrueQuickDrawFlag(GetSurfaceNodeSlot(atlas66c));
  ResetQuickDrawStrokeState();
  dstX = 0x40;
  resourceId = 0x190;
  while (resourceId < 0x1ab) {
    if (resourceId != 0x195 && resourceId != 0x19e && resourceId != 0x1a7) {
      RECT blitRect;
      blitRect.left = dstX;
      blitRect.top = 0;
      blitRect.right = dstX + 0x40;
      blitRect.bottom = 0x40;
      ResolveAndBlitBitmapResourceToActiveAtlas(resourceId, &blitRect);
      dstX = dstX + 0x40;
    }
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
  NoOpQuickDrawLifecycleHookB(GetSurfaceNodeSlot(atlas66c));
  SetActiveQuickDrawSurfaceContext(savedContext, savedFlags);

  atlasBounds.right = 0xd7;
  atlasBounds.bottom = 0x78;
  g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&atlas670, 8, &atlasBounds);
  atlasBounds.right = 0x90;
  atlasBounds.bottom = 0x26;
  g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&atlas6b4, 8, &atlasBounds);
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  SetActiveQuickDrawSurfaceContext(atlas6b4, savedFlags);
  ReturnConstantTrueQuickDrawFlag(GetSurfaceNodeSlot(atlas6b4));
  ResetQuickDrawStrokeState();
  dstX = 0;
  resourceId = 0x23a;
  while (resourceId < 0x242) {
    RECT blitRect;
    blitRect.left = dstX;
    blitRect.top = 0;
    blitRect.right = dstX + 2;
    blitRect.bottom = 0x26;
    ResolveAndBlitBitmapResourceToActiveAtlas(resourceId, &blitRect);
    dstX = dstX + 2;
    resourceId = resourceId + 1;
  }
  NoOpQuickDrawLifecycleHookB(GetSurfaceNodeSlot(atlas6b4));
  SetActiveQuickDrawSurfaceContext(savedContext, savedFlags);

  if (atlas6b8 != 0) {
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&atlas6b8);
  }
  atlasBounds.left = 0;
  atlasBounds.top = 0;
  atlasBounds.right = 0;
  atlasBounds.bottom = 0;
  g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&atlas6b8, 8, &atlasBounds);
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  SetActiveQuickDrawSurfaceContext(atlas6b8, savedFlags);
  ReturnConstantTrueQuickDrawFlag(GetSurfaceNodeSlot(atlas6b8));
  ResetQuickDrawStrokeState();
  ResolveAndBlitBitmapResourceToActiveAtlas(0x244, &atlasBounds);
  NoOpQuickDrawLifecycleHookB(GetSurfaceNodeSlot(atlas6b8));
  SetActiveQuickDrawSurfaceContext(savedContext, savedFlags);

  index = 0;
  while (index < 0x10) {
    callback6bc[index].BuildBitmapMaskOpcodeBufferFromResourceRows(index + 0x2740, 0x40, 0x40,
                                                                   0x1680, 0x10);
    index = index + 1;
  }
  resourceId = 0x2760;
  while (resourceId < 0x2766) {
    callbackB3c[resourceId - 0x2760].BuildBitmapMaskOpcodeBufferFromResourceRows(
        resourceId - 0x26, 0x40, 0x40, 0x1680, 0x10);
    callbackC5c[resourceId - 0x2760].BuildBitmapMaskOpcodeBufferFromResourceRows(
        resourceId, 0x40, 0x40, 0x1680, 0x10);
    resourceId = resourceId + 1;
  }
  index = 0x10;
  while (index < 0x18) {
    callback6bc[index].BuildBitmapMaskOpcodeBufferFromResourceRows(index + 0x2756, 0x40, 0x40,
                                                                   0x1680, 0x10);
    index = index + 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050b5b0
void TMacViewMgr::ReloadBitmap244AndRefreshUiCaches() {
  g_pUiViewManager->NoOpRuntimeUiCallback_005df3f0(3);
  if (atlas6b8 != 0) {
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&atlas6b8);
  }
  atlas6b8 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x244);
  if (atlas688 != 0) {
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&atlas688);
  }
  LoadStrategicMapOverlayAtlas8699();
}

// FUNCTION: IMPERIALISM 0x0050b640
undefined TMacViewMgr::RenderTurnEventPalettePreviewSurfaceAndProgress() {
  RECT fillRect;
  TQuickDrawSurfaceContext* savedContext;
  int savedFlags;
  TBitmapSurfaceNode** surfaceObject;
  int pixelBase;
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
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  SetActiveQuickDrawSurfaceContext(atlas670, savedFlags);
  surfaceObject = static_cast<TBitmapSurfaceNode**>(GetSurfaceNodeSlot(atlas670));
  ReturnConstantTrueQuickDrawFlag(surfaceObject);
  ResetQuickDrawStrokeState();
  pixelBase = reinterpret_cast<int>(GetSurfaceNodePixelBits(surfaceObject));
  strideBytes = static_cast<ushort>((*surfaceObject)->stride) & 0x3fff;
  SetQuickDrawStrokeColor(0xffffff);
  g_pUiRuntimeContext->ApplyLegendSplitSlot34(0x32);
  FillRectWithQuickDrawBrushAndContextOffset(&fillRect);
  colOffset = 0;
  tileIndex = 0;
  while (tileIndex < 0x1950) {
    terrainCode = g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04;
    if (terrainCode < 0x17) {
      if (terrainCode == 0) {
        terrainCode = 0x3e;
      }
      paletteByte = static_cast<unsigned char>(
          g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(terrainCode));
      *reinterpret_cast<unsigned char*>(pixelBase + colOffset) = paletteByte;
      *reinterpret_cast<unsigned char*>(pixelBase + colOffset + 1) = paletteByte;
      *reinterpret_cast<unsigned char*>(pixelBase + strideBytes + colOffset) = paletteByte;
      *reinterpret_cast<unsigned char*>(pixelBase + strideBytes + colOffset + 1) = paletteByte;
    }
    colOffset = colOffset + 2;
    if (colOffset == 0xd8) {
      colOffset = 0;
      pixelBase = pixelBase + strideBytes * 2;
    }
    tileIndex = tileIndex + 1;
  }
  pixelBase = reinterpret_cast<int>(GetSurfaceNodePixelBits(surfaceObject));
  pixelBase = pixelBase + strideBytes * 2;
  scratchBuffer = new unsigned char[0x6540];
  if (scratchBuffer == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  {
    int copyRow = 0;
    unsigned char* scratchCursor = scratchBuffer;
    while (copyRow < 0x78) {
      unsigned char* srcCursor =
          reinterpret_cast<unsigned char*>(pixelBase + copyRow * strideBytes);
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
    char* rowStart = reinterpret_cast<char*>(pixelBase + 1);
    char* scratchRow = reinterpret_cast<char*>(scratchBuffer + 0x1b1);
    int edgeRow = 0x70;
    while (edgeRow != 0) {
      int edgeCol = 0xd6;
      char* compareRow = rowStart;
      while (edgeCol != 0) {
        char centerPixel = compareRow[0];
        char neighborPixel;
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
      scratchRow = scratchRow + 3;
      edgeRow = edgeRow - 1;
    }
  }
  {
    int copyRow = 0;
    unsigned char* scratchCursor = scratchBuffer;
    while (copyRow < 0x78) {
      unsigned char* dstCursor =
          reinterpret_cast<unsigned char*>(pixelBase + copyRow * strideBytes);
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
  NoOpQuickDrawLifecycleHookB(GetSurfaceNodeSlot(atlas670));
  SetActiveQuickDrawSurfaceContext(savedContext, savedFlags);
  RebuildSurfaceRowsWithTemporaryRowBuffer();
  reinterpret_cast<unsigned char*>(g_pGlobalMapState)[4] = 1;
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050b9e0
undefined TMacViewMgr::RebuildMapTileNeighborHighlightPolygonsForAllTiles() {
  int tileIndex = 0;
  int tileByteOffset = 0;
  RgnHandle* tileSlot = tileStateSlots;
  while (tileByteOffset < 0xfc00) {
    if (reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable)[tileByteOffset] != -1) {
      if (*tileSlot != 0) {
        DisposeRgn(*tileSlot);
        *tileSlot = 0;
      }
      *tileSlot = NewRgn();
      OpenRgn();
      char neighborCount =
          reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable)[tileByteOffset + 0x3a];
      int neighborIndex = 0;
      if (neighborCount > 0) {
        short* neighborCursor = reinterpret_cast<short*>(
            reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable) + tileByteOffset + 0x42);
        while (neighborIndex < neighborCount) {
          InvokeBuildHexNeighborHighlightPolygonForTile(neighborCursor[0], tileIndex);
          neighborIndex = neighborIndex + 1;
          neighborCursor = neighborCursor + 1;
        }
      }
      CloseRgn(*tileSlot);
    }
    tileByteOffset = tileByteOffset + 0xa8;
    tileIndex = tileIndex + 1;
    tileSlot = tileSlot + 1;
  }
  RebuildNationClipRegionsAndDispatchMapEvent();
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050bad0
undefined TMacViewMgr::RebuildNationClipRegionsAndDispatchMapEvent() {
  if (g_pSimMgr->numGreatPowers == 1) {
    g_pGameFlowState->DispatchTaggedGameStateEvent1F20(0x72656765, 0, 0xfffffffd);
  }
  if (tileStateSlots[0] != 0) {
    RgnHandle regionWrapper = NewRgn();
    int nationIndex = 0;
    while (nationIndex < 0x17) {
      SetEmptyRgn(regionWrapper);
      int tileByteOffset = 0;
      RgnHandle* tileSlot = tileStateSlots;
      while (tileByteOffset < 0xfc00) {
        if (reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable)[tileByteOffset] ==
            nationIndex) {
          UnionRgn(regionWrapper, *tileSlot, regionWrapper);
        }
        tileByteOffset = tileByteOffset + 0xa8;
        tileSlot = tileSlot + 1;
      }
      EnsureClipRegionWrapperAtSlotAndMergeSourceRegion(reinterpret_cast<undefined4>(regionWrapper),
                                                        static_cast<short>(nationIndex));
      nationIndex = nationIndex + 1;
    }
    DisposeRgn(regionWrapper);
    RenderTurnEventPalettePreviewSurfaceAndProgress();
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050bbc0
undefined TMacViewMgr::OrphanCallChain_C4_I35_0050bbc0(int* param_1, undefined4 param_2,
                                                       short param_3) {
  CityOrderSource* orderSource = reinterpret_cast<CityOrderSource*>(param_1);
  if (orderSource->QuerySellModeFlag1D8() != 0) {
    g_apNationStates[param_3]->SetDiplomacyState1c6ClampedToCounterA4(static_cast<short>(param_2),
                                                                      -1);
    return 0;
  }
  g_apNationStates[param_3]->SetDiplomacyState1c6ClampedToCounterA4(
      static_cast<short>(param_2), orderSource->QuerySellQuantity1D4());
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050bc50
undefined TMacViewMgr::SyncSellTaggedChildControlWithNationState(TView* view, short orderSlot,
                                                                 short nationIndex) {
  using turn_event_dialog::GoldCommitControl;
  using turn_event_dialog::TSellOrderRowControl;
  TSellOrderRowControl* row = static_cast<TSellOrderRowControl*>(view);
  view->DoPostCreate(0);
  *reinterpret_cast<short*>(reinterpret_cast<char*>(view) + 0x88) = orderSlot;
  if (g_pCityOrderCapabilityState->hasProductionOrder193 == 0 &&
      (orderSlot == 6 || orderSlot == 0xc)) {
    view->SetEnabled(0, 0);
  }
  short sellCount = g_apNationStates[nationIndex]->QueryNationMetricBySlot7C(orderSlot);
  // The clamp branch resets the nation index used by the trailing capacity check below to
  // 0 (matches the original: it reuses the same stack slot that held nationIndex).
  short effectiveNationIndex = nationIndex;
  if (sellCount > 0 && g_apNationStates[nationIndex]->tradeCapacity == 0) {
    g_apNationStates[nationIndex]->SetDiplomacyState1c6ClampedToCounterA4(orderSlot, 0);
    sellCount = 0;
    effectiveNationIndex = 0;
  }
  GoldCommitControl* sellControl =
      static_cast<GoldCommitControl*>(view->ResolveControlByTag(kControlTagSell));
  if (sellControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  if (sellCount < 0) {
    row->NotifySellValueUnavailable();
    sellControl->ConfigureGoldValueCells(0, 0);
    sellControl->SetEnabled(0, 1);
  } else {
    row->NotifySellValueValid();
  }
  if (sellCount > 0) {
    row->NotifySellValueActive();
    sellControl->ConfigureGoldValueCells(sellCount, 0);
    sellControl->SetEnabled(1, 1);
    return 0;
  }
  if (g_apNationStates[effectiveNationIndex]->tradeCapacity != 0) {
    row->NotifySellCapacityAvailable();
  }
  sellControl->ConfigureGoldValueCells(0, 0);
  sellControl->SetEnabled(0, 1);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050be30
TView* TMacViewMgr::ResolveTurnEventDialogOrFailAndInvokeSlot9C(int dialogId) {
  TView* dialog = g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(dialogId, 0);
  if (dialog == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UMacViewMgr.cpp", 0x917);
  }
  dialog->Open();
  return dialog;
}

// FUNCTION: IMPERIALISM 0x0050bea0
undefined TMacViewMgr::RefreshCityProductionDetailPanelAndArrowWidgets(word nationSlot) {
  TGreatPower* nation = g_apNationStates[nationSlot];
  TView* hostView = field04;
  CString scratch38;

  if (nationSlot == static_cast<word>(-1)) {
    TControl* panel = ResolveTaggedPanelOrFail(hostView, kTagCityProductionTotal);
    g_pSimMgr->GetString(0x2735, 0, &scratch38);
    panel->SetHoverHelpText(scratch38);

    TMyStaticText* textEntry = new TMyStaticText();

    int layoutHeight = 0xb;
    int layoutWidth = 0x14;
    int layoutPos = 0x3c;
    int layoutAnchor = 0xa2;
    int layoutOuter = 0x12;
    textEntry->InitializeTextEntryBaseAndOptionalStringResource(panel, &layoutAnchor, &layoutHeight,
                                                                5, 5, -1, 0);

    TUiTextStyleDescriptor styleDescriptor;
    BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xa, 0x2b67);
    textEntry->SetTextStyleAndMaybeRefresh(&styleDescriptor, 0);
    textEntry->SetTextAlignmentAndMaybeRefresh(0, 0);
    textEntry->controlTag = kTagDetailText;

    g_pSimMgr->GetString(0x2735, 1, &scratch38);
    textEntry->SetHoverHelpText(scratch38);

    short needCap = nation != 0 ? nation->needCapA6 : 0;
    SetPanelShortField(panel, 0x94, nation != 0 ? nation->needsOverCapFlag : 0);
    SetPanelShortField(panel, 0x96, needCap);
    SetPanelShortField(panel, 0x98, static_cast<short>(-1));
    return 0;
  }

  if (nationSlot == 1 || nationSlot == 7 || nationSlot == 10 || nationSlot == 0x10 ||
      nationSlot == 0x14) {
    return 0;
  }

  TCity* city = nation != 0 ? nation->city : 0;
  CString formatCurrent;
  CString formatTarget;
  CString formatProduction;
  CString formatField;
  CString bracketScratch;
  CString displayText;

  int summaryTag = GetTradeSummarySelectionTagByIndex(static_cast<short>(nationSlot));
  TControl* panel = ResolveTaggedPanelOrFail(hostView, static_cast<unsigned int>(summaryTag));

  short needTarget = 0;
  short needCurrent = 0;
  short showArrowWidgets = 0;
  short deficitCount = 0;
  short formatFieldValue = 0;
  bool useBracketOnlyPath = false;
  bool useSummaryPath = false;
  bool useProductionTailPath = false;

  switch (nationSlot) {
  case 0:
    needTarget = static_cast<short>(nation->needTargetByType[0] + nation->needTargetByType[1]);
    needCurrent = static_cast<short>(nation->needCurrentByType[0] + nation->needCurrentByType[1]);
    g_pSimMgr->GetString(0x2735, 2, &formatTarget);
    {
      int production = city->GetBuildingType(0);
      deficitCount =
          static_cast<short>(production * 2 - city->cityStockCottonB6 - city->cityStockWoolB8);
      formatCurrent.Format(reinterpret_cast<const char*>(kAddrDecimalFormat),
                           static_cast<int>(city->cityStockCottonB6) +
                               static_cast<int>(city->cityStockWoolB8));
      formatProduction.Format(reinterpret_cast<const char*>(kAddrDecimalFormat), production * 2);
      g_pSimMgr->GetString(0x2719, 0, &displayText);
    }
    break;
  case 2:
    needTarget = nation->needTargetByType[2];
    needCurrent = nation->needCurrentByType[2];
    g_pSimMgr->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    {
      int production = city->GetBuildingType(4);
      deficitCount = static_cast<short>(production * 2 - city->cityStockTimberBA);
      formatCurrent.Format(reinterpret_cast<const char*>(kAddrDecimalFormat),
                           static_cast<int>(city->cityStockTimberBA));
      formatTarget.Format(reinterpret_cast<const char*>(kAddrDecimalFormat), production * 2);
      g_pSimMgr->GetString(0x2719, 4, &displayText);
      formatFieldValue = city->cityStockTimberBA;
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 3:
  case 4:
    needTarget = nation->needTargetByType[nationSlot];
    needCurrent = nation->needCurrentByType[nationSlot];
    g_pSimMgr->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    {
      int production = city->GetBuildingType(2);
      deficitCount = static_cast<short>(production - (&city->cityStockCottonB6)[nationSlot]);
      formatCurrent.Format(reinterpret_cast<const char*>(kAddrDecimalFormat),
                           static_cast<int>((&city->cityStockCottonB6)[nationSlot]));
      formatTarget.Format(reinterpret_cast<const char*>(kAddrDecimalFormat), production);
      g_pSimMgr->GetString(0x2719, 2, &displayText);
      formatFieldValue = (&city->cityStockCottonB6)[nationSlot];
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 5:
    needTarget = nation->needTargetByType[5];
    needCurrent = nation->needCurrentByType[5];
    g_pSimMgr->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    formatCurrent.Format(reinterpret_cast<const char*>(kAddrDecimalFormat),
                         static_cast<int>(needCurrent));
    formatTarget.Format(reinterpret_cast<const char*>(kAddrDecimalFormat),
                        static_cast<int>(needTarget));
    g_pSimMgr->GetString(0x2719, 1, &displayText);
    ScanBracketExpressionsInto(&bracketScratch, displayText);
    useBracketOnlyPath = true;
    break;
  case 6:
    needTarget = nation->needTargetByType[6];
    needCurrent = nation->needCurrentByType[6];
    g_pSimMgr->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    {
      int production = city->GetBuildingType(6);
      deficitCount = static_cast<short>(production * 2 - city->cityStockOilC2);
      formatCurrent.Format(reinterpret_cast<const char*>(kAddrDecimalFormat),
                           static_cast<int>(city->cityStockOilC2));
      formatTarget.Format(reinterpret_cast<const char*>(kAddrDecimalFormat), production * 2);
      g_pSimMgr->GetString(0x2719, 6, &displayText);
      formatFieldValue = city->cityStockOilC2;
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 8:
    needTarget = nation->needTargetByType[8];
    needCurrent = nation->needCurrentByType[8];
    g_pSimMgr->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    {
      int production = city->GetBuildingType(1);
      deficitCount = static_cast<short>(production * 2 - city->cityStockFabricC6);
      formatCurrent.Format(reinterpret_cast<const char*>(kAddrDecimalFormat),
                           static_cast<int>(city->cityStockFabricC6));
      formatTarget.Format(reinterpret_cast<const char*>(kAddrDecimalFormat), production * 2);
      g_pSimMgr->GetString(0x2719, 1, &displayText);
      formatFieldValue = city->cityStockFabricC6;
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 9:
    needTarget = nation->needTargetByType[9];
    needCurrent = nation->needCurrentByType[9];
    g_pSimMgr->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    {
      int production = city->GetBuildingType(5);
      deficitCount = static_cast<short>(production * 2 - city->cityStockLumberC8);
      formatCurrent.Format(reinterpret_cast<const char*>(kAddrDecimalFormat),
                           static_cast<int>(city->cityStockLumberC8));
      formatTarget.Format(reinterpret_cast<const char*>(kAddrDecimalFormat), production * 2);
      g_pSimMgr->GetString(0x2719, 5, &displayText);
      formatFieldValue = city->cityStockLumberC8;
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 0xb:
    needTarget = nation->needTargetByType[0xb];
    needCurrent = nation->needCurrentByType[0xb];
    g_pSimMgr->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    {
      int production = city->GetBuildingType(3);
      deficitCount = static_cast<short>(production * 2 - city->cityStockSteelCC);
      formatCurrent.Format(reinterpret_cast<const char*>(kAddrDecimalFormat),
                           static_cast<int>(city->cityStockSteelCC));
      formatTarget.Format(reinterpret_cast<const char*>(kAddrDecimalFormat), production * 2);
      g_pSimMgr->GetString(0x2719, 3, &displayText);
      formatFieldValue = city->cityStockSteelCC;
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 0xc:
    needTarget = nation->needTargetByType[0xc];
    needCurrent = nation->needCurrentByType[0xc];
    g_pSimMgr->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    {
      int production = city->GetBuildingType(0xb);
      deficitCount = static_cast<short>(production * 2 - city->cityStockFuelCE);
      formatCurrent.Format(reinterpret_cast<const char*>(kAddrDecimalFormat),
                           static_cast<int>(city->cityStockFuelCE));
      formatTarget.Format(reinterpret_cast<const char*>(kAddrDecimalFormat), production * 2);
      g_pSimMgr->GetString(0x2719, 0xb, &displayText);
      formatFieldValue = city->cityStockFuelCE;
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 0xd:
  case 0xe:
  case 0xf:
    needTarget = nation->needTargetByType[nationSlot];
    needCurrent = nation->needCurrentByType[nationSlot];
    g_pSimMgr->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    formatCurrent.Format(reinterpret_cast<const char*>(kAddrDecimalFormat),
                         static_cast<int>(needCurrent));
    formatTarget.Format(reinterpret_cast<const char*>(kAddrDecimalFormat),
                        static_cast<int>(needTarget));
    g_pSimMgr->GetString(0x2719, 8, &displayText);
    ScanBracketExpressionsInto(&bracketScratch, displayText);
    useBracketOnlyPath = true;
    break;
  case 0x11:
  case 0x12:
    needTarget = nation->needTargetByType[nationSlot];
    needCurrent = nation->needCurrentByType[nationSlot];
    g_pSimMgr->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    {
      short* summary = city->GetCitySummaryRecordSlot74();
      short summaryValue = summary[nationSlot];
      formatTarget.Format(reinterpret_cast<const char*>(kAddrDecimalFormat),
                          static_cast<int>(summaryValue));
      deficitCount = static_cast<short>(summaryValue - (&city->cityStockCottonB6)[nationSlot]);
      formatCurrent.Format(reinterpret_cast<const char*>(kAddrDecimalFormat),
                           static_cast<int>((&city->cityStockCottonB6)[nationSlot]));
      g_pSimMgr->GetString(0x2735, 7, &displayText);
      ScanBracketExpressionsInto(&bracketScratch, displayText);
      displayText = bracketScratch;
      showArrowWidgets = 1;
      useSummaryPath = true;
    }
    break;
  case 0x13:
    needTarget =
        static_cast<short>(nation->needTargetByType[0x13] + nation->needTargetByType[0x14]);
    needCurrent =
        static_cast<short>(nation->needCurrentByType[0x13] + nation->needCurrentByType[0x14]);
    g_pSimMgr->GetString(0x2735, 3, &formatTarget);
    {
      short* summary = city->GetCitySummaryRecordSlot74();
      short summaryValue = summary[0x14];
      formatTarget.Format(reinterpret_cast<const char*>(kAddrDecimalFormat),
                          static_cast<int>(summaryValue));
      deficitCount =
          static_cast<short>(summaryValue - city->cityStockFishDC - city->cityStockLivestockDE);
      formatFieldValue = static_cast<short>(city->cityStockFishDC + city->cityStockLivestockDE);
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 0x15:
    needTarget = nation->needTargetByType[0x15];
    needCurrent = nation->needCurrentByType[0x15];
    g_pSimMgr->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    g_pSimMgr->GetString(500, 0, &formatCurrent);
    g_pSimMgr->GetString(0x2735, 9, &displayText);
    ScanBracketExpressionsInto(&bracketScratch, displayText);
    useBracketOnlyPath = true;
    break;
  case 0x16:
    needTarget = nation->needTargetByType[0x16];
    needCurrent = nation->needCurrentByType[0x16];
    g_pSimMgr->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    g_pSimMgr->GetString(200, 0, &formatCurrent);
    g_pSimMgr->GetString(0x2735, 9, &displayText);
    ScanBracketExpressionsInto(&bracketScratch, displayText);
    useBracketOnlyPath = true;
    break;
  default:
    needTarget = static_cast<short>(nationSlot);
    needCurrent = static_cast<short>(nationSlot);
    showArrowWidgets = static_cast<short>(nationSlot);
    deficitCount = static_cast<short>(nationSlot);
    break;
  }

  if (useBracketOnlyPath) {
    showArrowWidgets = 0;
    displayText = bracketScratch;
  } else if (!useSummaryPath) {
    if (useProductionTailPath) {
      formatField.Format(reinterpret_cast<const char*>(kAddrDecimalFormat),
                         static_cast<int>(formatFieldValue));
    }
    g_pSimMgr->GetString(0x2735, 7, &formatTarget);
    ScanBracketExpressionsInto(&bracketScratch, displayText);
    displayText = bracketScratch;
  }

  if (showArrowWidgets == 0) {
    SetPanelShortField(panel, 0x98, static_cast<short>(-1));
  } else if (deficitCount < 1) {
    SetPanelShortField(panel, 0x98, 0);
  } else {
    SetPanelShortField(panel, 0x98, deficitCount);
  }

  panel->SetHoverHelpText(displayText);

  if (needCurrent == 0) {
    panel->SetEnabled(0, 0);
    TControl* leftArrow = ResolveTaggedChildOrFail(panel, kTagArrowLeft);
    leftArrow->DispatchUiCommand19ToParent();
    TControl* rightArrow = ResolveTaggedChildOrFail(panel, kTagArrowRight);
    rightArrow->DispatchUiCommand19ToParent();
    return 0;
  }

  TControl* leftSource = ResolveTaggedChildOrFail(panel, kTagArrowLeft);
  int leftLayout0[2];
  int leftLayout1[2];
  CopyViewLayoutFieldsToStack(leftLayout0, leftLayout1, leftSource);
  leftSource->DispatchUiCommand19ToParent();

  TRightLeftView* leftView = new TRightLeftView();
  leftView->InitializeUiResourceEntryFrameAndParent(0, panel, leftLayout1, leftLayout0, 5, 5, 0);
  leftView->controlTag = kTagArrowLeft;

  TControl* rightSource = ResolveTaggedChildOrFail(panel, kTagArrowRight);
  int rightLayout0[2];
  int rightLayout1[2];
  CopyViewLayoutFieldsToStack(rightLayout0, rightLayout1, rightSource);
  rightSource->DispatchUiCommand19ToParent();

  TRightLeftView* rightView = new TRightLeftView();
  rightView->InitializeUiResourceEntryFrameAndParent(0, panel, rightLayout1, rightLayout0, 5, 5, 0);
  rightView->controlTag = kTagArrowRight;

  TMyStaticText* textEntry = new TMyStaticText();

  int textHeight = 0xb;
  int textWidth = 0x14;
  int textPos = 0x98;
  int textAnchor = 0x46;
  int textOuter = 0x12;
  textEntry->InitializeTextEntryBaseAndOptionalStringResource(panel, &textPos, &textHeight, 5, 5,
                                                              -1, 0);

  TUiTextStyleDescriptor styleDescriptor;
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xa, 0x2b67);
  textEntry->SetTextStyleAndMaybeRefresh(&styleDescriptor, 0);
  textEntry->SetTextAlignmentAndMaybeRefresh(0, 0);
  textEntry->controlTag = kTagDetailText;

  g_pSimMgr->GetString(0x2735, 4, &scratch38);
  textEntry->SetHoverHelpText(scratch38);

  if (nationSlot == 0x15 || nationSlot == 0x16) {
    TMyStaticText* valueEntry = new TMyStaticText();

    int valueHeight = 0xb;
    int valueWidth = 0x14;
    int valuePos = 0x3c;
    int valueAnchor = 0x32;
    valueEntry->InitializeTextEntryBaseAndOptionalStringResource(panel, &valuePos, &valueHeight, 5,
                                                                 5, -1, 0);
    valueEntry->SetTextStyleAndMaybeRefresh(&styleDescriptor, 0);
    valueEntry->SetTextAlignmentAndMaybeRefresh(0, 0);
    valueEntry->controlTag = kTagDetailValue;
  }

  SetPanelShortField(panel, 0x92, static_cast<short>(nationSlot));
  SetPanelShortField(panel, 0x94, needTarget);
  SetPanelShortField(panel, 0x96, needCurrent);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050d310
void TMacViewMgr::DispatchTurnEvent3B8AndWaitForCompletionFlag(int unusedArg1, int unusedArg2) {
  TView* dialog = field04;
  g_pUiRuntimeContext->DispatchTurnEventSlot4C(0x3b8, 0);
  short completionFlag = static_cast<short>(dialog->field14);
  while (completionFlag == 0) {
    PumpUiMessagesAndBackgroundTasks(1);
    completionFlag = static_cast<short>(dialog->field14);
  }
}

// FUNCTION: IMPERIALISM 0x0050d360
undefined TMacViewMgr::CreateCityBuildingDialogBySlot(int param_1, undefined4 param_2,
                                                      undefined4 param_3, int arg4, int arg5) {
  TurnEventDialogNode* dialog = reinterpret_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(param_1 + 0x23f0));
  GoldDialogControl* goldControl =
      reinterpret_cast<GoldDialogControl*>(dialog->ResolveControlByTag(0x444c4f47));
  if (goldControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  goldControl->InvokeSlot1D0FourParam(reinterpret_cast<int>(this), param_2, param_3, param_1);
  dialog->controlValue3c = 0x65;
  dialog->DispatchSlot9C();
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050d470
undefined TMacViewMgr::OrphanCallChain_C10_I80_0050d470(int param_1, undefined4 param_2, int arg3,
                                                        int arg4, int arg5, int arg6, int arg7) {
  TurnEventDialogNode* dialog = reinterpret_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(param_1 + 0x23f0));
  GoldDialogControl* goldControl =
      reinterpret_cast<GoldDialogControl*>(dialog->ResolveControlByTag(0x444c4f47));
  if (goldControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  goldControl->InvokeSlot1D0FourParam(reinterpret_cast<int>(this), param_2, param_1, param_1);
  dialog->controlValue3c = 0x65;
  dialog->InvokeSlotF0WithPair(static_cast<short>(reinterpret_cast<int>(this)),
                               static_cast<short>(param_1));
  dialog->DispatchSlot9C();
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050d5b0
undefined TMacViewMgr::OrphanCallChain_C9_I49_0050d5b0(int param_1, int arg2, int arg3) {
  TurnEventDialogNode* dialog = reinterpret_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x2404));
  GoldDialogControl* goldControl =
      reinterpret_cast<GoldDialogControl*>(dialog->ResolveControlByTag(0x444c4f47));
  if (goldControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  goldControl->InvokeSlot1CC(reinterpret_cast<int>(this), static_cast<int>(param_1), param_1);
  dialog->ShowTurnEventDialog(1);
  dialog->RefreshTurnEventDialog();
  dialog->InvokeSlotA0();
  goldControl->InvokeSlot1D0OneParam(dialog->QueryTurnEventContentObject());
  dialog->InvokeSlot1C();
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050d680
void TMacViewMgr::EnsureClipRegionWrapperAtSlotAndMergeSourceRegion(undefined4 param_1,
                                                                    short param_2) {
  if (regionSlots[param_2] == 0) {
    regionSlots[param_2] = NewRgn();
  }
  CopyRgn(reinterpret_cast<RgnHandle>(param_1), regionSlots[param_2]);
}

// FUNCTION: IMPERIALISM 0x0050d6c0
undefined TMacViewMgr::MacViewMgrSlot24(CPoint* point, short regionIndex) {
  if (regionSlots[regionIndex] != 0) {
    return QueryPointInsideHitRegion(point->x, point->y, regionSlots[regionIndex]);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050d700
undefined TMacViewMgr::RenderOffscreenBitmapTileSpanAndRestoreContext(int param_1) {
  TQuickDrawSurfaceContext* savedContext;
  int savedFlags;
  RECT resourceBounds;
  // The original reuses the incoming argument's stack slot as the out-context of
  // InitializeBitmapSurfaceContextWithRetry; the previous port misread that slot as
  // resourceBounds.right and passed the rect width around as a "context".
  TQuickDrawSurfaceContext* tileSurface = 0;
  regionSlots[param_1] = NewRgn();
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  TBitmapResourceLoader** loaderHandle = CreateBitmapResourceLoaderHandle(param_1 + 4000);
  CopyRect(&resourceBounds, &(*loaderHandle)->bitmapRect);
  g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&tileSurface, 1, &resourceBounds);
  SetActiveQuickDrawSurfaceContext(tileSurface, savedFlags);
  ReturnConstantTrueQuickDrawFlag(GetSurfaceNodeSlot(tileSurface));
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
      static_cast<TBitmapSurfaceNode**>(GetSurfaceNodeSlot(tileSurface));
  // The region rebuild consumes the node itself (it reads node->dib at +0x1c).
  if (BitMapToRegion(regionSlots[param_1], *surfaceHandle) != 0) {
    BitMapToRegion(regionSlots[param_1], *surfaceHandle);
    BitMapToRegion(regionSlots[param_1], *surfaceHandle);
  }
  g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&tileSurface);
  // Faithful to the original: the slot is already zeroed here, so this reads
  // *(0 + 0x24) — benign on the Win9x null page the game shipped against.
  NoOpQuickDrawLifecycleHookB(GetSurfaceNodeSlot(tileSurface));
  SetActiveQuickDrawSurfaceContext(savedContext, savedFlags);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050d8d0
void TMacViewMgr::OrphanLeaf_NoCall_Ins06_0050d8d0() {
  if (field04 != 0) {
    field04->InvalidateOffsetRegionUsingChildClipRect(0);
  }
}

// FUNCTION: IMPERIALISM 0x0050d8f0
void TMacViewMgr::OrphanLeaf_NoCall_Ins06_0050d8f0(short param_1) {
  if (field04 != 0) {
    *reinterpret_cast<int*>(reinterpret_cast<char*>(field04) + 0xac + param_1 * 4) = 0;
  }
}

// FUNCTION: IMPERIALISM 0x0050d920
void TMacViewMgr::OrphanCallChain_C1_I10_0050d920() {
  if (field04 != 0) {
    field04->RefreshCityProductionViewStateFromContext(0);
  }
  field04 = 0;
}

// FUNCTION: IMPERIALISM 0x0050d950
void TMacViewMgr::MacViewMgrSlot1B() {
  TView* hostView = g_pDisplayMgr->activeDialog;
  GoldDialogControl* goldControl =
      reinterpret_cast<GoldDialogControl*>(hostView->ResolveControlByTag(0x444c4f47));
  if (goldControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  goldControl->gold71();
  goldControl->SetGoldControlStateByResource(0, 0);
  InvokeCallObjectOffset24Vslot54IfPresent();
}

// FUNCTION: IMPERIALISM 0x0050d9e0
undefined TMacViewMgr::CopySpriteSurfaceToStrideBuffer(TBitmapResourceLoader** loaderHandle,
                                                       undefined4* param_2, short param_3) {
  int spriteHeader = reinterpret_cast<int>((*loaderHandle)->bitmapResource);
  undefined4* srcRow = *reinterpret_cast<undefined4**>(spriteHeader + 0xc);
  short srcStridePacked =
      *reinterpret_cast<short*>(*reinterpret_cast<int*>(spriteHeader + 0x10) + 4);
  unsigned int rowWidth =
      *reinterpret_cast<unsigned int*>(*reinterpret_cast<int*>(spriteHeader + 0x10) + 4);
  int rowCount = *reinterpret_cast<int*>(*reinterpret_cast<int*>(spriteHeader + 0x10) + 8);
  if (rowCount < 1) {
    rowCount = -rowCount;
  }
  while (rowCount != 0) {
    undefined4* srcPixel = srcRow;
    undefined4* dstPixel = param_2;
    unsigned int words = rowWidth >> 2;
    while (words != 0) {
      *dstPixel = *srcPixel;
      srcPixel = srcPixel + 1;
      dstPixel = dstPixel + 1;
      words = words - 1;
    }
    unsigned int tail = rowWidth & 3;
    while (tail != 0) {
      *(unsigned char*)dstPixel = *(unsigned char*)srcPixel;
      srcPixel = reinterpret_cast<undefined4*>(reinterpret_cast<char*>(srcPixel) + 1);
      dstPixel = reinterpret_cast<undefined4*>(reinterpret_cast<char*>(dstPixel) + 1);
      tail = tail - 1;
    }
    param_2 = reinterpret_cast<undefined4*>(reinterpret_cast<char*>(param_2) + param_3);
    srcRow = reinterpret_cast<undefined4*>(reinterpret_cast<char*>(srcRow) +
                                           static_cast<short>(srcStridePacked + 3U & 0xfffc));
    rowCount = rowCount - 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050da80
undefined TMacViewMgr::BlitMapOverlayGlyphStrip32x24SkipMask10(TBitmapSurfaceNode** dstSurface,
                                                               short param_2, short param_3,
                                                               short param_4) {
  TBitmapSurfaceNode** atlasSurface;
  short srcRowOffset;
  if (param_2 < 100) {
    atlasSurface = static_cast<TBitmapSurfaceNode**>(GetSurfaceNodeSlot(atlas674));
    srcRowOffset = static_cast<short>(param_2 << 5);
  } else {
    atlasSurface = static_cast<TBitmapSurfaceNode**>(GetSurfaceNodeSlot(atlas680));
    srcRowOffset = static_cast<short>((param_2 - 100) * 0x20);
  }
  ushort dstStrideRaw = static_cast<ushort>((*dstSurface)->stride);
  ReturnConstantTrueQuickDrawFlag(atlasSurface);
  int srcPixels = reinterpret_cast<int>(GetSurfaceNodePixelBits(atlasSurface));
  ushort srcStrideRaw = static_cast<ushort>((*atlasSurface)->stride);
  int dstPixels = reinterpret_cast<int>(GetSurfaceNodePixelBits(dstSurface));
  int dstStrideBytes = static_cast<int>(static_cast<short>(dstStrideRaw & 0x3fff));
  char* srcRow = reinterpret_cast<char*>(srcPixels + srcRowOffset);
  char* dstRow = reinterpret_cast<char*>(dstPixels + param_4 * dstStrideBytes + param_3);
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
  NoOpQuickDrawLifecycleHookB(atlasSurface);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050dd40
void TMacViewMgr::DrawStrategicMapUnitIcon(TBitmapSurfaceNode** pDstSurface, short nIconVariant,
                                           short nDstX, short nYShift) {
  TBitmapSurfaceNode** atlasSurface =
      static_cast<TBitmapSurfaceNode**>(GetSurfaceNodeSlot(unitIconAtlas));
  ReturnConstantTrueQuickDrawFlag(atlasSurface);
  int srcPixels = reinterpret_cast<int>(GetSurfaceNodePixelBits(atlasSurface));
  ushort srcStrideRaw = static_cast<ushort>((*atlasSurface)->stride);
  int dstPixels = reinterpret_cast<int>(GetSurfaceNodePixelBits(pDstSurface));
  int dstStrideBytes =
      static_cast<int>(static_cast<short>(static_cast<ushort>((*pDstSurface)->stride) & 0x3fff));
  char* srcRow = reinterpret_cast<char*>(srcPixels + static_cast<short>(nIconVariant * 0x14));
  char* dstRow = reinterpret_cast<char*>(dstPixels + (0x28 - nYShift) * dstStrideBytes +
                                         static_cast<int>(nDstX));
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
  NoOpQuickDrawLifecycleHookB(atlasSurface);
}

// FUNCTION: IMPERIALISM 0x0050df40
void TMacViewMgr::DrawStrategicMapUnitIconOverlay(TBitmapSurfaceNode** pDstSurface,
                                                  ushort wOverlayIconId, short nVariantRow,
                                                  short nDstX, short nYShift) {
  if (nVariantRow <= 0) {
    return;
  }
  short overlaySourceRow =
      reinterpret_cast<short*>(kAddrStrategicMapOverlaySourceRowByIconId)[wOverlayIconId];
  if (overlaySourceRow < 0) {
    return;
  }
  TBitmapSurfaceNode** atlasSurface =
      static_cast<TBitmapSurfaceNode**>(GetSurfaceNodeSlot(unitOverlayAtlas));
  ReturnConstantTrueQuickDrawFlag(atlasSurface);
  int srcPixels = reinterpret_cast<int>(GetSurfaceNodePixelBits(atlasSurface));
  ushort srcStrideRaw = static_cast<ushort>((*atlasSurface)->stride);
  int dstPixels = reinterpret_cast<int>(GetSurfaceNodePixelBits(pDstSurface));
  int dstStrideBytes =
      static_cast<int>(static_cast<short>(static_cast<ushort>((*pDstSurface)->stride) & 0x3fff));
  char* srcRow = reinterpret_cast<char*>(srcPixels + overlaySourceRow * (srcStrideRaw & 0x3fff));
  char* dstRow = reinterpret_cast<char*>(dstPixels + (0x28 - nYShift) * dstStrideBytes +
                                         static_cast<int>(nDstX));
  int rowsRemaining = 0x1a;
  do {
    int colsRemaining = 0x26;
    char* dstPixel = dstRow;
    char* srcPixel = srcRow;
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
  NoOpQuickDrawLifecycleHookB(atlasSurface);
}

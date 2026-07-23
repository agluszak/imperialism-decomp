#include "game/TMacViewMgr.h"
#include "game/map_overlay_geometry.h"

#include "game/turn_event_dialog_provisional.h"

#include <new>

#include "game/bitmap_descriptor_helpers.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/quickdraw_regions.h"
#include "game/TAnimation.h"
#include "game/TAnimator.h"
#include "game/TAssetMgr.h"
#include "game/TBitmapResourceLoader.h"
#include "game/TBuildingConstructionView.h"
#include "game/TBuildingView.h"
#include "game/CDib.h"
#include "game/TCity.h"
#include "game/TCityProductionView.h"
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

static bool QueryPointInsideHitRegion(short x, short y, RgnHandle region) {
  CPoint point;
  point.x = x;
  point.y = y;
  return PtInRgn(&point, region);
}

static void InvokeBuildHexNeighborHighlightPolygonForTile(short tileId, int tileIndex) {
  BuildHexNeighborHighlightPolygonForTile(tileId, tileIndex);
}

// The loader's original vtable has no destructor slot; every caller owns this exact type.
IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
void ReleaseBitmapLoaderHandle(TBitmapResourceLoader** loaderHandle) {
  if (loaderHandle == nullptr) {
    return;
  }
  delete *loaderHandle;
  delete loaderHandle;
}
IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE

void ResolveAndBlitBitmapResourceToActiveAtlas(int resourceId, RECT* dstRect) {
  TBitmapResourceLoader** loaderHandle = CreateBitmapResourceLoaderHandle(resourceId);
  QDLoadResource(loaderHandle);
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

// Provisional turn-event dialog / GOLD control interfaces are shared with TViewMgr.cpp
// via one header so the two copies can't drift (bd imperialism-decomp-hpd.7).
using turn_event_dialog::CityOrderSource;
using turn_event_dialog::GoldDialogControl;
using turn_event_dialog::TurnEventDialogNode;

} // namespace

// FUNCTION: IMPERIALISM 0x004d4ff0
void StrategicMapCallbackRecord::ApplyBitmapMaskToPixelBuffer(unsigned char* destinationPixels) {
  unsigned char* instruction = opcodeBytes00.Data();
  unsigned char* end = instruction + opcodeBytes00.Count();
  unsigned char* destinationBase = destinationPixels;

  while (instruction < end) {
    unsigned char opcode = *instruction++;
    if (opcode == 0xc3) {
      return;
    }
    if (opcode == 0x05 && end - instruction >= 4) {
      unsigned int advance = static_cast<unsigned int>(instruction[0]) |
                             (static_cast<unsigned int>(instruction[1]) << 8) |
                             (static_cast<unsigned int>(instruction[2]) << 16) |
                             (static_cast<unsigned int>(instruction[3]) << 24);
      destinationBase += advance;
      instruction += 4;
      continue;
    }
    if (opcode == 0xc6 && end - instruction >= 3 && instruction[0] == 0x40) {
      signed char displacement = static_cast<signed char>(instruction[1]);
      destinationBase[displacement] = instruction[2];
      instruction += 3;
      continue;
    }
    if (opcode == 0x66 && end - instruction >= 5 && instruction[0] == 0xc7 &&
        instruction[1] == 0x40) {
      signed char displacement = static_cast<signed char>(instruction[2]);
      destinationBase[displacement] = instruction[3];
      destinationBase[displacement + 1] = instruction[4];
      instruction += 5;
      continue;
    }
    if (opcode == 0xc7 && end - instruction >= 6 && instruction[0] == 0x40) {
      signed char displacement = static_cast<signed char>(instruction[1]);
      memcpy(destinationBase + displacement, instruction + 2, 4);
      instruction += 6;
      continue;
    }
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004d5090
void StrategicMapCallbackRecord::BuildBitmapMaskOpcodeBufferFromResourceRows(
    int resourceId, short width, short height, int destinationRowStride,
    unsigned char transparentPixel) {
  destinationRowStride2c = destinationRowStride;

  CDib* dib = g_pModuleLibraryCacheState->LoadBmpResourceByIdCached(
      static_cast<unsigned short>(resourceId));
  unsigned char* row = static_cast<unsigned char*>(dib->m_dibBits);
  int sourceRowStride = (dib->m_pInfoHeader->bmiHeader.biWidth + 3) & 0xfffffffc;
  int generatedBaseOffset = 0;

  opcodeAppendCursor10 = 0;
  opcodeBytes00.RemoveAll();
  opcodeAlignmentOffset14 = 0;
  hadTrailingPadding18 = 0;

  int y = 0;
  while (y < height) {
    int x = 0;
    while (x < width) {
      unsigned char pixel = row[x];
      if (pixel != transparentPixel) {
        int destinationOffset = y * destinationRowStride + x;
        int displacement = destinationOffset - generatedBaseOffset;
        if (displacement > 0x7f) {
          int advance = displacement;
          AppendOpcodeByte(0x05);
          AppendOpcodeByte(advance);
          AppendOpcodeByte(advance >> 8);
          AppendOpcodeByte(advance >> 16);
          AppendOpcodeByte(advance >> 24);
          generatedBaseOffset = destinationOffset;
          displacement = 0;
        }
        AppendOpcodeByte(0xc6);
        AppendOpcodeByte(0x40);
        AppendOpcodeByte(displacement);
        AppendOpcodeByte(pixel);
      }
      x = x + 1;
    }
    row = row + sourceRowStride;
    y = y + 1;
  }

  g_pModuleLibraryCacheState->ReleaseRecordById(static_cast<short>(resourceId));
  AppendOpcodeByte(0xc3);
}

// FUNCTION: IMPERIALISM 0x004d5580
StrategicMapCallbackRecord* StrategicMapCallbackRecord::AppendOpcodeByte(int value) {
  unsigned int index = static_cast<unsigned int>(opcodeAppendCursor10);
  opcodeAppendCursor10 = static_cast<int>(index) + 1;
  opcodeBytes00[index] = static_cast<unsigned char>(value);
  return this;
}

// FUNCTION: IMPERIALISM 0x004d5610
void StrategicMapCallbackRecord::AppendOpcodeBytePair(int value) {
  AppendOpcodeByte((value >> 8) & 0xff);
  AppendOpcodeByte(value & 0xff);
}

// FUNCTION: IMPERIALISM 0x004d5720
void StrategicMapCallbackRecord::FinalizeOpcodeBufferAlignment() {
  unsigned char* alignmentProbe = &opcodeBytes00[opcodeAlignmentOffset14];
  opcodeAlignmentOffset14 = reinterpret_cast<unsigned int>(alignmentProbe) & 3;
  if (opcodeAlignmentOffset14 != 0) {
    opcodeBytes00.Add(0);
    opcodeBytes00.Add(0);
    opcodeBytes00.Add(0);
    opcodeBytes00.Compact();
    alignmentProbe = &opcodeBytes00[opcodeAlignmentOffset14];
    opcodeAlignmentOffset14 = reinterpret_cast<unsigned int>(alignmentProbe) & 3;
  }

  if (opcodeAlignmentOffset14 != 0) {
    int payloadByteCount = opcodeBytes00.GetSize() - 3;
    for (int sourceIndex = 0; sourceIndex < payloadByteCount; ++sourceIndex) {
      unsigned char value = opcodeBytes00[sourceIndex];
      opcodeBytes00[sourceIndex + opcodeAlignmentOffset14] = value;
    }
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
TMacViewMgr::~TMacViewMgr() {}

// FUNCTION: IMPERIALISM 0x00509f20
void TMacViewMgr::InitializeStrategicMapViewSystem() {
  g_pUiViewManager->OpenFilesFor(3);
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
  g_pStrategicMapViewSystem = 0;
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
  if (this == 0 || g_pCityOrderCapabilityState == 0) {
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
  g_pUiViewManager->OpenFilesFor(3);
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
}

// FUNCTION: IMPERIALISM 0x0050b5b0
void TMacViewMgr::ReloadBitmap244AndRefreshUiCaches() {
  g_pUiViewManager->OpenFilesFor(3);
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
  g_pUiRuntimeContext->SetForeColor(0x32);
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
          g_pUiRuntimeContext->GetColor(static_cast<short>(terrainCode)));
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
      unsigned char* srcCursor = surfaceBase + copyRow * strideBytes;
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
    char* rowStart = reinterpret_cast<char*>(smoothingBase + 1);
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
      unsigned char* dstCursor = surfaceBase + copyRow * strideBytes;
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
  (*GetGWorldPixMap(atlas670))->dib->FlipScanlineOrder();
  g_pGlobalMapState->strategicMapPalettePreviewReady04 = 1;
}

// FUNCTION: IMPERIALISM 0x0050b9e0
void TMacViewMgr::RebuildMapTileNeighborHighlightPolygonsForAllTiles() {
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
}

// FUNCTION: IMPERIALISM 0x0050bad0
void TMacViewMgr::RebuildNationClipRegionsAndDispatchMapEvent() {
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
      EnsureClipRegionWrapperAtSlotAndMergeSourceRegion(regionWrapper,
                                                        static_cast<short>(nationIndex));
      nationIndex = nationIndex + 1;
    }
    DisposeRgn(regionWrapper);
    RenderTurnEventPalettePreviewSurfaceAndProgress();
  }
}

// FUNCTION: IMPERIALISM 0x0050bbc0
void TMacViewMgr::ApplySellOrderRowToNationState(int* param_1, int param_2, short param_3) {
  CityOrderSource* orderSource = reinterpret_cast<CityOrderSource*>(param_1);
  if (orderSource->QuerySellModeFlag1D8() != 0) {
    g_apNationStates[param_3]->SetDiplomacyState1c6ClampedToCounterA4(static_cast<short>(param_2),
                                                                      -1);
    return;
  }
  g_apNationStates[param_3]->SetDiplomacyState1c6ClampedToCounterA4(
      static_cast<short>(param_2), orderSource->QuerySellQuantity1D4());
}

// FUNCTION: IMPERIALISM 0x0050bc50
void TMacViewMgr::SyncSellTaggedChildControlWithNationState(TView* view, short orderSlot,
                                                            short nationIndex) {
  using turn_event_dialog::GoldCommitControl;
  using turn_event_dialog::TSellOrderRowControl;
  TSellOrderRowControl* row = static_cast<TSellOrderRowControl*>(view);
  view->DoPostCreate(0);
  *reinterpret_cast<short*>(reinterpret_cast<char*>(view) + 0x88) = orderSlot;
  if (g_pCityOrderCapabilityState->perTechUnlockFlag180[TTechMgr::kProductionOrderTechId] == 0 &&
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
    return;
  }
  if (g_apNationStates[effectiveNationIndex]->tradeCapacity != 0) {
    row->NotifySellCapacityAvailable();
  }
  sellControl->ConfigureGoldValueCells(0, 0);
  sellControl->SetEnabled(0, 1);
}

// FUNCTION: IMPERIALISM 0x0050be30
TView* TMacViewMgr::MakeBookDialog(int dialogId) {
  TView* dialog = g_pTurnEventDialogFactoryRegistry->ResolveDialogNodeByMessageContext(dialogId, 0);
  if (dialog == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UMacViewMgr.cpp", 0x917);
  }
  dialog->Open();
  return dialog;
}

// FUNCTION: IMPERIALISM 0x0050bea0
void TMacViewMgr::RefreshCityProductionDetailPanelAndArrowWidgets(word nationSlot) {
  TGreatPower* nation = g_apNationStates[nationSlot];
  TView* hostView = activeCityProductionView04;
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

    TextStyle styleDescriptor;
    BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xa, 0x2b67);
    textEntry->InstallTextStyle(styleDescriptor, 0);
    textEntry->SetTextAlignmentAndMaybeRefresh(0, 0);
    textEntry->controlTag = kTagDetailText;

    g_pSimMgr->GetString(0x2735, 1, &scratch38);
    textEntry->SetHoverHelpText(scratch38);

    short needCap = nation != 0 ? nation->needCapA6 : 0;
    SetPanelShortField(panel, 0x94, nation != 0 ? nation->needsOverCapFlag : 0);
    SetPanelShortField(panel, 0x96, needCap);
    SetPanelShortField(panel, 0x98, static_cast<short>(-1));
    return;
  }

  if (nationSlot == 1 || nationSlot == 7 || nationSlot == 10 || nationSlot == 0x10 ||
      nationSlot == 0x14) {
    return;
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
    g_pSimMgr->NumToOrdinal(static_cast<int>(nationSlot), &formatTarget);
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
    g_pSimMgr->NumToOrdinal(static_cast<int>(nationSlot), &formatTarget);
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
    g_pSimMgr->NumToOrdinal(static_cast<int>(nationSlot), &formatTarget);
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
    g_pSimMgr->NumToOrdinal(static_cast<int>(nationSlot), &formatTarget);
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
    g_pSimMgr->NumToOrdinal(static_cast<int>(nationSlot), &formatTarget);
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
    g_pSimMgr->NumToOrdinal(static_cast<int>(nationSlot), &formatTarget);
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
    g_pSimMgr->NumToOrdinal(static_cast<int>(nationSlot), &formatTarget);
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
    g_pSimMgr->NumToOrdinal(static_cast<int>(nationSlot), &formatTarget);
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
    g_pSimMgr->NumToOrdinal(static_cast<int>(nationSlot), &formatTarget);
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
    g_pSimMgr->NumToOrdinal(static_cast<int>(nationSlot), &formatTarget);
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
    g_pSimMgr->NumToOrdinal(static_cast<int>(nationSlot), &formatTarget);
    g_pSimMgr->GetString(500, 0, &formatCurrent);
    g_pSimMgr->GetString(0x2735, 9, &displayText);
    ScanBracketExpressionsInto(&bracketScratch, displayText);
    useBracketOnlyPath = true;
    break;
  case 0x16:
    needTarget = nation->needTargetByType[0x16];
    needCurrent = nation->needCurrentByType[0x16];
    g_pSimMgr->NumToOrdinal(static_cast<int>(nationSlot), &formatTarget);
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
    leftArrow->BecameWindowTarget();
    TControl* rightArrow = ResolveTaggedChildOrFail(panel, kTagArrowRight);
    rightArrow->BecameWindowTarget();
    return;
  }

  TControl* leftSource = ResolveTaggedChildOrFail(panel, kTagArrowLeft);
  int leftLayout0[2];
  int leftLayout1[2];
  CopyViewLayoutFieldsToStack(leftLayout0, leftLayout1, leftSource);
  leftSource->BecameWindowTarget();

  TRightLeftView* leftView = new TRightLeftView();
  leftView->InitializeUiResourceEntryFrameAndParent(0, panel, leftLayout1, leftLayout0, 5, 5, 0);
  leftView->controlTag = kTagArrowLeft;

  TControl* rightSource = ResolveTaggedChildOrFail(panel, kTagArrowRight);
  int rightLayout0[2];
  int rightLayout1[2];
  CopyViewLayoutFieldsToStack(rightLayout0, rightLayout1, rightSource);
  rightSource->BecameWindowTarget();

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

  TextStyle styleDescriptor;
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xa, 0x2b67);
  textEntry->InstallTextStyle(styleDescriptor, 0);
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
    valueEntry->InstallTextStyle(styleDescriptor, 0);
    valueEntry->SetTextAlignmentAndMaybeRefresh(0, 0);
    valueEntry->controlTag = kTagDetailValue;
  }

  SetPanelShortField(panel, 0x92, static_cast<short>(nationSlot));
  SetPanelShortField(panel, 0x94, needTarget);
  SetPanelShortField(panel, 0x96, needCurrent);
}

// FUNCTION: IMPERIALISM 0x0050d310
void TMacViewMgr::DispatchTurnEvent3B8AndWaitForCompletionFlag(int unusedArg1, int unusedArg2) {
  TView* dialog = activeCityProductionView04;
  g_pUiRuntimeContext->DispatchTurnEvent(0x3b8, 0);
  short completionFlag = static_cast<short>(dialog->field14);
  while (completionFlag == 0) {
    PumpUiMessagesAndBackgroundTasks(1);
    completionFlag = static_cast<short>(dialog->field14);
  }
}

// FUNCTION: IMPERIALISM 0x0050d360
TBuildingView* TMacViewMgr::OpenBuildingWindow(short buildingSlot, TCity* city,
                                               unsigned char closeAfterOpen,
                                               unsigned char isEmbeddedPage,
                                               TCityProductionView* productionView) {
  TurnEventDialogNode* dialog = reinterpret_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(buildingSlot + 0x23f0));
  TBuildingView* buildingView =
      static_cast<TBuildingView*>(dialog->ResolveControlByTag(0x444c4f47));
  if (buildingView == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUMacViewMgr_00696D68, 0xb4f);
  }
  buildingView->ApplyCityViewSelectionPayloadAndRefreshControls(city, isEmbeddedPage != 0,
                                                                productionView, buildingSlot);
  dialog->controlValue3c = 0x65;
  if (closeAfterOpen != 0) {
    dialog->ShowTurnEventDialog(1);
    dialog->RefreshTurnEventDialog();
    dialog->Close();
    dialog->Free();
    return 0;
  }
  dialog->Open();
  return buildingView;
}

// FUNCTION: IMPERIALISM 0x0050d470
void TMacViewMgr::ShowGoldDialogForTurnEventContext(int param_1, int param_2, int arg3, int arg4,
                                                    int arg5, int arg6, int arg7) {
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
}

// FUNCTION: IMPERIALISM 0x0050d5b0
void TMacViewMgr::OpenConstructionWindow(short buildingSlot, TCity* city,
                                         TCityProductionView* productionView) {
  TurnEventDialogNode* dialog = reinterpret_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x2404));
  TBuildingConstructionView* constructionView =
      static_cast<TBuildingConstructionView*>(dialog->ResolveControlByTag(0x444c4f47));
  if (constructionView == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUMacViewMgr_00696D68, 0xb98);
  }
  constructionView->StuffValues(buildingSlot, city, productionView);
  dialog->ShowTurnEventDialog(1);
  unsigned long dialogAction = dialog->RefreshTurnEventDialog();
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
bool TMacViewMgr::IsPointInsideClipRegionSlot(CPoint* point, short regionIndex) {
  if (regionSlots[regionIndex] != 0) {
    return QueryPointInsideHitRegion(point->x, point->y, regionSlots[regionIndex]);
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
    activeCityProductionView04->GetDrawableRegion(0);
  }
  activeCityProductionView04 = 0;
}

// FUNCTION: IMPERIALISM 0x0050d950
void TMacViewMgr::RefreshActiveGoldControlAndUiRuntimeState() {
  TView* hostView = g_pDisplayMgr->activeDialog;
  GoldDialogControl* goldControl =
      static_cast<GoldDialogControl*>(hostView->ResolveControlByTag(0x444c4f47));
  if (goldControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  goldControl->gold71();
  goldControl->SetGoldControlStateByResource(0, 0);
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
  short overlaySourceOffset =
      reinterpret_cast<short*>(kAddrStrategicMapOverlaySourceRowByIconId)[wOverlayIconId];
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
  unsigned char* dstRow = dstPixels + (0x28 - nYShift) * dstStrideBytes + static_cast<int>(nDstX);
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

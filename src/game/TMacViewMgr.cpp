#include "game/TMacViewMgr.h"

#include <new>

#include "game/bitmap_descriptor_helpers.h"
#include "game/ClipStateRegion.h"
#include "game/TAnimation.h"
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
#include "game/TView.h"
#include "game/UiRuntimeContext.h"
#include "game/diplomacy_globals.h"
#include "game/quickdraw_globals.h"
#include "game/trade_quickdraw.h"
#include "game/ui_invalidation_guard.h"
#include "game/turn_event_packets.h"
#include "game/mfc.h"
#include "game/turn_flow_cooldown.h"
#include "decomp_types.h"

void WrapperFor_FreeHeapBufferIfNotNull_At004feb50(undefined4* field);

void __fastcall BuildStrategicMapGaugeAtlasFrom1422And1423(TMacViewMgr* self);
void __fastcall RefreshCityCapabilityUiHandlesForActiveNation(TMacViewMgr* self);
void __fastcall BuildStrategicMapTileOverlayStripSurfaces800To807(TMacViewMgr* self);
void __fastcall ReloadBitmap244AndRefreshUiCaches(TMacViewMgr* self);

int __cdecl IsPointInsideHitRegion(CPoint* point, int hitArg);

undefined4 scanBracketExpressions(void);
undefined4 AssignStringSharedRefAndReturnThis(void);
undefined4 RunEnableAndProcessFlagWithScopedSharedStringCleanup(void);
undefined4 BuildUiTextStyleDescriptor(void);
undefined4 CallCallbackRepeatedly(void);
undefined4 RebuildSurfaceRowsWithTemporaryRowBuffer(void);
undefined4 BuildBitmapMaskOpcodeBufferFromResourceRows(void);
undefined4 BuildHexNeighborHighlightPolygonForTile(void);
undefined4 CallObjectOffset24Vslot54IfPresent(void);

namespace MacViewUiInvoke {

static CString* AssignStringSharedRefAndReturnThis(TView* view, CString* sharedString) {
  return reinterpret_cast<CString*(__cdecl*)(TView*, CString*)>(
      reinterpret_cast<void (*)()>(AssignStringSharedRefAndReturnThis))(view, sharedString);
}

static void InvokeRunEnableAndProcessFlagWithScopedSharedStringCleanup(void) {
  reinterpret_cast<void(__cdecl*)(void)>(
      reinterpret_cast<void (*)()>(RunEnableAndProcessFlagWithScopedSharedStringCleanup))();
}

static void BuildUiTextStyleDescriptor(void* styleDescriptor, int unused, int arg2, int arg3) {
  reinterpret_cast<void(__cdecl*)(void*, int, int, int)>(
      reinterpret_cast<void (*)()>(BuildUiTextStyleDescriptor))(styleDescriptor, unused, arg2,
                                                                 arg3);
}

} // namespace MacViewUiInvoke

namespace {

const unsigned int kAddrStrNilPointer = 0x00694fc8;
const unsigned int kAddrStrFailure = 0x00694fd8;
const unsigned int kAddrStrategicMapOverlaySourceRowByIconId = 0x00696d20;
const unsigned int kAddrDecimalFormat = 0x0069430c;

const unsigned int kTagCityProductionTotal = 0x746f7461u;
const unsigned int kTagArrowLeft = 0x6c656674u;
const unsigned int kTagArrowRight = 0x72676874u;
const unsigned int kTagDetailText = 0x74657874u;
const unsigned int kTagDetailValue = 0x76616c75u;

static void SetPanelShortField(TControl* panel, int offset, short value) {
  *reinterpret_cast<short*>(reinterpret_cast<char*>(panel) + offset) = value;
}

static TControl* ResolveTaggedPanelOrFail(TView* hostView, unsigned int tag) {
  TControl* panel = hostView->ResolveControlByTag(tag);
  if (panel == 0) {
    MessageBoxA(0, reinterpret_cast<const char*>(kAddrStrNilPointer),
                reinterpret_cast<const char*>(kAddrStrFailure), 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  return panel;
}

static TControl* ResolveTaggedChildOrFail(TControl* panel, unsigned int tag) {
  TControl* child = panel->ResolveControlByTag(tag);
  if (child == 0) {
    MessageBoxA(0, reinterpret_cast<const char*>(kAddrStrNilPointer),
                reinterpret_cast<const char*>(kAddrStrFailure), 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  return child;
}

static void CopyViewLayoutFieldsToStack(int* layout0, int* layout1, TControl* srcControl) {
  TView* srcView = srcControl;
  layout0[0] = srcView->ownerOffsetX;
  layout0[1] = srcView->ownerOffsetY;
  layout1[0] = srcView->field34;
  layout1[1] = srcView->field38;
}

static void SetControlCommandTagAt1c(TControl* control, unsigned int tag) {
  *reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(control) + 0x1c) = tag;
}

static void ScanBracketExpressionsInto(CString* dest, const CString& templateText) {
  reinterpret_cast<void(__stdcall*)(void*, void*, char*)>(scanBracketExpressions)(
      g_pLocalizationTable, dest,
      const_cast<char*>(static_cast<LPCSTR>(templateText)));
}

static undefined4 QueryPointInsideHitRegion(short x, short y, ClipStateRegionWrapper* region) {
  CPoint point;
  point.x = x;
  point.y = y;
  return IsPointInsideHitRegion(&point, reinterpret_cast<int>(region));
}

static void InvokeCallCallbackRepeatedly(void* buf, int elemSize, int count, void* cb) {
  reinterpret_cast<void(__stdcall*)(void*, int, int, void*)>(
      reinterpret_cast<void (*)()>(CallCallbackRepeatedly))(buf, elemSize, count, cb);
}

static void InvokeRebuildSurfaceRowsWithTemporaryRowBuffer(void) {
  reinterpret_cast<void(__cdecl*)(void)>(
      reinterpret_cast<void (*)()>(RebuildSurfaceRowsWithTemporaryRowBuffer))();
}

static void InvokeBuildBitmapMaskOpcodeBufferFromResourceRows(int a, int b, int c, int d, int e) {
  reinterpret_cast<void(__cdecl*)(int, int, int, int, int)>(reinterpret_cast<void (*)()>(
      BuildBitmapMaskOpcodeBufferFromResourceRows))(a, b, c, d, e);
}

static void InvokeBuildHexNeighborHighlightPolygonForTile(short tileId, int tileIndex) {
  reinterpret_cast<void(__cdecl*)(short, int)>(reinterpret_cast<void (*)()>(
      BuildHexNeighborHighlightPolygonForTile))(tileId, tileIndex);
}

static void InvokeCallObjectOffset24Vslot54IfPresent(void) {
  reinterpret_cast<void(__cdecl*)(void)>(
      reinterpret_cast<void (*)()>(CallObjectOffset24Vslot54IfPresent))();
}

void FreeHeapBufferField(int* field) {
  WrapperFor_FreeHeapBufferIfNotNull_At004feb50(reinterpret_cast<undefined4*>(field));
}

void ReleaseBitmapLoaderHandle(int** loaderHandle) {
  if (loaderHandle == nullptr) {
    return;
  }
  TAnimation* animation = reinterpret_cast<TAnimation*>(*loaderHandle);
  if (animation != nullptr) {
    animation->WrapperFor_thunk_DecrementDialogResourceRefCountByShortIdAndCleanup_At00495c00();
    ::operator delete(animation);
  }
  ::operator delete(loaderHandle);
}

void ResolveAndBlitBitmapResourceToActiveAtlas(int resourceId, RECT* dstRect) {
  int** loaderHandle = WrapperFor_AllocateWithFallbackHandler_At004a1130(resourceId);
  if (*loaderHandle != 0) {
    WrapperFor_thunk_ResolveBmpResourceHandleWithDefault3B6_At00495c40(loaderHandle, dstRect);
  }
  ReleaseBitmapLoaderHandle(loaderHandle);
}

struct CityOrderSource {
  virtual char QuerySellModeFlag1D8() = 0;
  virtual short QuerySellQuantity1D4() = 0;
};

struct TurnEventDialogView : public TView {
  virtual void ShowTurnEventDialog(int flag);
  virtual void node69();
  virtual void node6a();
  virtual void RefreshTurnEventDialog();
  virtual void node6c();
  virtual void node6d();
  virtual void* QueryTurnEventContentObject();
  virtual void DispatchSlot9C();
  virtual void SetDialogModeSlotF0(int mode);
  virtual void InvokeSlotF0WithPair(short a, short b);
  virtual void SetDialogActiveFlag(int flag);
  virtual void InvokeSlotA0();
  virtual void InvokeSlot1C();
};

struct GoldDialogControl : public TControl {
  virtual void gold71();
  virtual void SetGoldControlStateByResource(int a, int b);
  virtual void InvokeSlot1CC(int a, int b, int c);
  virtual void InvokeSlot1D0FourParam(int a, int b, int c, int slot);
  virtual void InvokeSlot1D0OneParam(void* content);
};

}  // namespace

// GLOBAL: IMPERIALISM 0x00658610
IMPLEMENT_DYNCREATE(TMacViewMgr, TObject)

// FUNCTION: IMPERIALISM 0x00509ca0
TMacViewMgr::TMacViewMgr() : TObject() {
  InvokeCallCallbackRepeatedly(callback6bc, 0x30, 0x18, reinterpret_cast<void*>(0x00404d5e));
  InvokeCallCallbackRepeatedly(callbackB3c, 0x30, 6, reinterpret_cast<void*>(0x00404d5e));
  InvokeCallCallbackRepeatedly(callbackC5c, 0x30, 6, reinterpret_cast<void*>(0x00404d5e));
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
undefined4 TMacViewMgr::VTableSlot26(short tileIndex) {
  return reinterpret_cast<undefined4>(regionSlots[tileIndex]);
}

// SYNTHETIC: IMPERIALISM 0x00509e30
// TMacViewMgr::`scalar deleting destructor'
TMacViewMgr::~TMacViewMgr() {}

// FUNCTION: IMPERIALISM 0x00509e60
void __fastcall WrapperFor_InvokeCallbackNTimesWithSehGuard_At00509e60(TMacViewMgr* self) {
  InvokeCallCallbackRepeatedly(self->callbackC5c, 0x30, 6, reinterpret_cast<void*>(0x004038a0));
  InvokeCallCallbackRepeatedly(self->callbackB3c, 0x30, 6, reinterpret_cast<void*>(0x004038a0));
  InvokeCallCallbackRepeatedly(self->callback6bc, 0x30, 0x18, reinterpret_cast<void*>(0x004038a0));
}

// FUNCTION: IMPERIALISM 0x00509f20
void InitializeStrategicMapViewSystem(TMacViewMgr* self) {
  g_pUiViewManager->NoOpRuntimeUiCallback_005df3f0();
  self->BuildStrategicMapCommodityIconAtlasFrom700To722();
  self->LoadStrategicMapUnitIconAtlas750();
  self->LoadStrategicMapUnitOverlayAtlas751();
  self->LoadStrategicMapOverlayAtlas8699();
  BuildStrategicMapGaugeAtlasFrom1422And1423(self);
  RefreshCityCapabilityUiHandlesForActiveNation(self);
  BuildStrategicMapTileOverlayStripSurfaces800To807(self);
}

// FUNCTION: IMPERIALISM 0x00509f70
void TMacViewMgr::Free() {
  int index = 0;
  while (index < 0x17) {
    if (regionSlots[index] != 0) {
      DestroyClipStateRegionWrapperObject(regionSlots[index]);
      regionSlots[index] = 0;
    }
    ++index;
  }
  index = 0;
  while (index < 0x180) {
    if (tileStateSlots[index] != 0) {
      DestroyClipStateRegionWrapperObject(tileStateSlots[index]);
      tileStateSlots[index] = 0;
    }
    ++index;
  }
  FreeHeapBufferField(&unitIconAtlas);
  FreeHeapBufferField(&unitOverlayAtlas);
  FreeHeapBufferField(&atlas674);
  FreeHeapBufferField(&atlas668);
  FreeHeapBufferField(&atlas66c);
  FreeHeapBufferField(&atlas670);
  FreeHeapBufferField(&atlas680);
  FreeHeapBufferField(&atlas688);
  FreeHeapBufferField(&atlas68c);
  FreeHeapBufferField(&atlas690);
  FreeHeapBufferField(&atlas684);
  FreeHeapBufferField(&atlas6b4);
  FreeHeapBufferField(&atlas6b8);
  index = 0;
  while (index < 8) {
    FreeHeapBufferField(&atlas694[index]);
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
  RefreshCityCapabilityUiHandlesForActiveNation(this);
}

// FUNCTION: IMPERIALISM 0x0050a180
void TMacViewMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
}

// FUNCTION: IMPERIALISM 0x0050a1a0
undefined TMacViewMgr::BuildStrategicMapCommodityIconAtlasFrom700To722() {
  RECT atlasBounds;
  undefined4 savedContext;
  undefined4 savedFlags;
  int* atlasSurface;
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
  g_pDisplayMgr->Helper_Uses_thunk_Cluster_GameplayHint_004962c0_At004feab0(reinterpret_cast<undefined4*>(&atlas674), 8, &atlasBounds);
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(atlas674), savedFlags);
  atlasSurface = reinterpret_cast<int*>(GetSurfaceObjectAtContextOffset24(atlas674));
  ReturnConstantTrueQuickDrawFlag(atlasSurface);
  ResetQuickDrawStrokeState();
  pixelBuffer = reinterpret_cast<int*>(GetSurfaceHeaderFromSurfaceObject(atlasSurface));
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
  stridePixels = static_cast<short>(*reinterpret_cast<ushort*>(*atlasSurface + 4) & 0x3fff);
  dstCursor = reinterpret_cast<undefined4*>(pixelBuffer) - 2;
  commodityIndex = 0;
  while (commodityIndex < 0x17) {
    int** loaderHandle =
        WrapperFor_AllocateWithFallbackHandler_At004a1130(commodityIndex + 700);
    if (loaderHandle != nullptr && *loaderHandle != 0) {
      dstCursor = dstCursor + 2;
      CopySpriteSurfaceToStrideBuffer(reinterpret_cast<int*>(loaderHandle), dstCursor,
                                      static_cast<short>(stridePixels));
    }
    ReleaseBitmapLoaderHandle(loaderHandle);
    commodityIndex = commodityIndex + 1;
  }
  NoOpQuickDrawLifecycleHookB(GetSurfaceObjectAtContextOffset24(atlas674));
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(savedContext), savedFlags);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050a3b0
undefined TMacViewMgr::LoadStrategicMapUnitIconAtlas750() {
  unitIconAtlas = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x2ee);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050a3e0
undefined TMacViewMgr::LoadStrategicMapUnitOverlayAtlas751() {
  unitOverlayAtlas = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x2ef);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050a410
undefined TMacViewMgr::LoadStrategicMapOverlayAtlas8699() {
  atlas680 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x21fb);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050a440
undefined TMacViewMgr::LoadStrategicMapMarkerAtlas1372() {
  atlas684 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x55c);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050a470
void __fastcall BuildStrategicMapGaugeAtlasFrom1422And1423(TMacViewMgr* self) {
  RECT atlasBounds;
  undefined4 savedContext;
  undefined4 savedFlags;
  atlasBounds.left = 0;
  atlasBounds.top = 0;
  atlasBounds.right = 0x500;
  atlasBounds.bottom = 0x10;
  g_pDisplayMgr->Helper_Uses_thunk_Cluster_GameplayHint_004962c0_At004feab0(reinterpret_cast<undefined4*>(&self->atlas688), 8, &atlasBounds);
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(self->atlas688), savedFlags);
  ReturnConstantTrueQuickDrawFlag(GetSurfaceObjectAtContextOffset24(self->atlas688));
  ResetQuickDrawStrokeState();
  ResolveAndBlitBitmapResourceToActiveAtlas(0x58e, &atlasBounds);
  ResolveAndBlitBitmapResourceToActiveAtlas(0x58f, &atlasBounds);
  NoOpQuickDrawLifecycleHookB(GetSurfaceObjectAtContextOffset24(self->atlas688));
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(savedContext), savedFlags);
}

// FUNCTION: IMPERIALISM 0x0050a6a0
void __fastcall RefreshCityCapabilityUiHandlesForActiveNation(TMacViewMgr* self) {
  short nationId;
  unsigned int variant;
  if (IsTurnCooldownCounterActiveOrResetFlag() != 0) {
    return;
  }
  if (self == 0 || g_pCityOrderCapabilityState == 0) {
    return;
  }
  if (self->atlas68c != 0) {
    WrapperFor_FreeHeapBufferIfNotNull_At004feb50(reinterpret_cast<undefined4*>(&self->atlas68c));
  }
  if (self->atlas690 != 0) {
    WrapperFor_FreeHeapBufferIfNotNull_At004feb50(reinterpret_cast<undefined4*>(&self->atlas690));
  }
  nationId = g_pUiRuntimeContext->GetActiveNationId();
  if (nationId < 0) {
    return;
  }
  g_pUiViewManager->NoOpRuntimeUiCallback_005df3f0();
  nationId = g_pUiRuntimeContext->GetActiveNationId();
  variant = g_pCityOrderCapabilityState->orderCapRows277[nationId].flag != 0;
  nationId = g_pUiRuntimeContext->GetActiveNationId();
  if (g_pCityOrderCapabilityState->orderCapRows277[nationId].secondaryCapabilityFlag280 != 0) {
    variant = 2;
  }
  nationId = g_pUiRuntimeContext->GetActiveNationId();
  self->atlas68c = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(nationId + 0x579 + variant * 7);
  nationId = g_pUiRuntimeContext->GetActiveNationId();
  self->atlas690 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(nationId + 0x564 + variant * 7);
}

// FUNCTION: IMPERIALISM 0x0050a820
void __fastcall BuildStrategicMapTileOverlayStripSurfaces800To807(TMacViewMgr* self) {
  undefined4 savedContext;
  undefined4 savedFlags;
  int stripIndex;
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  stripIndex = 0;
  while (stripIndex < 8) {
    int** loaderHandle = WrapperFor_AllocateWithFallbackHandler_At004a1130(stripIndex + 800);
    if (*loaderHandle == 0) {
      return;
    }
    RECT resourceBounds;
    CopyRect(&resourceBounds, reinterpret_cast<RECT*>(*loaderHandle + 8));
    g_pDisplayMgr->Helper_Uses_thunk_Cluster_GameplayHint_004962c0_At004feab0(reinterpret_cast<undefined4*>(&self->atlas694[stripIndex]), 8,
                                &resourceBounds);
    SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(self->atlas694[stripIndex]), savedFlags);
    ReturnConstantTrueQuickDrawFlag(GetSurfaceObjectAtContextOffset24(self->atlas694[stripIndex]));
    NoOpRuntimeCallback_00497c00(loaderHandle);
    if (*loaderHandle != 0) {
      ResetQuickDrawStrokeState();
      WrapperFor_thunk_ResolveBmpResourceHandleWithDefault3B6_At00495c40(loaderHandle, &resourceBounds);
      if (stripIndex == 0) {
        InvokeRebuildSurfaceRowsWithTemporaryRowBuffer();
      }
      ReleaseBitmapLoaderHandle(loaderHandle);
    }
    NoOpQuickDrawLifecycleHookB(GetSurfaceObjectAtContextOffset24(self->atlas694[stripIndex]));
    stripIndex = stripIndex + 1;
  }
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(savedContext), savedFlags);
}

// FUNCTION: IMPERIALISM 0x0050a9f0
undefined TMacViewMgr::RenderOffscreenBitmapGridStripAndRestoreContext() {
  RECT atlasBounds;
  undefined4 savedContext;
  undefined4 savedFlags;
  int dstX;
  int dstY;
  int resourceId;
  int index;
  atlasBounds.left = 0;
  atlasBounds.top = 0;
  atlasBounds.right = 0xcc0;
  atlasBounds.bottom = 0x40;
  g_pDisplayMgr->Helper_Uses_thunk_Cluster_GameplayHint_004962c0_At004feab0(reinterpret_cast<undefined4*>(&atlas668), 8, &atlasBounds);
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(atlas668), savedFlags);
  ReturnConstantTrueQuickDrawFlag(GetSurfaceObjectAtContextOffset24(atlas668));
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
  NoOpQuickDrawLifecycleHookB(GetSurfaceObjectAtContextOffset24(atlas668));
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(savedContext), savedFlags);

  atlasBounds.right = 0xa80;
  g_pDisplayMgr->Helper_Uses_thunk_Cluster_GameplayHint_004962c0_At004feab0(reinterpret_cast<undefined4*>(&atlas66c), 8, &atlasBounds);
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(atlas66c), savedFlags);
  ReturnConstantTrueQuickDrawFlag(GetSurfaceObjectAtContextOffset24(atlas66c));
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
  NoOpQuickDrawLifecycleHookB(GetSurfaceObjectAtContextOffset24(atlas66c));
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(savedContext), savedFlags);

  atlasBounds.right = 0xd7;
  atlasBounds.bottom = 0x78;
  g_pDisplayMgr->Helper_Uses_thunk_Cluster_GameplayHint_004962c0_At004feab0(reinterpret_cast<undefined4*>(&atlas670), 8, &atlasBounds);
  atlasBounds.right = 0x90;
  atlasBounds.bottom = 0x26;
  g_pDisplayMgr->Helper_Uses_thunk_Cluster_GameplayHint_004962c0_At004feab0(reinterpret_cast<undefined4*>(&atlas6b4), 8, &atlasBounds);
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(atlas6b4), savedFlags);
  ReturnConstantTrueQuickDrawFlag(GetSurfaceObjectAtContextOffset24(atlas6b4));
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
  NoOpQuickDrawLifecycleHookB(GetSurfaceObjectAtContextOffset24(atlas6b4));
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(savedContext), savedFlags);

  if (atlas6b8 != 0) {
    WrapperFor_FreeHeapBufferIfNotNull_At004feb50(reinterpret_cast<undefined4*>(&atlas6b8));
  }
  atlasBounds.left = 0;
  atlasBounds.top = 0;
  atlasBounds.right = 0;
  atlasBounds.bottom = 0;
  g_pDisplayMgr->Helper_Uses_thunk_Cluster_GameplayHint_004962c0_At004feab0(reinterpret_cast<undefined4*>(&atlas6b8), 8, &atlasBounds);
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(atlas6b8), savedFlags);
  ReturnConstantTrueQuickDrawFlag(GetSurfaceObjectAtContextOffset24(atlas6b8));
  ResetQuickDrawStrokeState();
  ResolveAndBlitBitmapResourceToActiveAtlas(0x244, &atlasBounds);
  NoOpQuickDrawLifecycleHookB(GetSurfaceObjectAtContextOffset24(atlas6b8));
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(savedContext), savedFlags);

  index = 0;
  while (index < 0x10) {
    InvokeBuildBitmapMaskOpcodeBufferFromResourceRows(index + 0x2740, 0x40, 0x40, 0x1680, 0x10);
    index = index + 1;
  }
  resourceId = 0x2760;
  while (resourceId < 0x2766) {
    InvokeBuildBitmapMaskOpcodeBufferFromResourceRows(resourceId - 0x26, 0x40, 0x40, 0x1680, 0x10);
    InvokeBuildBitmapMaskOpcodeBufferFromResourceRows(resourceId, 0x40, 0x40, 0x1680, 0x10);
    resourceId = resourceId + 1;
  }
  index = 0x10;
  while (index < 0x18) {
    InvokeBuildBitmapMaskOpcodeBufferFromResourceRows(index + 0x2756, 0x40, 0x40, 0x1680, 0x10);
    index = index + 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050b5b0
void __fastcall ReloadBitmap244AndRefreshUiCaches(TMacViewMgr* self) {
  g_pUiViewManager->NoOpRuntimeUiCallback_005df3f0();
  if (self->atlas6b8 != 0) {
    WrapperFor_FreeHeapBufferIfNotNull_At004feb50(reinterpret_cast<undefined4*>(&self->atlas6b8));
  }
  self->atlas6b8 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x244);
  if (self->atlas688 != 0) {
    WrapperFor_FreeHeapBufferIfNotNull_At004feb50(reinterpret_cast<undefined4*>(&self->atlas688));
  }
  self->LoadStrategicMapOverlayAtlas8699();
}

// FUNCTION: IMPERIALISM 0x0050b640
undefined TMacViewMgr::RenderTurnEventPalettePreviewSurfaceAndProgress() {
  RECT fillRect;
  undefined4 savedContext;
  undefined4 savedFlags;
  int* surfaceObject;
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
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(atlas670), savedFlags);
  surfaceObject = reinterpret_cast<int*>(GetSurfaceObjectAtContextOffset24(atlas670));
  ReturnConstantTrueQuickDrawFlag(surfaceObject);
  ResetQuickDrawStrokeState();
  pixelBase = reinterpret_cast<int>(GetSurfaceHeaderFromSurfaceObject(surfaceObject));
  strideBytes = *reinterpret_cast<ushort*>(*surfaceObject + 4) & 0x3fff;
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
      paletteByte =
          static_cast<unsigned char>(g_pUiRuntimeContext->MapTurnEventCodeToPaletteIndex(terrainCode));
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
  pixelBase = reinterpret_cast<int>(GetSurfaceHeaderFromSurfaceObject(surfaceObject));
  pixelBase = pixelBase + strideBytes * 2;
  scratchBuffer = new unsigned char[0x6540];
  if (scratchBuffer == 0) {
    MessageBoxA(0, reinterpret_cast<const char*>(kAddrStrNilPointer),
                reinterpret_cast<const char*>(kAddrStrFailure), 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  {
    int copyRow = 0;
    unsigned char* scratchCursor = scratchBuffer;
    while (copyRow < 0x78) {
      unsigned char* srcCursor = reinterpret_cast<unsigned char*>(pixelBase + copyRow * strideBytes);
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
    char* compareRow = reinterpret_cast<char*>(pixelBase + 1);
    char* scratchRow = reinterpret_cast<char*>(scratchBuffer + 0x1b1);
    int edgeRow = 0x70;
    while (edgeRow != 0) {
      int edgeCol = 0xd6;
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
      compareRow = compareRow + strideBytes;
      scratchRow = scratchRow + 3;
      edgeRow = edgeRow - 1;
    }
  }
  {
    int copyRow = 0;
    unsigned char* scratchCursor = scratchBuffer;
    while (copyRow < 0x78) {
      unsigned char* dstCursor = reinterpret_cast<unsigned char*>(pixelBase + copyRow * strideBytes);
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
  NoOpQuickDrawLifecycleHookB(GetSurfaceObjectAtContextOffset24(atlas670));
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(savedContext), savedFlags);
  InvokeRebuildSurfaceRowsWithTemporaryRowBuffer();
  reinterpret_cast<unsigned char*>(g_pGlobalMapState)[4] = 1;
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050b9e0
undefined TMacViewMgr::RebuildMapTileNeighborHighlightPolygonsForAllTiles() {
  int tileIndex = 0;
  int tileByteOffset = 0;
  ClipStateRegionWrapper** tileSlot = tileStateSlots;
  while (tileByteOffset < 0xfc00) {
    if (reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable)[tileByteOffset] != -1) {
      if (*tileSlot != 0) {
        DestroyClipStateRegionWrapperObject(*tileSlot);
        *tileSlot = 0;
      }
      *tileSlot = CreateClipStateRegionWrapperObject();
      RebuildMapTileNeighborHighlightPolygonsForAllTiles_Impl();
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
      WrapperFor_LookupHandleMapEntryWithCreate_At00497f90(*tileSlot);
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
  if (g_pLocalizationTable->field30 == 1) {
    DispatchTaggedGameStateEvent1F20(0x72656765, 0, 0xfffffffd);
  }
  if (tileStateSlots[0] != 0) {
    ClipStateRegionWrapper* regionWrapper = CreateClipStateRegionWrapperObject();
    int nationIndex = 0;
    while (nationIndex < 0x17) {
      ResetClipRegionAndReadBoundingRect(regionWrapper);
      int tileByteOffset = 0;
      ClipStateRegionWrapper** tileSlot = tileStateSlots;
      while (tileByteOffset < 0xfc00) {
        if (reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable)[tileByteOffset] ==
            nationIndex) {
          CombineTwoRegionsIntoDestinationAndUpdateBox(regionWrapper, *tileSlot, regionWrapper);
        }
        tileByteOffset = tileByteOffset + 0xa8;
        tileSlot = tileSlot + 1;
      }
      EnsureClipRegionWrapperAtSlotAndMergeSourceRegion(
          reinterpret_cast<undefined4>(regionWrapper), static_cast<short>(nationIndex));
      nationIndex = nationIndex + 1;
    }
    DestroyClipStateRegionWrapperObject(regionWrapper);
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
undefined TMacViewMgr::SyncSellTaggedChildControlWithNationState(int* param_1, short param_2) {
  TView* controlView = reinterpret_cast<TView*>(param_1);
  short sellCount;
  TControl* sellControl;
  controlView->SetState(0, 0);
  *reinterpret_cast<short*>(reinterpret_cast<char*>(param_1) + 0x88) =
      static_cast<short>(reinterpret_cast<int>(param_1));
  if (g_pCityOrderCapabilityState->hasProductionOrder193 == 0 &&
      (reinterpret_cast<int>(param_1) == 6 || reinterpret_cast<int>(param_1) == 0xc)) {
    controlView->SetEnabled(0, 0);
  }
  sellCount = g_apNationStates[param_2]->QueryNationMetricBySlot7C(param_2);
  if (sellCount > 0 && g_apNationStates[param_2]->tradeCapacity == 0) {
    g_apNationStates[param_2]->SetDiplomacyState1c6ClampedToCounterA4(0, 0);
    sellCount = 0;
  }
  sellControl = controlView->ResolveControlByTag(0x53656c6c);
  if (sellControl == 0) {
    MessageBoxA(0, reinterpret_cast<const char*>(kAddrStrNilPointer),
                reinterpret_cast<const char*>(kAddrStrFailure), 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  if (sellCount < 0) {
    controlView->RefreshCityProductionViewStateFromContext(0);
    sellControl->RefreshCityProductionViewStateFromContext(0);
    sellControl->SetEnabled(0, 1);
  } else {
    controlView->InvalidateOffsetRegionUsingChildClipRect(0);
  }
  if (sellCount > 0) {
    controlView->ForwardMapViewVirtualC4IfPresent(sellCount);
    sellControl->RefreshCityProductionViewStateFromContext(reinterpret_cast<int*>(sellCount));
    sellControl->SetEnabled(1, 1);
    return 0;
  }
  if (g_apNationStates[param_2]->tradeCapacity != 0) {
    controlView->DispatchSlot9CToLinkedChildren();
  }
  sellControl->RefreshCityProductionViewStateFromContext(0);
  sellControl->SetEnabled(0, 1);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050be30
undefined TMacViewMgr::ResolveTurnEventDialogOrFailAndInvokeSlot9C() {
  TurnEventDialogView* dialog =
      reinterpret_cast<TurnEventDialogView*>(g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0));
  if (dialog == 0) {
    MessageBoxA(0, reinterpret_cast<const char*>(kAddrStrNilPointer),
                reinterpret_cast<const char*>(kAddrStrFailure), 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  dialog->DispatchSlot9C();
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050bea0
undefined TMacViewMgr::RefreshCityProductionDetailPanelAndArrowWidgets(word nationSlot) {
  TGreatPower* nation = g_apNationStates[nationSlot];
  TView* hostView = reinterpret_cast<TView*>(field04);
  CString scratch38;

  if (nationSlot == static_cast<word>(-1)) {
    TControl* panel = ResolveTaggedPanelOrFail(hostView, kTagCityProductionTotal);
    g_pLocalizationTable->GetString(0x2735, 0, &scratch38);
    MacViewUiInvoke::AssignStringSharedRefAndReturnThis(panel, &scratch38);
    MacViewUiInvoke::InvokeRunEnableAndProcessFlagWithScopedSharedStringCleanup();

    TMyStaticText* textEntry = new TMyStaticText();

    int layoutHeight = 0xb;
    int layoutWidth = 0x14;
    int layoutPos = 0x3c;
    int layoutAnchor = 0xa2;
    int layoutOuter = 0x12;
    textEntry->InitializeTextEntryBaseAndOptionalStringResource(panel, &layoutAnchor, &layoutHeight,
                                                                5, 5, -1, 0);

    TControlPictureRectState styleDescriptor;
    MacViewUiInvoke::BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xa, 0x2b67);
    textEntry->SetCityProductionDialogPictureRectAndMaybeRefresh(&styleDescriptor, 0);
    textEntry->OrphanCallChain_C1_I09_0048ff70();
    SetControlCommandTagAt1c(textEntry, kTagDetailText);

    g_pLocalizationTable->GetString(0x2735, 1, &scratch38);
    MacViewUiInvoke::AssignStringSharedRefAndReturnThis(textEntry, &scratch38);
    MacViewUiInvoke::InvokeRunEnableAndProcessFlagWithScopedSharedStringCleanup();

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
    needTarget =
        static_cast<short>(nation->needTargetByType[0] + nation->needTargetByType[1]);
    needCurrent =
        static_cast<short>(nation->needCurrentByType[0] + nation->needCurrentByType[1]);
    g_pLocalizationTable->GetString(0x2735, 2, &formatTarget);
    {
      int production = city->GetBuildingProductionValueBySlot(0);
      deficitCount = static_cast<short>(production * 2 - city->cityStockCottonB6 - city->cityStockWoolB8);
      formatCurrent.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
          static_cast<int>(city->cityStockCottonB6) + static_cast<int>(city->cityStockWoolB8));
      formatProduction.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                          production * 2);
      g_pLocalizationTable->GetString(0x2719, 0, &displayText);
    }
    break;
  case 2:
    needTarget = nation->needTargetByType[2];
    needCurrent = nation->needCurrentByType[2];
    g_pLocalizationTable->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    {
      int production = city->GetBuildingProductionValueBySlot(4);
      deficitCount = static_cast<short>(production * 2 - city->cityStockTimberBA);
      formatCurrent.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                          static_cast<int>(city->cityStockTimberBA));
      formatTarget.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                          production * 2);
      g_pLocalizationTable->GetString(0x2719, 4, &displayText);
      formatFieldValue = city->cityStockTimberBA;
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 3:
  case 4:
    needTarget = nation->needTargetByType[nationSlot];
    needCurrent = nation->needCurrentByType[nationSlot];
    g_pLocalizationTable->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    {
      int production = city->GetBuildingProductionValueBySlot(2);
      deficitCount = static_cast<short>(production - (&city->cityStockCottonB6)[nationSlot]);
      formatCurrent.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                          static_cast<int>((&city->cityStockCottonB6)[nationSlot]));
      formatTarget.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                          production);
      g_pLocalizationTable->GetString(0x2719, 2, &displayText);
      formatFieldValue = (&city->cityStockCottonB6)[nationSlot];
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 5:
    needTarget = nation->needTargetByType[5];
    needCurrent = nation->needCurrentByType[5];
    g_pLocalizationTable->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    formatCurrent.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                        static_cast<int>(needCurrent));
    formatTarget.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                        static_cast<int>(needTarget));
    g_pLocalizationTable->GetString(0x2719, 1, &displayText);
    ScanBracketExpressionsInto(&bracketScratch, displayText);
    useBracketOnlyPath = true;
    break;
  case 6:
    needTarget = nation->needTargetByType[6];
    needCurrent = nation->needCurrentByType[6];
    g_pLocalizationTable->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    {
      int production = city->GetBuildingProductionValueBySlot(6);
      deficitCount = static_cast<short>(production * 2 - city->cityStockOilC2);
      formatCurrent.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                          static_cast<int>(city->cityStockOilC2));
      formatTarget.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                          production * 2);
      g_pLocalizationTable->GetString(0x2719, 6, &displayText);
      formatFieldValue = city->cityStockOilC2;
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 8:
    needTarget = nation->needTargetByType[8];
    needCurrent = nation->needCurrentByType[8];
    g_pLocalizationTable->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    {
      int production = city->GetBuildingProductionValueBySlot(1);
      deficitCount = static_cast<short>(production * 2 - city->cityStockFabricC6);
      formatCurrent.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                          static_cast<int>(city->cityStockFabricC6));
      formatTarget.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                          production * 2);
      g_pLocalizationTable->GetString(0x2719, 1, &displayText);
      formatFieldValue = city->cityStockFabricC6;
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 9:
    needTarget = nation->needTargetByType[9];
    needCurrent = nation->needCurrentByType[9];
    g_pLocalizationTable->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    {
      int production = city->GetBuildingProductionValueBySlot(5);
      deficitCount = static_cast<short>(production * 2 - city->cityStockLumberC8);
      formatCurrent.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                          static_cast<int>(city->cityStockLumberC8));
      formatTarget.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                          production * 2);
      g_pLocalizationTable->GetString(0x2719, 5, &displayText);
      formatFieldValue = city->cityStockLumberC8;
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 0xb:
    needTarget = nation->needTargetByType[0xb];
    needCurrent = nation->needCurrentByType[0xb];
    g_pLocalizationTable->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    {
      int production = city->GetBuildingProductionValueBySlot(3);
      deficitCount = static_cast<short>(production * 2 - city->cityStockSteelCC);
      formatCurrent.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                          static_cast<int>(city->cityStockSteelCC));
      formatTarget.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                          production * 2);
      g_pLocalizationTable->GetString(0x2719, 3, &displayText);
      formatFieldValue = city->cityStockSteelCC;
      showArrowWidgets = 1;
      useProductionTailPath = true;
    }
    break;
  case 0xc:
    needTarget = nation->needTargetByType[0xc];
    needCurrent = nation->needCurrentByType[0xc];
    g_pLocalizationTable->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    {
      int production = city->GetBuildingProductionValueBySlot(0xb);
      deficitCount = static_cast<short>(production * 2 - city->cityStockFuelCE);
      formatCurrent.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                          static_cast<int>(city->cityStockFuelCE));
      formatTarget.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                          production * 2);
      g_pLocalizationTable->GetString(0x2719, 0xb, &displayText);
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
    g_pLocalizationTable->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    formatCurrent.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                        static_cast<int>(needCurrent));
    formatTarget.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                        static_cast<int>(needTarget));
    g_pLocalizationTable->GetString(0x2719, 8, &displayText);
    ScanBracketExpressionsInto(&bracketScratch, displayText);
    useBracketOnlyPath = true;
    break;
  case 0x11:
  case 0x12:
    needTarget = nation->needTargetByType[nationSlot];
    needCurrent = nation->needCurrentByType[nationSlot];
    g_pLocalizationTable->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
  {
    short* summary = city->GetCitySummaryRecordSlot74();
    short summaryValue = summary[nationSlot];
    formatTarget.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                        static_cast<int>(summaryValue));
    deficitCount = static_cast<short>(summaryValue - (&city->cityStockCottonB6)[nationSlot]);
    formatCurrent.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                        static_cast<int>((&city->cityStockCottonB6)[nationSlot]));
    g_pLocalizationTable->GetString(0x2735, 7, &displayText);
    ScanBracketExpressionsInto(&bracketScratch, displayText);
    displayText = bracketScratch;
    showArrowWidgets = 1;
    useSummaryPath = true;
  }
    break;
  case 0x13:
    needTarget = static_cast<short>(nation->needTargetByType[0x13] + nation->needTargetByType[0x14]);
    needCurrent =
        static_cast<short>(nation->needCurrentByType[0x13] + nation->needCurrentByType[0x14]);
    g_pLocalizationTable->GetString(0x2735, 3, &formatTarget);
  {
    short* summary = city->GetCitySummaryRecordSlot74();
    short summaryValue = summary[0x14];
    formatTarget.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                        static_cast<int>(summaryValue));
    deficitCount = static_cast<short>(summaryValue - city->cityStockFishDC - city->cityStockLivestockDE);
    formatFieldValue =
        static_cast<short>(city->cityStockFishDC + city->cityStockLivestockDE);
    showArrowWidgets = 1;
    useProductionTailPath = true;
  }
    break;
  case 0x15:
    needTarget = nation->needTargetByType[0x15];
    needCurrent = nation->needCurrentByType[0x15];
    g_pLocalizationTable->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    g_pLocalizationTable->GetString(500, 0, &formatCurrent);
    g_pLocalizationTable->GetString(0x2735, 9, &displayText);
    ScanBracketExpressionsInto(&bracketScratch, displayText);
    useBracketOnlyPath = true;
    break;
  case 0x16:
    needTarget = nation->needTargetByType[0x16];
    needCurrent = nation->needCurrentByType[0x16];
    g_pLocalizationTable->FormatOrdinalString(static_cast<int>(nationSlot), &formatTarget);
    g_pLocalizationTable->GetString(200, 0, &formatCurrent);
    g_pLocalizationTable->GetString(0x2735, 9, &displayText);
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
      formatField.Format( reinterpret_cast<const char*>(kAddrDecimalFormat),
                                                        static_cast<int>(formatFieldValue));
    }
    g_pLocalizationTable->GetString(0x2735, 7, &formatTarget);
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

  MacViewUiInvoke::AssignStringSharedRefAndReturnThis(panel, &displayText);
  MacViewUiInvoke::InvokeRunEnableAndProcessFlagWithScopedSharedStringCleanup();

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
  SetControlCommandTagAt1c(leftView, kTagArrowLeft);

  TControl* rightSource = ResolveTaggedChildOrFail(panel, kTagArrowRight);
  int rightLayout0[2];
  int rightLayout1[2];
  CopyViewLayoutFieldsToStack(rightLayout0, rightLayout1, rightSource);
  rightSource->DispatchUiCommand19ToParent();

  TRightLeftView* rightView = new TRightLeftView();
  rightView->InitializeUiResourceEntryFrameAndParent(0, panel, rightLayout1, rightLayout0, 5, 5, 0);
  SetControlCommandTagAt1c(rightView, kTagArrowRight);

  TMyStaticText* textEntry = new TMyStaticText();

  int textHeight = 0xb;
  int textWidth = 0x14;
  int textPos = 0x98;
  int textAnchor = 0x46;
  int textOuter = 0x12;
  textEntry->InitializeTextEntryBaseAndOptionalStringResource(panel, &textPos, &textHeight, 5, 5, -1,
                                                              0);

  TControlPictureRectState styleDescriptor;
  MacViewUiInvoke::BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xa, 0x2b67);
  textEntry->SetCityProductionDialogPictureRectAndMaybeRefresh(&styleDescriptor, 0);
  textEntry->OrphanCallChain_C1_I09_0048ff70();
  SetControlCommandTagAt1c(textEntry, kTagDetailText);

  g_pLocalizationTable->GetString(0x2735, 4, &scratch38);
  MacViewUiInvoke::AssignStringSharedRefAndReturnThis(textEntry, &scratch38);
  MacViewUiInvoke::InvokeRunEnableAndProcessFlagWithScopedSharedStringCleanup();

  if (nationSlot == 0x15 || nationSlot == 0x16) {
    TMyStaticText* valueEntry = new TMyStaticText();

    int valueHeight = 0xb;
    int valueWidth = 0x14;
    int valuePos = 0x3c;
    int valueAnchor = 0x32;
    valueEntry->InitializeTextEntryBaseAndOptionalStringResource(panel, &valuePos, &valueHeight, 5, 5,
                                                               -1, 0);
    valueEntry->SetCityProductionDialogPictureRectAndMaybeRefresh(&styleDescriptor, 0);
    valueEntry->OrphanCallChain_C1_I09_0048ff70();
    SetControlCommandTagAt1c(valueEntry, kTagDetailValue);
  }

  SetPanelShortField(panel, 0x92, static_cast<short>(nationSlot));
  SetPanelShortField(panel, 0x94, needTarget);
  SetPanelShortField(panel, 0x96, needCurrent);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050d310
undefined TMacViewMgr::DispatchTurnEvent3B8AndWaitForCompletionFlag() {
  TView* dialog = reinterpret_cast<TView*>(field04);
  g_pUiRuntimeContext->DispatchTurnEventSlot4C(0x3b8, 0);
  short completionFlag = *reinterpret_cast<short*>(reinterpret_cast<char*>(dialog) + 0x14);
  while (completionFlag == 0) {
    PumpUiMessagesAndBackgroundTasks(1);
    completionFlag = *reinterpret_cast<short*>(reinterpret_cast<char*>(dialog) + 0x14);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050d360
undefined TMacViewMgr::CreateCityBuildingDialogBySlot(int param_1, undefined4 param_2,
                                                      undefined4 param_3) {
  TurnEventDialogView* dialog = reinterpret_cast<TurnEventDialogView*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(param_1 + 0x23f0));
  GoldDialogControl* goldControl =
      reinterpret_cast<GoldDialogControl*>(dialog->ResolveControlByTag(0x444c4f47));
  if (goldControl == 0) {
    MessageBoxA(0, reinterpret_cast<const char*>(kAddrStrNilPointer),
                reinterpret_cast<const char*>(kAddrStrFailure), 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  goldControl->InvokeSlot1D0FourParam(reinterpret_cast<int>(this), param_2, param_3, param_1);
  *reinterpret_cast<int*>(reinterpret_cast<char*>(dialog) + 0x3c) = 0x65;
  dialog->DispatchSlot9C();
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050d470
undefined TMacViewMgr::OrphanCallChain_C10_I80_0050d470(undefined4 param_1, undefined4 param_2) {
  TurnEventDialogView* dialog = reinterpret_cast<TurnEventDialogView*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(param_1 + 0x23f0));
  GoldDialogControl* goldControl =
      reinterpret_cast<GoldDialogControl*>(dialog->ResolveControlByTag(0x444c4f47));
  if (goldControl == 0) {
    MessageBoxA(0, reinterpret_cast<const char*>(kAddrStrNilPointer),
                reinterpret_cast<const char*>(kAddrStrFailure), 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  goldControl->InvokeSlot1D0FourParam(reinterpret_cast<int>(this), param_2, param_1, param_1);
  *reinterpret_cast<int*>(reinterpret_cast<char*>(dialog) + 0x3c) = 0x65;
  dialog->InvokeSlotF0WithPair(static_cast<short>(reinterpret_cast<int>(this)),
                               static_cast<short>(param_1));
  dialog->DispatchSlot9C();
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050d5b0
undefined TMacViewMgr::OrphanCallChain_C9_I49_0050d5b0(undefined4 param_1) {
  TurnEventDialogView* dialog = reinterpret_cast<TurnEventDialogView*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x2404));
  GoldDialogControl* goldControl =
      reinterpret_cast<GoldDialogControl*>(dialog->ResolveControlByTag(0x444c4f47));
  if (goldControl == 0) {
    MessageBoxA(0, reinterpret_cast<const char*>(kAddrStrNilPointer),
                reinterpret_cast<const char*>(kAddrStrFailure), 0x30);
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
undefined TMacViewMgr::EnsureClipRegionWrapperAtSlotAndMergeSourceRegion(undefined4 param_1,
                                                                         short param_2) {
  if (regionSlots[param_2] == 0) {
    regionSlots[param_2] = CreateClipStateRegionWrapperObject();
  }
  CombineOptionalSourceRegionIntoDestinationAndUpdateBox(
      reinterpret_cast<ClipStateRegionWrapper*>(param_1), regionSlots[param_2]);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050d6c0
undefined TMacViewMgr::WrapperFor_IsPointInsideHitRegion_At0050d6c0(short tileIndex) {
  if (regionSlots[tileIndex] != 0) {
    return QueryPointInsideHitRegion(0, 0, regionSlots[tileIndex]);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050d700
undefined TMacViewMgr::RenderOffscreenBitmapTileSpanAndRestoreContext(int param_1) {
  undefined4 savedContext;
  undefined4 savedFlags;
  RECT resourceBounds;
  int gworldHandle = param_1;
  regionSlots[param_1] = CreateClipStateRegionWrapperObject();
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  int** loaderHandle = WrapperFor_AllocateWithFallbackHandler_At004a1130(param_1 + 4000);
  CopyRect(&resourceBounds, reinterpret_cast<RECT*>(reinterpret_cast<char*>(*loaderHandle) + 8));
  g_pDisplayMgr->Helper_Uses_thunk_Cluster_GameplayHint_004962c0_At004feab0(reinterpret_cast<undefined4*>(&gworldHandle), 1, &resourceBounds);
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(resourceBounds.right), savedFlags);
  ReturnConstantTrueQuickDrawFlag(GetSurfaceObjectAtContextOffset24(resourceBounds.right));
  NoOpRuntimeCallback_00497c00(loaderHandle);
  if (*loaderHandle != 0) {
    ResetQuickDrawStrokeState();
    WrapperFor_thunk_ResolveBmpResourceHandleWithDefault3B6_At00495c40(loaderHandle, &resourceBounds);
    ReleaseBitmapLoaderHandle(loaderHandle);
  }
  void* surfaceObject = GetSurfaceObjectAtContextOffset24(resourceBounds.right);
  if (RebuildSpriteNonTransparentPolygonRegion(regionSlots[param_1], surfaceObject) != 0) {
    RebuildSpriteNonTransparentPolygonRegion(regionSlots[param_1], surfaceObject);
    RebuildSpriteNonTransparentPolygonRegion(regionSlots[param_1], surfaceObject);
  }
  int surfaceContext = resourceBounds.right;
  WrapperFor_FreeHeapBufferIfNotNull_At004feb50(reinterpret_cast<undefined4*>(&surfaceContext));
  NoOpQuickDrawLifecycleHookB(GetSurfaceObjectAtContextOffset24(resourceBounds.right));
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(savedContext), savedFlags);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050d8d0
undefined TMacViewMgr::OrphanLeaf_NoCall_Ins06_0050d8d0() {
  if (field04 != 0) {
    reinterpret_cast<TView*>(field04)->InvalidateOffsetRegionUsingChildClipRect(0);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050d8f0
undefined TMacViewMgr::OrphanLeaf_NoCall_Ins06_0050d8f0(short param_1) {
  if (field04 != 0) {
    *reinterpret_cast<int*>(reinterpret_cast<char*>(field04) + 0xac + param_1 * 4) = 0;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050d920
undefined TMacViewMgr::OrphanCallChain_C1_I10_0050d920() {
  if (field04 != 0) {
    reinterpret_cast<TView*>(field04)->RefreshCityProductionViewStateFromContext(0);
  }
  field04 = 0;
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050d950
undefined TMacViewMgr::WrapperFor_CallObjectOffset24Vslot54IfPresent_At0050d950() {
  TView* hostView = g_pDisplayMgr->activeDialog;
  GoldDialogControl* goldControl =
      reinterpret_cast<GoldDialogControl*>(hostView->ResolveControlByTag(0x444c4f47));
  if (goldControl == 0) {
    MessageBoxA(0, reinterpret_cast<const char*>(kAddrStrNilPointer),
                reinterpret_cast<const char*>(kAddrStrFailure), 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  goldControl->gold71();
  goldControl->SetGoldControlStateByResource(0, 0);
  InvokeCallObjectOffset24Vslot54IfPresent();
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050d9e0
undefined TMacViewMgr::CopySpriteSurfaceToStrideBuffer(int* param_1, undefined4* param_2,
                                                       short param_3) {
  int spriteHeader = *reinterpret_cast<int*>(param_1[0] + 0x18);
  undefined4* srcRow = *reinterpret_cast<undefined4**>(spriteHeader + 0xc);
  short srcStridePacked = *reinterpret_cast<short*>(*reinterpret_cast<int*>(spriteHeader + 0x10) + 4);
  unsigned int rowWidth = *reinterpret_cast<unsigned int*>(*reinterpret_cast<int*>(spriteHeader + 0x10) + 4);
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
undefined TMacViewMgr::BlitMapOverlayGlyphStrip32x24SkipMask10(int* param_1, short param_2,
                                                                short param_3, short param_4) {
  int* atlasSurface;
  short srcRowOffset;
  if (param_2 < 100) {
    atlasSurface = reinterpret_cast<int*>(GetSurfaceObjectAtContextOffset24(atlas674));
    srcRowOffset = static_cast<short>(param_2 << 5);
  } else {
    atlasSurface = reinterpret_cast<int*>(GetSurfaceObjectAtContextOffset24(atlas680));
    srcRowOffset = static_cast<short>((param_2 - 100) * 0x20);
  }
  ushort dstStrideRaw = *reinterpret_cast<ushort*>(*param_1 + 4);
  ReturnConstantTrueQuickDrawFlag(atlasSurface);
  int srcPixels = reinterpret_cast<int>(GetSurfaceHeaderFromSurfaceObject(atlasSurface));
  ushort srcStrideRaw = *reinterpret_cast<ushort*>(*atlasSurface + 4);
  int dstPixels = reinterpret_cast<int>(GetSurfaceHeaderFromSurfaceObject(param_1));
  int dstStrideBytes = static_cast<int>(static_cast<short>(dstStrideRaw & 0x3fff));
  char* srcRow = reinterpret_cast<char*>(srcPixels + srcRowOffset);
  char* dstRow = reinterpret_cast<char*>(dstPixels + param_4 * dstStrideBytes + param_3);
  int rowsRemaining = 0x18;
  do {
    if (srcRow[0] != '\x10') dstRow[0] = srcRow[0];
    if (srcRow[1] != '\x10') dstRow[1] = srcRow[1];
    if (srcRow[2] != '\x10') dstRow[2] = srcRow[2];
    if (srcRow[3] != '\x10') dstRow[3] = srcRow[3];
    if (srcRow[4] != '\x10') dstRow[4] = srcRow[4];
    if (srcRow[5] != '\x10') dstRow[5] = srcRow[5];
    if (srcRow[6] != '\x10') dstRow[6] = srcRow[6];
    if (srcRow[7] != '\x10') dstRow[7] = srcRow[7];
    if (srcRow[8] != '\x10') dstRow[8] = srcRow[8];
    if (srcRow[9] != '\x10') dstRow[9] = srcRow[9];
    if (srcRow[10] != '\x10') dstRow[10] = srcRow[10];
    if (srcRow[0x0b] != '\x10') dstRow[0x0b] = srcRow[0x0b];
    if (srcRow[0x0c] != '\x10') dstRow[0x0c] = srcRow[0x0c];
    if (srcRow[0x0d] != '\x10') dstRow[0x0d] = srcRow[0x0d];
    if (srcRow[0x0e] != '\x10') dstRow[0x0e] = srcRow[0x0e];
    if (srcRow[0x0f] != '\x10') dstRow[0x0f] = srcRow[0x0f];
    if (srcRow[0x10] != '\x10') dstRow[0x10] = srcRow[0x10];
    if (srcRow[0x11] != '\x10') dstRow[0x11] = srcRow[0x11];
    if (srcRow[0x12] != '\x10') dstRow[0x12] = srcRow[0x12];
    if (srcRow[0x13] != '\x10') dstRow[0x13] = srcRow[0x13];
    if (srcRow[0x14] != '\x10') dstRow[0x14] = srcRow[0x14];
    if (srcRow[0x15] != '\x10') dstRow[0x15] = srcRow[0x15];
    if (srcRow[0x16] != '\x10') dstRow[0x16] = srcRow[0x16];
    if (srcRow[0x17] != '\x10') dstRow[0x17] = srcRow[0x17];
    if (srcRow[0x18] != '\x10') dstRow[0x18] = srcRow[0x18];
    if (srcRow[0x19] != '\x10') dstRow[0x19] = srcRow[0x19];
    if (srcRow[0x1a] != '\x10') dstRow[0x1a] = srcRow[0x1a];
    if (srcRow[0x1b] != '\x10') dstRow[0x1b] = srcRow[0x1b];
    if (srcRow[0x1c] != '\x10') dstRow[0x1c] = srcRow[0x1c];
    if (srcRow[0x1d] != '\x10') dstRow[0x1d] = srcRow[0x1d];
    if (srcRow[0x1e] != '\x10') dstRow[0x1e] = srcRow[0x1e];
    if (srcRow[0x1f] != '\x10') dstRow[0x1f] = srcRow[0x1f];
    rowsRemaining = rowsRemaining - 1;
    dstRow = dstRow + dstStrideBytes;
    srcRow = srcRow + static_cast<short>(srcStrideRaw & 0x3fff);
  } while (rowsRemaining != 0);
  NoOpQuickDrawLifecycleHookB(atlasSurface);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050dd40
void TMacViewMgr::DrawStrategicMapUnitIcon(int* pDstSurface, short nIconVariant, short nDstX,
                                           short nYShift) {
  int* atlasSurface =
      reinterpret_cast<int*>(GetSurfaceObjectAtContextOffset24(unitIconAtlas));
  ReturnConstantTrueQuickDrawFlag(atlasSurface);
  int srcPixels = reinterpret_cast<int>(GetSurfaceHeaderFromSurfaceObject(atlasSurface));
  ushort srcStrideRaw = *reinterpret_cast<ushort*>(*atlasSurface + 4);
  int dstPixels = reinterpret_cast<int>(GetSurfaceHeaderFromSurfaceObject(pDstSurface));
  int dstStrideBytes =
      static_cast<int>(static_cast<short>(*reinterpret_cast<ushort*>(*pDstSurface + 4) & 0x3fff));
  char* srcRow = reinterpret_cast<char*>(srcPixels + static_cast<short>(nIconVariant * 0x14));
  char* dstRow = reinterpret_cast<char*>(dstPixels + (0x28 - nYShift) * dstStrideBytes +
                                       static_cast<int>(nDstX));
  int rowsRemaining = 0x18;
  do {
    if (srcRow[0] != '\x10') dstRow[0] = srcRow[0];
    if (srcRow[1] != '\x10') dstRow[1] = srcRow[1];
    if (srcRow[2] != '\x10') dstRow[2] = srcRow[2];
    if (srcRow[3] != '\x10') dstRow[3] = srcRow[3];
    if (srcRow[4] != '\x10') dstRow[4] = srcRow[4];
    if (srcRow[5] != '\x10') dstRow[5] = srcRow[5];
    if (srcRow[6] != '\x10') dstRow[6] = srcRow[6];
    if (srcRow[7] != '\x10') dstRow[7] = srcRow[7];
    if (srcRow[8] != '\x10') dstRow[8] = srcRow[8];
    if (srcRow[9] != '\x10') dstRow[9] = srcRow[9];
    if (srcRow[0x0b] != '\x10') dstRow[0x0b] = srcRow[0x0b];
    if (srcRow[0x0c] != '\x10') dstRow[0x0c] = srcRow[0x0c];
    if (srcRow[0x0d] != '\x10') dstRow[0x0d] = srcRow[0x0d];
    if (srcRow[0x0e] != '\x10') dstRow[0x0e] = srcRow[0x0e];
    if (srcRow[0x0f] != '\x10') dstRow[0x0f] = srcRow[0x0f];
    if (srcRow[0x10] != '\x10') dstRow[0x10] = srcRow[0x10];
    if (srcRow[0x11] != '\x10') dstRow[0x11] = srcRow[0x11];
    if (srcRow[0x12] != '\x10') dstRow[0x12] = srcRow[0x12];
    if (srcRow[0x13] != '\x10') dstRow[0x13] = srcRow[0x13];
    rowsRemaining = rowsRemaining - 1;
    dstRow = dstRow + dstStrideBytes;
    srcRow = srcRow + static_cast<short>(srcStrideRaw & 0x3fff);
  } while (rowsRemaining != 0);
  NoOpQuickDrawLifecycleHookB(atlasSurface);
}

// FUNCTION: IMPERIALISM 0x0050df40
void TMacViewMgr::DrawStrategicMapUnitIconOverlay(int* pDstSurface, ushort wOverlayIconId,
                                                  short nVariantRow, short nDstX, short nYShift) {
  if (nVariantRow <= 0) {
    return;
  }
  short overlaySourceRow =
      reinterpret_cast<short*>(kAddrStrategicMapOverlaySourceRowByIconId)[wOverlayIconId];
  if (overlaySourceRow < 0) {
    return;
  }
  int* atlasSurface =
      reinterpret_cast<int*>(GetSurfaceObjectAtContextOffset24(unitOverlayAtlas));
  ReturnConstantTrueQuickDrawFlag(atlasSurface);
  int srcPixels = reinterpret_cast<int>(GetSurfaceHeaderFromSurfaceObject(atlasSurface));
  ushort srcStrideRaw = *reinterpret_cast<ushort*>(*atlasSurface + 4);
  int dstPixels = reinterpret_cast<int>(GetSurfaceHeaderFromSurfaceObject(pDstSurface));
  int dstStrideBytes =
      static_cast<int>(static_cast<short>(*reinterpret_cast<ushort*>(*pDstSurface + 4) & 0x3fff));
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

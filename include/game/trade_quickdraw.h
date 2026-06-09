#pragma once

#include "decomp_types.h"
#include "game/GameAssert.h"
#include "game/TControl.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/ui_widget_thunks.h"

undefined4 ApplyHitRegionToClipState(void);
void SnapshotHitRegionToClipCache(int* clipDescriptor);
undefined4 thunk_ApplyRectClipRegionToGlobalClipState(void);
undefined4 thunk_SetQuickDrawTextOriginWithContextOffset(void);
undefined4 ResetQuickDrawStrokeState(void);
undefined4 thunk_SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(void);
undefined4 thunk_DrawCenteredGuideLineOnMapDc(void);
undefined4 thunk_RenderHintHelperWithCtrlModifierOverlay(void);
undefined4 UpdatePaletteIndexWithDefaultFallback(void);
undefined4 BlitRectWithOptionalTransparency(void);
undefined4 ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(void);

static __inline void SetQuickDrawTextOrigin(short x, short y) {
  reinterpret_cast<void(__cdecl*)(short, short)>(thunk_SetQuickDrawTextOriginWithContextOffset)(x,
                                                                                                y);
}

static __inline void DrawCenteredGuideLine(short x, short y) {
  reinterpret_cast<void(__cdecl*)(short, short)>(thunk_DrawCenteredGuideLineOnMapDc)(x, y);
}

static __inline void SetQuickDrawStylePair(short styleA, short styleB) {
  reinterpret_cast<void(__cdecl*)(short, short)>(
      thunk_SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty)(styleA, styleB);
}

static __inline void ApplyRectClipRegion(int* rectBuffer) {
  reinterpret_cast<void(__cdecl*)(int*)>(thunk_ApplyRectClipRegionToGlobalClipState)(rectBuffer);
}

// SetQuickDrawFillColor(int) is the real global at 0x495000, declared in
// quickdraw_guards.h (included above).

static __inline void CallUiRuntimeSlot34(UiRuntimeContext* runtimeContext, int styleIndex) {
  runtimeContext->ApplyLegendSplitSlot34(styleIndex);
}
typedef void* hwnd_t;

const int kControlTagMove = 0x6d6f7665;
const int kControlTagSell = 0x53656c6c;
const int kControlTagAvai = 0x61766169;
const int kControlTagCard = 0x63617264;
const int kControlTagOffr = 0x6f666672;
const int kControlTagGree = 0x67726565;
const int kControlTagLeft = 0x6c656674;
const int kControlTagRght = 0x72676874;
const int kSummaryTagFood = 0x666f6f64;
const int kSummaryTagPopu = 0x706f7075;
const int kSummaryTagProf = 0x70726f66;
const int kSummaryTagPowe = 0x706f7765;
const int kSummaryTagRail = 0x7261696c;
const int kSummaryTagIart = 0x74726169;
const unsigned int kAddrClassDescTAmtBar = 0x00662f80;
const unsigned int kAddrClassDescTAmtBarCluster = 0x00662f50;
const unsigned int kAddrActiveQuickDrawSurfaceContext = 0x006A1D60;
const unsigned int kAddrPrimaryRenderSurfaceContext = 0x006A30A8;

static __inline TControl* CallResolveControlByTagSlot94(void* owner, int tag) {
  return reinterpret_cast<TControl*(__fastcall*)(void*, int, int)>(
      (*reinterpret_cast<void***>(owner))[0x94 / 4])(owner, 0, tag);
}

static __inline TControl* ResolveOwnerControl(void* owner, int controlTag) {
  return CallResolveControlByTagSlot94(owner, controlTag);
}

static __inline int ReadIntAt(unsigned int address) {
  return *reinterpret_cast<int*>(address);
}

static __inline void* ReadPointerAt(unsigned int address) {
  return *reinterpret_cast<void**>(address);
}

static __inline void CallApplyMoveValueSlot1D0(void* context, int value) {
  reinterpret_cast<void(__fastcall*)(void*, int)>(
      (*reinterpret_cast<void***>(context))[0x1d0 / 4])(context, value);
}

extern const int kTradeSellPropagationTags[17];
extern const int kControlTagBar;
extern struct NationState* GetNationStateBySlot(short slot);
extern short QueryNationMetricBySlot(struct NationState* state, short metricSlot);
extern int QueryUiScreenModeRaw(struct UiRuntimeContext* context);
extern char CallControlFlagSlot1D8(TControl* control);
extern void CallControlActionSlot1E0(TControl* control);
extern char CallBoolSlot1DC(void* self);
extern void FailNilPointerInUSmallViews(int line);

// Underlying nil-pointer assert: report the (sourcePath, line) and bail. The
// per-file wrappers (e.g. FailNilPointerInUSmallViews) forward through here.
static __inline void FailNilPointerWithAssert(const char* sourcePath, int line) {
  GAME_FAIL_NIL_POINTER();
  reinterpret_cast<void(__cdecl*)(const char*, int)>(thunk_DestructTShipAndFreeIfOwned)(sourcePath,
                                                                                        line);
}

struct CityTradeProductionSlots {
  char pad_00[4];
  short valueAt4;
  short valueAt6;
  short valueAt8;
};

struct CityTradeScenarioDescriptor {
  char pad_00[0x14];
  CityTradeProductionSlots* productionSlots;
  char pad_18[6];
  short extraAt1E;
};

struct NationCityTradeState {
  char pad_00[0xe4];
  struct TradeCommodityMetricRecord* tradeCommodityRecordPtrs[32];
  char pad_164[0x2c];
  struct TradeCommodityMetricRecord* specialCommodityRecordAt190;
  char pad_194[0x44];
  CityTradeScenarioDescriptor* scenarioTradeDescriptor;
};

const unsigned int kAddrClassDescTIndustryAmtBar = 0x00662fb0;
const unsigned int kAddrClassDescTRailAmtBar = 0x00662fe0;
const unsigned int kAddrClassDescTShipAmtBar = 0x00663010; // Guessed based on pattern
const unsigned int kAddrGlobalNationStates = 0x006A4370;

static __inline struct NationState* GetActiveNationState(void) {
  return reinterpret_cast<struct NationState**>(
      kAddrGlobalNationStates)[g_pUiRuntimeContext->GetActiveNationId()];
}

struct TradeSummarySelectionMap {
  int summaryTags[32];
};

const unsigned int kAddrTradeSummarySelectionMap = 0x006960e0;

static __inline int GetTradeSummarySelectionTagByIndex(short index) {
  TradeSummarySelectionMap* selectionMap =
      reinterpret_cast<TradeSummarySelectionMap*>(kAddrTradeSummarySelectionMap);
  return selectionMap->summaryTags[index];
}

static __inline void* CallOwnerPanelSlot58(void* self) {
  return reinterpret_cast<void*(__fastcall*)(void*)>((*reinterpret_cast<void***>(self))[0x58 / 4])(
      self);
}

static __inline void ApplyQuickDrawStyleFromRuntime(short styleIndex) {
  if (g_pUiRuntimeContext == 0) {
    return;
  }
  CallUiRuntimeSlot34(g_pUiRuntimeContext, styleIndex);
}

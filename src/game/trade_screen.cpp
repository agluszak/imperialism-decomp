// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#include "decomp_types.h"
#include "game/ui_widget_shared.h"

typedef void* hwnd_t;
typedef void code(void);
extern "C" int __stdcall MessageBoxA(hwnd_t hWnd, const char* text, const char* caption,
                                     unsigned int type);
struct tagRECT {
  int left;
  int top;
  int right;
  int bottom;
};
typedef tagRECT RECT;
extern "C" int __stdcall OffsetRect(RECT* lprc, int dx, int dy);
extern "C" int __stdcall CopyRect(RECT* lprcDst, const RECT* lprcSrc);
undefined4 TemporarilyClearAndRestoreUiInvalidationFlag(void);
undefined4 thunk_InvalidateCityDialogRectRegion(void);
unsigned int __cdecl thunk_GetActiveNationId(void);
void __fastcall InitializeTradeMoveAndBarControls(void* context, int unusedEdx,
                                                  unsigned int styleSeed);
undefined4 thunk_InitializeTradeMoveAndBarControls(void);
undefined4 thunk_NoOpUiLifecycleHook(void);
undefined4 thunk_BuildUiTextStyleDescriptor(void);
undefined4 thunk_DestructTShipAndFreeIfOwned(void);
undefined4 thunk_GetCityBuildingProductionValueBySlot(void);
void __fastcall HandleTradeMoveControlAdjustment(void* context, int commandId, void* eventArg,
                                                 int eventExtra);
void __fastcall thunk_HandleTradeMoveControlAdjustment(void* context, int commandId, void* eventArg,
                                                       int eventExtra);
undefined4 thunk_HandleCityDialogToggleCommandOrForward(void);
undefined4 thunk_HandleCursorHoverSelectionByChildHitTestAndFallback(void);
undefined4 ActivateFirstIdleTacticalUnitByCategoryAtTile(void);
undefined4 ActivateFirstActiveTacticalUnitByCategoryAtTile(void);
int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 ConstructTUberClusterBaseState(void);
undefined4 thunk_ConstructUiResourceEntryType4B0C0(void);
undefined4 thunk_ConstructUiClickablePictureResourceEntry(void);
undefined4 thunk_ConstructPictureResourceEntryBase(void);
undefined4 thunk_DestructEngineerDialogBaseState(void);
undefined4 thunk_DestructCityDialogSharedBaseState(void); // GHIDRA_FUNCTION IMPERIALISM 0x004601B0
undefined4 thunk_DispatchPictureResourceCommand(void);
undefined4 thunk_DispatchPanelControlEvent(void);
undefined4 thunk_GetTickCountDiv16(void);
undefined4 thunk_InitializeUiTextStyleDescriptor(void);
undefined4 thunk_ConstructUiTabCursorPictureEntry(void);
undefined4 DispatchUiMouseEventToChildrenOrSelf(void);
undefined4 AcquireReusableQuickDrawSurface(void);
undefined4 ReleaseOrCacheQuickDrawSurface(void);
undefined4 ApplyHitRegionToClipState(void);
undefined4 SnapshotHitRegionToClipCache(void);
undefined4 thunk_ApplyRectClipRegionToGlobalClipState(void);
undefined4 thunk_SetQuickDrawTextOriginWithContextOffset(void);
undefined4 SetQuickDrawFillColor(void);
undefined4 ResetQuickDrawStrokeState(void);
undefined4 thunk_SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(void);
undefined4 thunk_DrawCenteredGuideLineOnMapDc(void);
undefined4 thunk_RenderHintHelperWithCtrlModifierOverlay(void);
undefined4 UpdatePaletteIndexWithDefaultFallback(void);
undefined4 BlitRectWithOptionalTransparency(void);
undefined4 ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(void);
undefined4 FormatStringWithVarArgsToSharedRef(void);
undefined4 thunk_MeasureTextExtentWithCachedQuickDrawStyle(void);
undefined4 thunk_DrawTextWithCachedQuickDrawStyleState(void);
int* InitializeSharedStringRefFromEmpty(int* dst_ref_ptr);
void ReleaseSharedStringRefIfNotEmpty(int* ref_ptr);
void __fastcall HandleTradeArrowAutoRepeatTickAndDispatch(void* self, int unusedEdx,
                                                          int repeatState, void* arg8, void* argC,
                                                          void* dispatchArg, void* arg14);
// GHIDRA_NAME: InitializeTradeScreenBitmapControls
// GHIDRA_PROTO: undefined InitializeTradeScreenBitmapControls()
/* DECOMPILATION FAILED: Exception while decompiling 004601b0: process: timeout */

namespace {

const char kNilPointerText[] = "Nil Pointer";
const char kFailureCaption[] = "Failure";
const char kUSmallViewsCppPath[] = "D:\\Ambit\\Cross\\USmallViews.cpp";
const char kUSuperMapCppPath[] = "D:\\Ambit\\Cross\\USuperMap.cpp";

const int kControlTagSell = 0x53656c6c;
const int kControlTagBar = 0x62617220;
const int kControlTagMove = 0x6d6f7665;
const int kControlTagAvai = 0x61766169;
const int kControlTagCard = 0x63617264;
const int kControlTagBack = 0x6261636b;
const int kControlTagOffr = 0x6f666672;
const int kControlTagGree = 0x67726565;
const int kControlTagLeft = 0x6c656674;
const int kControlTagRght = 0x72676874;
const int kControlTagArms = 0x41726d73;
const int kControlTagClos = 0x436c6f73;
const int kSummaryTagFood = 0x666f6f64;
const int kSummaryTagPopu = 0x706f7075;
const int kSummaryTagProf = 0x70726f66;
const int kSummaryTagPowe = 0x706f7765;
const int kSummaryTagRail = 0x7261696c;
const int kSummaryTagIart = 0x74726169;
const int kAssertLineBidSecondary = 0x907;
const int kAssertLineBidActionable = 0x8de;
const int kAssertLineOfferActionable = 0x8f2;
const int kAssertLineBidControl = 0x92e;
const int kAssertLineBidGree = 0x93f;
const int kAssertLineBidLeft = 0x941;
const int kAssertLineBidRight = 0x943;
const int kAssertLineOfferControl = 0x95c;
const int kAssertLineOfferGree = 0x970;
const int kAssertLineOfferLeft = 0x972;
const int kAssertLineOfferRight = 0x974;
const int kAssertLineOfferSecondaryOffr = 0x98f;
const int kAssertLineOfferSecondaryGree = 0x9ad;
const int kAssertLineOfferSecondaryLeft = 0x9af;
const int kAssertLineOfferSecondaryRight = 0x9b1;
const int kAssertLineInitBar = 0x7a2;
const int kAssertLineInitLeft = 0x7a6;
const int kAssertLineInitRight = 0x7a8;
const int kAssertLineInitGree = 0x7b8;
const int kAssertLineUpdateSell = 0x9e0;
const int kAssertLineUpdateBar = 0x9e4;
const int kAssertLineUpdateGree = 0x9e7;
const int kAssertLineRatioB = 0xb73;
const int kAssertLineRatioA = 0xd1d;
const int kAssertLineMoveBarInitNil = 0x725;
const int kAssertLineMoveAdjustMove = 0x749;
const int kAssertLineMoveAdjustAvai = 0x74d;
const int kAssertLineMoveAdjustMoveMinus = 0x759;
const int kAssertLineTradeSummaryRtnu = 0x67d;
const int kAssertLineTradeSummaryIart = 0x682;
const int kAssertLineTradeSummaryProf = 0x687;
const int kAssertLineTradeSellIncSell = 0x816;
const int kAssertLineTradeSellIncCap = 0x81d;
const int kAssertLineMovePageMinus = 0xd34;
const int kAssertLineMovePagePlus = 0xd3c;
const int kAssertLineToolSubcontrolToggle = 0xac7;
const unsigned int kVtableTIndustryCluster = 0x00665ed0;
const unsigned int kAddrClassDescTIndustryCluster = 0x00662f98;
const unsigned int kVtableTIndustryAmtBar = 0x00666110;
const unsigned int kAddrClassDescTIndustryAmtBar = 0x00662fb0;
const unsigned int kVtableTAmtBar = 0x00665cc8;
const unsigned int kAddrClassDescTAmtBar = 0x00662f80;
const unsigned int kVtableTAmtBarCluster = 0x00665838;
const unsigned int kAddrClassDescTAmtBarCluster = 0x00662f50;
const unsigned int kVtableTProductionCluster = 0x006653c8;
const unsigned int kAddrClassDescTProductionCluster = 0x00662f20;
const unsigned int kVtableTClosePicture = 0x00665608;
const unsigned int kAddrClassDescTClosePicture = 0x00662f38;
const unsigned int kVtableTRailCluster = 0x00666318;
const unsigned int kAddrClassDescTRailCluster = 0x00662fc8;
const unsigned int kVtableTRailAmtBar = 0x00666558;
const unsigned int kAddrClassDescTRailAmtBar = 0x00662fe0;
const unsigned int kVtableTShipyardCluster = 0x00666760;
const unsigned int kAddrClassDescTShipyardCluster = 0x00662ff8;
const unsigned int kVtableTUnitToolbarCluster = 0x00664d38;
const unsigned int kAddrClassDescTUnitToolbarCluster = 0x00662ed8;
const unsigned int kVtableTButton = 0x0064a2b8;
const unsigned int kVtableTStatusButton = 0x00664f68;
const unsigned int kAddrClassDescTStatusButton = 0x00662ef0;
const unsigned int kVtableTCityBarCluster = 0x00665190;
const unsigned int kAddrClassDescTCityBarCluster = 0x00662f08;
const unsigned int kAddrTradeSummarySelectionMap = 0x006960e0;
const unsigned int kAddrDecimalFormat = 0x0069430C;
const unsigned int kAddrActiveQuickDrawSurfaceContext = 0x006A1D60;
const unsigned int kAddrStrategicMapViewSystem = 0x006A21A8;
const unsigned int kAddrGlobalMapState = 0x006A43D4;
const unsigned int kAddrOverlayClipCacheParamX = 0x006A4450;
const unsigned int kAddrOverlayClipCacheParamY = 0x006A4454;

// Symbol placeholders to preserve OFFSET-style codegen in ctor/dtor wrappers.
// GLOBAL: IMPERIALISM 0x666998
char g_vtblTShipAmtBar;
// GLOBAL: IMPERIALISM 0x663010
char g_pClassDescTShipAmtBar;
char g_vtblTTraderAmtBar;
// GLOBAL: IMPERIALISM 0x663028
char g_pClassDescTTraderAmtBar;
// GLOBAL: IMPERIALISM 0x662f68
char g_pClassDescTTradeCluster;
char PTR_thunk_GetTTradeClusterClassNamePointer_00665a70;

const short kTradeBitmapBidStateA = 0x083f;
const short kTradeBitmapBidStateB = 0x084d;
const short kTradeBitmapBidSecondaryStateA = 0x0840;
const short kTradeBitmapBidSecondaryStateB = 0x084e;
const short kTradeBitmapOfferStateA = 0x0841;
const short kTradeBitmapOfferStateB = 0x084f;
const short kTradeBitmapOfferSecondaryStateA = 0x0842;
const short kTradeBitmapOfferSecondaryStateB = 0x0850;
const int kTradeRowStateTag_67643020 = 0x67643020;
const int kTradeSellPropagationTags[] = {
    0x72733020, 0x72733120, 0x72733220, 0x72733320, 0x72733420, 0x72733520,
    0x72733620, 0x6d613020, 0x6d613120, 0x6d613220, 0x6d613320, 0x6d613420,
    0x6d613520, 0x67643020, 0x67643120, 0x67643220, 0x67643320,
};
const unsigned int kAddrGlobalNationStates = 0x006A4370;

struct UiRuntimeContext;
struct NationCityTradeState;
struct TradeMovePanelContext;
struct TradeCommodityMetricRecord;
struct CityTradeScenarioDescriptor;

struct NationState {
  void* vftable;
  char pad_04[0xa0];
  short tradeCapacity;
  char pad_a6[0x7ee];
  NationCityTradeState* cityState;
};

struct TradeBarControlLayout {
  void* vftable;
  char pad_04[0x30];
  short barRange;
  char pad_36[0x2e];
  short barSteps;
};

struct TradeAmountBarLayout {
  void* vftable;
  char pad_04[0x5c];
  short rangeOrMaxValue;
  short stepOrCurrentValue;
  short auxValueA;
  short auxValueB;

  void UpdateNationStateGaugeValuesFromScenarioRecordCode();
};

struct TradeMoveStepCluster {
  void* vftable;
  char pad_04[0x84];
  int field_88;
  short field_8c;
  short field_8e;
  int field_90;
  int field_94;

  void HandleTradeMovePageStepCommand(int commandId, void* eventArg, int eventExtra);
  void SelectTradeSpecialCommodityAndInitializeControls();
  void RefreshTradeMoveBarAndTurnControl();
  void HandleTradeMoveArrowControlEvent(int commandId, TradeControl* sourceControl, int eventExtra);
  void OrphanTiny_SetWordEcxOffset_8c_00586a60(short value);
  void OrphanLeaf_NoCall_Ins05_00586a80(int value90, int value94);
  void OrphanTiny_SetWordEcxOffset_8e_00586ab0(short value);
};

struct ProductionClusterState {
  void* vftable;
  char pad_04[0x84];
  int field_88;
  short field_8c;
  short field_8e;
  int field_90;
  int field_94;
};

struct TAmtBarClusterContext {
  void* vftable;
  char pad_04[0x84];
  short metricSlotAt88;
  short pad_8a;
  short valueAt8c;
  short valueAt8e;

  void HandleTradeSellControlCommand(int commandId, void* eventArg, int eventExtra);
};

struct ClosePictureState {
  void* vftable;
  char pad_04[0x18];
  int ownerDescriptorAt1c;
  char pad_20[0x74];
};

struct IndustryAmtBarState {
  void* vftable;
  char pad_04[0x1c];
  TradeMovePanelContext* ownerPanelContext;
  char pad_24[0x10];
  int barRangeRaw;
  char pad_38[0x28];
  short cachedRangeAt60;
  short cachedRatioAt62;
  short cachedProductionAt64;
  short cachedStyleAt66;
  TradeCommodityMetricRecord* selectedMetricRecord;

  IndustryAmtBarState* ConstructTRailAmtBarBaseState();
  IndustryAmtBarState* DestructTRailAmtBarAndMaybeFree(unsigned char freeSelfFlag);
  void SelectTradeSummaryMetricByTagAndUpdateBarValues();
  IndustryAmtBarState* ConstructTShipAmtBarBaseState();
  IndustryAmtBarState* DestructTShipAmtBarAndMaybeFree(unsigned char freeSelfFlag);
  void SelectTradeSpecialCommodityAndRecomputeBarLimits(int passthroughArg);
};

struct TradeCommodityMetricRecord {
  void* vftable;
  short controlValue;
  char pad_06[0x4c];
  short buildingSlot;

  __inline short QueryStepValue();
};

struct NationCityTradeState {
  char pad_00[0xe4];
  TradeCommodityMetricRecord* tradeCommodityRecordPtrs[32];
  char pad_164[0x2c];
  TradeCommodityMetricRecord* specialCommodityRecordAt190;
  char pad_194[0x44];
  CityTradeScenarioDescriptor* scenarioTradeDescriptor;
};

struct CityTradeProductionSlots {
  char pad_00[4];
  short valueAt4;
  short valueAt6;
  short valueAt8;
};

struct CityTradeScenarioDescriptor {
  char pad_00[0x10];
  CityTradeProductionSlots* productionSlots;
  char pad_14[0xa];
  short extraAt1E;
};

struct TradeSummarySelectionMap {
  char pad_00[0x28];
  int summaryTags[32];
};

struct TradeMoveControlState;
struct TradeMovePanelContext;

struct TradeScreenContext {
  void* vftable;
  char pad_04[0x18];
  int rowStateTag;
  char pad_20[0x68];
  short tradeMetricSlot;

  __inline TradeControl* ResolveControlByTag(int controlTag);
  __inline TradeControl* RequireControlByTag(int controlTag);
  void InitializeTradeSellControlState(unsigned int styleSeed);
  short QueryTradeSellControlQuantity();
  char IsTradeBidControlActionable();
  char IsTradeOfferControlActionable();
  void SetTradeBidSecondaryBitmapState();
  void SetTradeBidControlBitmapState();
  void SetTradeOfferControlBitmapState();
  void SetTradeOfferSecondaryBitmapState();
  void UpdateTradeSellControlAndBarFromNationMetric(int metricClampMax);
  void SetTradeToolSubcontrolEnabledStateByFlag(unsigned char enabledFlag);
};

struct UiRuntimeContext {
  void* vftable;
};

struct ApplicationUiRootControllerState {
  void* vftable;
  char pad_04[0x20];
  int screenModeAt24;
};

struct UnitToolbarClusterState {
  void* vftable;
  char pad_04[0x84];
};

struct StatusButtonState {
  void* vftable;
  char pad_04[0x18];
  int controlTagAt1c;
  void* ownerPanelAt20;
  char pad_24[0x60];
};

struct CityBarClusterState {
  void* vftable;
  char pad_04[0x84];
};

static __inline TradeControl* CallResolveControlByTagSlot94(void* context, int controlTag) {
  return reinterpret_cast<TradeControl*(__fastcall*)(void*, int)>(
      (*reinterpret_cast<void***>(context))[0x94 / 4])(context, controlTag);
}

static __inline void CallApplyMoveValueSlot1D0(void* context, int value) {
  reinterpret_cast<void(__fastcall*)(void*, int)>((*reinterpret_cast<void***>(context))[0x1d0 / 4])(
      context, value);
}

static __inline void CallPostMoveValueSlot1D4(void* context, int value, int commitFlag) {
  reinterpret_cast<void(__fastcall*)(void*, int, int)>(
      (*reinterpret_cast<void***>(context))[0x1d4 / 4])(context, value, commitFlag);
}

static __inline void CallNotifyMoveUpdatedSlot1D8(void* context) {
  reinterpret_cast<void(__fastcall*)(void*)>((*reinterpret_cast<void***>(context))[0x1d8 / 4])(
      context);
}

static __inline short ReadControlValueFieldPlus4(TradeControl* control) {
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 4);
}

static __inline short CallQueryUiScreenModeSlot54(UiRuntimeContext* runtimeContext) {
  return reinterpret_cast<short(__fastcall*)(UiRuntimeContext*)>(
      (*reinterpret_cast<void***>(runtimeContext))[0x54 / 4])(runtimeContext);
}

static __inline void CallUiRuntimeSlot34(UiRuntimeContext* runtimeContext, int styleIndex) {
  reinterpret_cast<void(__fastcall*)(UiRuntimeContext*, int)>(
      (*reinterpret_cast<void***>(runtimeContext))[0x34 / 4])(runtimeContext, styleIndex);
}

static __inline void CallUiRuntimeSlot68(UiRuntimeContext* runtimeContext, int modeValue) {
  reinterpret_cast<void(__fastcall*)(UiRuntimeContext*, int)>(
      (*reinterpret_cast<void***>(runtimeContext))[0x68 / 4])(runtimeContext, modeValue);
}

static __inline char CallControlFlagSlot1D8(TradeControl* control) {
  return reinterpret_cast<char(__fastcall*)(TradeControl*)>(
      (*reinterpret_cast<void***>(control))[0x1d8 / 4])(control);
}

static __inline void CallControlActionSlot1E0(TradeControl* control) {
  reinterpret_cast<void(__fastcall*)(TradeControl*)>(
      (*reinterpret_cast<void***>(control))[0x1e0 / 4])(control);
}

static __inline short CallQueryNationMetricBySlot78(NationState* nationState, short metricSlot) {
  return reinterpret_cast<short(__fastcall*)(NationState*, short)>(
      (*reinterpret_cast<void***>(nationState))[0x78 / 4])(nationState, metricSlot);
}

static __inline short CallQueryNationMetricBySlot7C(NationState* nationState, short metricSlot) {
  return reinterpret_cast<short(__fastcall*)(NationState*, short)>(
      (*reinterpret_cast<void***>(nationState))[0x7c / 4])(nationState, metricSlot);
}

static __inline int CallQuerySelectedIndexSlotBC(void* self) {
  return reinterpret_cast<int(__fastcall*)(void*)>((*reinterpret_cast<void***>(self))[0xbc / 4])(
      self);
}

static __inline char CallBoolSlot28(void* self) {
  return reinterpret_cast<char(__fastcall*)(void*)>((*reinterpret_cast<void***>(self))[0x28 / 4])(
      self);
}

static __inline char CallBoolSlot1BC(void* self) {
  return reinterpret_cast<char(__fastcall*)(void*)>((*reinterpret_cast<void***>(self))[0x1bc / 4])(
      self);
}

static __inline char CallBoolSlot1DC(void* self) {
  return reinterpret_cast<char(__fastcall*)(void*)>((*reinterpret_cast<void***>(self))[0x1dc / 4])(
      self);
}

static __inline void CallVoidSlotA0(void* self) {
  reinterpret_cast<void(__fastcall*)(void*)>((*reinterpret_cast<void***>(self))[0xa0 / 4])(self);
}

static __inline void CallVoidSlot1C(void* self) {
  reinterpret_cast<void(__fastcall*)(void*)>((*reinterpret_cast<void***>(self))[0x1c / 4])(self);
}

static __inline void CallVoidSlotE4(void* self) {
  reinterpret_cast<void(__fastcall*)(void*)>((*reinterpret_cast<void***>(self))[0xe4 / 4])(self);
}

static __inline void* CallOwnerPanelSlot58(void* self) {
  return reinterpret_cast<void*(__fastcall*)(void*)>((*reinterpret_cast<void***>(self))[0x58 / 4])(
      self);
}

static __inline void FailNilPointerWithAssert(const char* sourcePath, int line);
static __inline void FailNilPointerInUSmallViews(int line);

struct TradeMoveControlState {
  void* vftable;
  char pad_04[0x1c];
  void* ownerContext;
  char pad_24[0x10];
  int barRangeRaw;
  char pad_38[0x2c];
  short barStepsRaw;

  void ClampAndApplyTradeMoveValue(int* requestedValuePtr);
};

struct TradeMovePanelContext {
  void* vftable;
  char pad_04[0x18];
  int summaryTag;
  void* ownerContext;
  int ownerOffsetX;
  int ownerOffsetY;
  char pad_2c[0x5c];
  TradeControl* selectedMetricControl;
  short selectedMetricValue;
  short selectedMetricStep;

  void OrphanCallChain_C1_I06_00588c30(int value);
  void HandleTradeMoveControlAdjustment(int commandId, void* eventArg, int eventExtra);
  void UpdateTradeMoveControlsFromDrag(int dragValue, int updateFlag);
  void UpdateTradeBarFromSelectedMetricRatio_B(void);
  void HandleTradeMoveStepCommand(int commandId, void* eventArg, int eventExtra);
  void OrphanCallChain_C1_I06_005899c0(int value);
  void UpdateTradeMoveControlsFromScaledDrag(int dragValue, int updateFlag);
  void UpdateTradeBarFromSelectedMetricRatio_A(void);
};

__inline short TradeCommodityMetricRecord::QueryStepValue() {
  return reinterpret_cast<TradeControl*>(this)->QueryStepValueSlot30();
}

__inline TradeControl* TradeScreenContext::ResolveControlByTag(int controlTag) {
  return CallResolveControlByTagSlot94(this, controlTag);
}

__inline TradeControl* TradeScreenContext::RequireControlByTag(int controlTag) {
  TradeControl* control = ResolveControlByTag(controlTag);
  if (control == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return 0;
  }
  return control;
}

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif

// FUNCTION: IMPERIALISM 0x00401b3b
void __fastcall thunk_HandleTradeArrowAutoRepeatTickAndDispatch(TradeControl* self, int unusedEdx,
                                                                int repeatState, void* arg8,
                                                                void* argC, void* dispatchArg,
                                                                void* arg14) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  HandleTradeArrowAutoRepeatTickAndDispatch(self, 0, repeatState, arg8, argC, dispatchArg, arg14);
}

// FUNCTION: IMPERIALISM 0x004032fb
void __fastcall thunk_SetTradeToolSubcontrolEnabledStateByFlag(TradeScreenContext* self,
                                                               int unusedEdx,
                                                               unsigned char enabledFlag) {
  (void)unusedEdx;
  self->SetTradeToolSubcontrolEnabledStateByFlag(enabledFlag);
}

static __inline void FailNilPointerWithAssert(const char* sourcePath, int line) {
  MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
  reinterpret_cast<void(__cdecl*)(const char*, int)>(thunk_DestructTShipAndFreeIfOwned)(sourcePath,
                                                                                         line);
}

static __inline void FailNilPointerInUSmallViews(int line) {
  FailNilPointerWithAssert(kUSmallViewsCppPath, line);
}

static __inline short QueryUiScreenMode(UiRuntimeContext* runtimeContext) {
  if (runtimeContext == 0 || runtimeContext->vftable == 0) {
    return 4;
  }
  return CallQueryUiScreenModeSlot54(runtimeContext);
}

static __inline short QueryUiScreenModeRaw(UiRuntimeContext* runtimeContext) {
  return CallQueryUiScreenModeSlot54(runtimeContext);
}

static __inline NationState* GetNationStateBySlot(short slotId) {
  NationState** ppNationStates = reinterpret_cast<NationState**>(kAddrGlobalNationStates);
  return ppNationStates[slotId];
}

static __inline NationCityTradeState* GetNationCityStateBySlot(short slotId) {
  NationState* nationState = GetNationStateBySlot(slotId);
  if (nationState == 0) {
    return 0;
  }
  return nationState->cityState;
}

static __inline int GetTradeSummarySelectionTagByIndex(short index) {
  TradeSummarySelectionMap* selectionMap =
      reinterpret_cast<TradeSummarySelectionMap*>(kAddrTradeSummarySelectionMap);
  return selectionMap->summaryTags[index];
}

static __inline short QueryNationMetricBySlot(NationState* nationState, short metricSlot) {
  return CallQueryNationMetricBySlot78(nationState, metricSlot);
}

static __inline short QueryNationTradeCapacity(NationState* nationState) {
  return nationState->tradeCapacity;
}

static __inline TradeControl* ResolveOwnerControl(void* owner, int controlTag) {
  return CallResolveControlByTagSlot94(owner, controlTag);
}

extern UiRuntimeContext* g_pUiRuntimeContext;

static __inline void ApplyQuickDrawStyleFromRuntime(short styleIndex) {
  if (g_pUiRuntimeContext == 0) {
    return;
  }
  CallUiRuntimeSlot34(g_pUiRuntimeContext, styleIndex);
}

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

static __inline void* ReadPointerAt(unsigned int address) {
  return *reinterpret_cast<void**>(address);
}

static __inline int ReadIntAt(unsigned int address) {
  return *reinterpret_cast<int*>(address);
}

// GLOBAL: IMPERIALISM 0x6a21bc
UiRuntimeContext* g_pUiRuntimeContext = 0;
// GLOBAL: IMPERIALISM 0x6a18e0
ApplicationUiRootControllerState* g_pApplicationUiRootController = 0;
// GLOBAL: IMPERIALISM 0x6a44b0
void* g_pActiveCityDialogLegendSelectionOwner = 0;
// GLOBAL: IMPERIALISM 0x6a44b4
unsigned char g_bCityDialogLegendSelectionInitialized = 0;

} // namespace

// Included by src/game/trade_screen.cpp.
// Contains trade-screen core logic functions (address-ordered).

// GHIDRA_NAME InitializeTradeSellControlState
// GHIDRA_PROTO void __cdecl InitializeTradeSellControlState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Initializes Sell/Bar/Arrow control style and enabled state for current
// nation/resource context; then initializes move/bar controls baseline. GHIDRA_COMMENT_END
/* Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context;
   then initializes move/bar controls baseline. */

// GHIDRA_NAME HandleTradeArrowAutoRepeatTickAndDispatch
// GHIDRA_PROTO void __thiscall HandleTradeArrowAutoRepeatTickAndDispatch(int repeatState, void *
// arg8, void * argC, void * dispatchArg, void * arg14) GHIDRA_COMMENT_BEGIN GHIDRA_COMMENT [Enum]
// Auto-repeat tick emits EArrowSplitCommandId::LEFT/RIGHT based on hit side/tag and repeat timing
// gates. GHIDRA_COMMENT_END
/* [Enum] Auto-repeat tick emits EArrowSplitCommandId::LEFT/RIGHT based on hit side/tag and repeat
   timing gates. */

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x00583bd0
void __fastcall HandleTradeArrowAutoRepeatTickAndDispatch(void* self, int unusedEdx, int repeatState,
                                                          void* arg8, void* argC,
                                                          void* dispatchArg, void* arg14) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  reinterpret_cast<void(__fastcall*)(void*, int, int, void*, void*, void*, void*)>(
      ::thunk_DispatchPictureResourceCommand)(self, 0, repeatState, arg8, argC, dispatchArg,
                                              arg14);

  if (repeatState == 2) {
    return;
  }

  unsigned int tick = (unsigned int)thunk_GetTickCountDiv16();
  int* repeatDeadline = reinterpret_cast<int*>(reinterpret_cast<char*>(self) + 0x94);
  if (tick < (unsigned int)(*repeatDeadline + 5)) {
    return;
  }

  tick = (unsigned int)thunk_GetTickCountDiv16();
  *repeatDeadline = (int)tick;
  if (repeatState == 0) {
    *repeatDeadline = (int)tick + 10;
  }

  TradeControl* selfControl = reinterpret_cast<TradeControl*>(self);
  char isActive = selfControl->CtrlSlot91(dispatchArg);
  if (isActive == '\0') {
    return;
  }

  if (*reinterpret_cast<int*>(reinterpret_cast<char*>(self) + 0x1c) == kControlTagRght) {
    selfControl->CtrlSlot16(100, 0, 0);
    return;
  }

  selfControl->CtrlSlot16(0x65, self, 0);
}

#if defined(_MSC_VER)
#pragma optimize("y", off)
#endif

// FUNCTION: IMPERIALISM 0x00585f70
UnitToolbarClusterState* __cdecl CreateTUnitToolbarClusterInstance(void) {
  UnitToolbarClusterState* cluster =
      reinterpret_cast<UnitToolbarClusterState*>(AllocateWithFallbackHandler(0x88));
  if (cluster != 0) {
    TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
    cluster->vftable = reinterpret_cast<void*>(kVtableTUnitToolbarCluster);
  }
  return cluster;
}

// FUNCTION: IMPERIALISM 0x00585ff0
void* __cdecl GetTUnitToolbarClusterClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTUnitToolbarCluster);
}

// FUNCTION: IMPERIALISM 0x00586010
UnitToolbarClusterState* __fastcall
ConstructTUnitToolbarClusterBaseState(UnitToolbarClusterState* cluster) {
  // ORIG_CALLCONV: __thiscall
  TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
  cluster->vftable = reinterpret_cast<void*>(kVtableTUnitToolbarCluster);
  return cluster;
}

// FUNCTION: IMPERIALISM 0x00586040
UnitToolbarClusterState* __fastcall
DestructTUnitToolbarClusterAndMaybeFree(UnitToolbarClusterState* cluster, int unusedEdx,
                                        unsigned char freeSelfFlag) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)cluster);
  }
  return cluster;
}

// FUNCTION: IMPERIALISM 0x00586090
void __fastcall WrapperFor_thunk_DispatchPanelControlEvent_At00586090(
    UnitToolbarClusterState* cluster, int eventClass, void* eventPayload, int eventFlags) {
  // ORIG_CALLCONV: __thiscall
  reinterpret_cast<void(__fastcall*)(void*, int, void*, int)>(thunk_DispatchPanelControlEvent)(
      cluster, eventClass, eventPayload, eventFlags);

  if (!(((g_pApplicationUiRootController->screenModeAt24 == 1) && (eventClass == 0x68)) ||
        (eventClass == 0x67) || (eventClass == 10) || (eventClass == 0x0c))) {
    return;
  }

  void* ownerPanel = reinterpret_cast<void*(__fastcall*)(UnitToolbarClusterState*)>(
      (*reinterpret_cast<void***>(cluster))[0x58 / 4])(cluster);
  TradeControl* mainControl = CallResolveControlByTagSlot94(ownerPanel, 0x6d61696e);
  if (mainControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return;
  }
  reinterpret_cast<void(__fastcall*)(TradeControl*)>(
      (*reinterpret_cast<void***>(mainControl))[0x3c / 4])(mainControl);
}

// FUNCTION: IMPERIALISM 0x00586150
unsigned char OrphanVtableAssignStub_00586150(void) {
  return 1;
}

// FUNCTION: IMPERIALISM 0x00586170
void UpdateTradeResourceSelectionByIndex(void* self, int nResourceIndex)

{
  // ORIG_CALLCONV: __thiscall
  int* panel = 0;
  int* control = 0;

  *reinterpret_cast<int*>(reinterpret_cast<char*>(self) + 0x84) = nResourceIndex;

  panel = reinterpret_cast<int*>(reinterpret_cast<void*(__fastcall*)(void*)>(
      (*reinterpret_cast<void***>(self))[0x58 / 4])(self));
  if (panel == 0) {
    return;
  }

  control = reinterpret_cast<int*>(reinterpret_cast<void*(__fastcall*)(void*, int)>(
      (*reinterpret_cast<void***>(panel))[0x94 / 4])(panel, 0x444c4f47));
  if (control == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return;
  }

  reinterpret_cast<void(__fastcall*)(void*, int, void*, int)>(
      (*reinterpret_cast<void***>(control))[0x3c / 4])(control, 0x0c, 0, 0);
}

// FUNCTION: IMPERIALISM 0x00586280
StatusButtonState* __cdecl CreateTStatusButtonInstance(void) {
  StatusButtonState* button =
      reinterpret_cast<StatusButtonState*>(AllocateWithFallbackHandler(0x84));
  if (button != 0) {
    reinterpret_cast<TControl*>(button)->thunk_ConstructUiCommandTagResourceEntryBase();
    button->vftable = reinterpret_cast<void*>(kVtableTButton);
    TemporarilyClearAndRestoreUiInvalidationFlag();
    button->vftable = reinterpret_cast<void*>(kVtableTStatusButton);
  }
  return button;
}

// FUNCTION: IMPERIALISM 0x00586310
void* __cdecl GetTStatusButtonClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTStatusButton);
}

// FUNCTION: IMPERIALISM 0x00586330
StatusButtonState* __fastcall ConstructTStatusButtonBaseState(StatusButtonState* button,
                                                              int unusedEdx) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  reinterpret_cast<TControl*>(button)->thunk_ConstructUiCommandTagResourceEntryBase();
  button->vftable = reinterpret_cast<void*>(kVtableTButton);
  TemporarilyClearAndRestoreUiInvalidationFlag();
  button->vftable = reinterpret_cast<void*>(kVtableTStatusButton);
  return button;
}

// FUNCTION: IMPERIALISM 0x005863b0
StatusButtonState* __fastcall DestructTStatusButtonAndMaybeFree(StatusButtonState* button,
                                                                int unusedEdx,
                                                                unsigned char freeSelfFlag) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)button);
  }
  return button;
}

// FUNCTION: IMPERIALISM 0x00586400
void __fastcall HandleCityDialogSelectionAndBackControlReset(StatusButtonState* button,
                                                             int unusedEdx, int selectedIndex) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;

  if (selectedIndex == CallQuerySelectedIndexSlotBC(button) && CallBoolSlot28(button) != '\0') {
    if (CallBoolSlot1BC(button) == '\0') {
      if (g_pActiveCityDialogLegendSelectionOwner != 0) {
        CallVoidSlotA0(g_pActiveCityDialogLegendSelectionOwner);
        g_pActiveCityDialogLegendSelectionOwner = 0;
        g_bCityDialogLegendSelectionInitialized = 0;
      }

      TradeControl* backControl =
          CallResolveControlByTagSlot94(button->ownerPanelAt20, kControlTagBack);
      if (backControl != 0) {
        CallVoidSlot1C(backControl);
        CallVoidSlotE4(button->ownerPanelAt20);
      }

      if (button->controlTagAt1c != kControlTagArms && button->controlTagAt1c == kControlTagClos) {
        if (g_pActiveCityDialogLegendSelectionOwner != 0) {
          CallVoidSlotA0(g_pActiveCityDialogLegendSelectionOwner);
          g_pActiveCityDialogLegendSelectionOwner = 0;
        }
        g_bCityDialogLegendSelectionInitialized = 0;
        void* ownerPanel = CallOwnerPanelSlot58(button);
        if (ownerPanel != 0) {
          CallVoidSlotA0(ownerPanel);
        }
      }
    }
  }

  thunk_HandleCityDialogToggleCommandOrForward();
}

// FUNCTION: IMPERIALISM 0x00586590
CityBarClusterState* __cdecl CreateTCityBarClusterInstance(void) {
  CityBarClusterState* cluster =
      reinterpret_cast<CityBarClusterState*>(AllocateWithFallbackHandler(0x88));
  if (cluster != 0) {
    TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
    cluster->vftable = reinterpret_cast<void*>(kVtableTCityBarCluster);
  }
  return cluster;
}

// FUNCTION: IMPERIALISM 0x00586610
void* __cdecl GetTCityBarClusterClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTCityBarCluster);
}

// FUNCTION: IMPERIALISM 0x00586630
CityBarClusterState* __fastcall ConstructTCityBarClusterBaseState(CityBarClusterState* cluster,
                                                                  int unusedEdx) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
  cluster->vftable = reinterpret_cast<void*>(kVtableTCityBarCluster);
  return cluster;
}

// FUNCTION: IMPERIALISM 0x00586660
void* __fastcall DestructTCityBarClusterAndMaybeFree(void* cluster, int unusedEdx,
                                                     unsigned char freeSelfFlag) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)cluster);
  }
  return cluster;
}

// FUNCTION: IMPERIALISM 0x005866b0
void __fastcall UpdateTradeSummaryMetricControlsFromRecord(void* self, int unusedEdx,
                                                           int recordContext)

{
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  int recordNode = *reinterpret_cast<int*>(recordContext + 0xac);
  int metricContext = *reinterpret_cast<int*>(recordContext + 0x1d8);
  int metrics = *reinterpret_cast<int*>(metricContext + 0x10);
  void*(__fastcall * resolveByTag)(void*, int) = reinterpret_cast<void*(__fastcall*)(void*, int)>(
      (*reinterpret_cast<void***>(self))[0x94 / 4]);

  TradeControl* areaControl = reinterpret_cast<TradeControl*>(resolveByTag(self, 0x74726561));
  if (areaControl != 0) {
    areaControl->SetControlValue(*reinterpret_cast<int*>(recordNode + 0x10), 1);
    areaControl->SetEnabledPair(0, 1);
  }

  TradeControl* returnControl = reinterpret_cast<TradeControl*>(resolveByTag(self, 0x756e7472));
  if (returnControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineTradeSummaryRtnu);
  }
  returnControl->SetControlValue((int)*reinterpret_cast<short*>(metrics + 4), 1);

  TradeControl* airControl = reinterpret_cast<TradeControl*>(resolveByTag(self, 0x74726169));
  if (airControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineTradeSummaryIart);
  }
  airControl->SetControlValue((int)*reinterpret_cast<short*>(metrics + 6), 1);

  TradeControl* profControl = reinterpret_cast<TradeControl*>(resolveByTag(self, 0x70726f66));
  if (profControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineTradeSummaryProf);
  }
  profControl->SetControlValue((int)*reinterpret_cast<short*>(metrics + 8), 1);
}

// FUNCTION: IMPERIALISM 0x00586840
ProductionClusterState* __cdecl CreateTProductionClusterInstance(void) {
  ProductionClusterState* cluster =
      reinterpret_cast<ProductionClusterState*>(AllocateWithFallbackHandler(0x98));
  if (cluster != 0) {
    reinterpret_cast<void(__fastcall*)(void*)>(ConstructTUberClusterBaseState)(cluster);
    cluster->vftable = reinterpret_cast<void*>(kVtableTProductionCluster);
    cluster->field_90 = 0;
    cluster->field_94 = 0;
    cluster->field_88 = 0;
    cluster->field_8c = 0;
    cluster->field_8e = 0;
  }
  return cluster;
}

// FUNCTION: IMPERIALISM 0x00586900
void* __cdecl GetTProductionClusterClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTProductionCluster);
}

// FUNCTION: IMPERIALISM 0x00586920
ProductionClusterState* __fastcall
ConstructTProductionClusterBaseState(ProductionClusterState* cluster) {
  // ORIG_CALLCONV: __thiscall
  reinterpret_cast<void(__fastcall*)(void*)>(ConstructTUberClusterBaseState)(cluster);
  cluster->vftable = reinterpret_cast<void*>(kVtableTProductionCluster);
  cluster->field_90 = 0;
  cluster->field_94 = 0;
  cluster->field_88 = 0;
  cluster->field_8c = 0;
  cluster->field_8e = 0;
  return cluster;
}

// FUNCTION: IMPERIALISM 0x00586970
ProductionClusterState* __fastcall
DestructTProductionClusterAndMaybeFree(ProductionClusterState* cluster, int unusedEdx,
                                       unsigned char freeSelfFlag) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)cluster);
  }
  return cluster;
}

// FUNCTION: IMPERIALISM 0x005869c0
void __fastcall HandleProductionClusterValuePanelSplitArrowCommand64or65AndForward(
    ProductionClusterState* cluster, int commandId, void* eventArg, int eventExtra) {
  // ORIG_CALLCONV: __thiscall
  TradeControl* valueControl = ResolveOwnerControl(cluster, 0x76616c75);
  if (valueControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
  }
  reinterpret_cast<void(__fastcall*)(void*, int, void*, int)>(thunk_DispatchPanelControlEvent)(
      cluster, commandId, eventArg, eventExtra);
}

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x00586a60
void TradeMoveStepCluster::OrphanTiny_SetWordEcxOffset_8c_00586a60(short value) {
  // ORIG_CALLCONV: __thiscall
  field_8c = value;
}

// FUNCTION: IMPERIALISM 0x00586a80
void TradeMoveStepCluster::OrphanLeaf_NoCall_Ins05_00586a80(int value90, int value94) {
  // ORIG_CALLCONV: __thiscall
  field_90 = value90;
  field_94 = value94;
}

// FUNCTION: IMPERIALISM 0x00586ab0
void TradeMoveStepCluster::OrphanTiny_SetWordEcxOffset_8e_00586ab0(short value) {
  // ORIG_CALLCONV: __thiscall
  field_8e = value;
}

#if defined(_MSC_VER)
#pragma optimize("y", off)
#endif

// FUNCTION: IMPERIALISM 0x00586ad0
ClosePictureState* __cdecl CreateTClosePictureInstance(void) {
  ClosePictureState* picture =
      reinterpret_cast<ClosePictureState*>(AllocateWithFallbackHandler(0x94));
  if (picture != 0) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_ConstructUiTabCursorPictureEntry)(picture);
    picture->vftable = reinterpret_cast<void*>(kVtableTClosePicture);
  }
  return picture;
}

// FUNCTION: IMPERIALISM 0x00586b50
void* __cdecl GetTClosePictureClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTClosePicture);
}

// FUNCTION: IMPERIALISM 0x00586b70
ClosePictureState* __fastcall ConstructTClosePictureBaseState(ClosePictureState* picture) {
  // ORIG_CALLCONV: __thiscall
  reinterpret_cast<void(__fastcall*)(void*)>(::thunk_ConstructUiTabCursorPictureEntry)(picture);
  picture->vftable = reinterpret_cast<void*>(kVtableTClosePicture);
  return picture;
}

// FUNCTION: IMPERIALISM 0x00586ba0
ClosePictureState* __fastcall DestructTClosePictureAndMaybeFree(ClosePictureState* picture,
                                                                int unusedEdx,
                                                                unsigned char freeSelfFlag) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  thunk_DestructCityDialogSharedBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)picture);
  }
  return picture;
}

// FUNCTION: IMPERIALISM 0x00586bf0
void __fastcall
WrapperFor_DispatchUiMouseEventToChildrenOrSelf_At00586bf0(ClosePictureState* picture, int arg1,
                                                           int arg2, int arg3, int arg4) {
  // ORIG_CALLCONV: __thiscall
  reinterpret_cast<int(__fastcall*)(void*, int, int, int, int)>(
      ::DispatchUiMouseEventToChildrenOrSelf)(picture, arg1, arg2, arg3, arg4);
  TradeControl* control =
      reinterpret_cast<TradeControl*>(reinterpret_cast<void*(__fastcall*)(ClosePictureState*)>(
          (*reinterpret_cast<void***>(picture))[0x58 / 4])(picture));
  if (control != 0) {
    control->ApplyStyleDescriptor(reinterpret_cast<void*>(picture->ownerDescriptorAt1c), 1);
  }
}

// FUNCTION: IMPERIALISM 0x00586c40
TradeMovePanelContext* __cdecl CreateTradeMoveControlPanelBasic(void) {
  TradeMovePanelContext* panel =
      reinterpret_cast<TradeMovePanelContext*>(AllocateWithFallbackHandler(0x88));
  if (panel != 0) {
    reinterpret_cast<void(__fastcall*)(void*)>(ConstructTUberClusterBaseState)(panel);
    *reinterpret_cast<void**>(panel) = reinterpret_cast<void*>(kVtableTAmtBarCluster);
  }
  return panel;
}

// FUNCTION: IMPERIALISM 0x00586cc0
void* __cdecl GetTAmtBarClusterClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTAmtBarCluster);
}

// FUNCTION: IMPERIALISM 0x00586ce0
TradeMovePanelContext* __fastcall
ConstructTradeMoveControlPanelBasic(TradeMovePanelContext* panel) {
  reinterpret_cast<void(__fastcall*)(void*)>(ConstructTUberClusterBaseState)(panel);
  *reinterpret_cast<void**>(panel) = reinterpret_cast<void*>(kVtableTAmtBarCluster);
  return panel;
}

// FUNCTION: IMPERIALISM 0x00586d10
TradeMovePanelContext* __fastcall DestructTAmtBarClusterMaybeFree(TradeMovePanelContext* panel,
                                                                  int unusedEdx,
                                                                  unsigned char freeSelfFlag) {
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)panel);
  }
  return panel;
}

// FUNCTION: IMPERIALISM 0x00586d60
void __fastcall InitializeTradeMoveAndBarControls(void* context, int unusedEdx,
                                                  unsigned int styleSeed) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  TradeMovePanelContext* panel = reinterpret_cast<TradeMovePanelContext*>(context);
  TradeControl* moveControl = ResolveOwnerControl(panel, kControlTagMove);
  unsigned int styleDescriptor = styleSeed & 0xffff0000;
  if (moveControl != 0) {
    reinterpret_cast<void(__cdecl*)(int, unsigned int*, int, int)>(
        thunk_BuildUiTextStyleDescriptor)(0, &styleDescriptor, 0xa, 0x2b67);
    moveControl->ApplyStyleDescriptor(&styleDescriptor, 0);
    moveControl->SetStyleState(-2, 0);
  }

  TradeControl* barControl = ResolveOwnerControl(panel, kControlTagBar);
  if (barControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineMoveBarInitNil);
  }
  reinterpret_cast<void(__fastcall*)(TradeControl*, int, unsigned int)>(
      (*reinterpret_cast<void***>(barControl))[0xdc / 4])(barControl, 0, styleDescriptor);
  reinterpret_cast<void(__fastcall*)(void*, int, unsigned int)>(thunk_NoOpUiLifecycleHook)(
      panel, 0, styleDescriptor);
}

// FUNCTION: IMPERIALISM 0x00586e50
short __stdcall OrphanLeaf_NoCall_Ins02_00586e50(short value, int unusedArg) {
  (void)unusedArg;
  return value;
}

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x00586e70
void TradeMovePanelContext::HandleTradeMoveControlAdjustment(int commandId, void* eventArg,
                                                             int eventExtra) {
  // ORIG_CALLCONV: __thiscall
  int normalizedCommand = commandId - 100;
  void*(__fastcall * resolveByTag)(void*, int) = reinterpret_cast<void*(__fastcall*)(void*, int)>(
      (*reinterpret_cast<void***>(this))[0x94 / 4]);

  if (normalizedCommand == 0) {
    TradeControl* moveControl =
        reinterpret_cast<TradeControl*>(resolveByTag(this, kControlTagMove));
    if (moveControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineMoveAdjustMove);
    }
    short moveValue = moveControl->QueryValue();

    TradeControl* availableControl =
        reinterpret_cast<TradeControl*>(resolveByTag(this, kControlTagAvai));
    if (availableControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineMoveAdjustAvai);
    }
    short availableValue = (short)availableControl->QueryValue();
    if (moveValue < availableValue) {
      CallApplyMoveValueSlot1D0(this, moveValue + 1);
    }
  } else if (normalizedCommand == 1) {
    TradeControl* moveControl =
        reinterpret_cast<TradeControl*>(resolveByTag(this, kControlTagMove));
    if (moveControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineMoveAdjustMoveMinus);
    }
    int moveValue = moveControl->QueryValue();
    if ((short)moveValue != 0) {
      CallApplyMoveValueSlot1D0(this, moveValue - 1);
    }
  }
  reinterpret_cast<void(__fastcall*)(void*, int, void*, int)>(thunk_DispatchPanelControlEvent)(
      this, commandId, eventArg, eventExtra);
}

#if defined(_MSC_VER)
#pragma optimize("y", off)
#endif

void __fastcall HandleTradeMoveControlAdjustment(void* context, int commandId, void* eventArg,
                                                 int eventExtra) {
  reinterpret_cast<TradeMovePanelContext*>(context)->HandleTradeMoveControlAdjustment(
      commandId, eventArg, eventExtra);
}

// FUNCTION: IMPERIALISM 0x00586ff0
void __cdecl OrphanRetStub_00586ff0(void) {}

// FUNCTION: IMPERIALISM 0x00587010
void* CreateTradeSellControlPanel(void) {
  void* cluster = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x8c));
  if (cluster != 0) {
    reinterpret_cast<void(__fastcall*)(void*)>(ConstructTUberClusterBaseState)(cluster);
    *reinterpret_cast<void**>(cluster) =
        reinterpret_cast<void*>(&PTR_thunk_GetTTradeClusterClassNamePointer_00665a70);
  }
  return cluster;
}

// FUNCTION: IMPERIALISM 0x00587090
void* GetTTradeClusterClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTTradeCluster);
}

// FUNCTION: IMPERIALISM 0x005870b0
void __fastcall ConstructTradeSellControlPanel(void* self)

{
  reinterpret_cast<void(__fastcall*)(void*)>(ConstructTUberClusterBaseState)(self);
  *reinterpret_cast<void**>(self) =
      reinterpret_cast<void*>(&PTR_thunk_GetTTradeClusterClassNamePointer_00665a70);
}

// FUNCTION: IMPERIALISM 0x005870e0
void* __fastcall DestroyTradeSellControlPanel(void* self, int unusedEdx,
                                              unsigned char freeSelfFlag) {
  (void)unusedEdx;
  reinterpret_cast<void(__fastcall*)(void*)>(thunk_DestructEngineerDialogBaseState)(self);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)self);
  }
  return self;
}

// FUNCTION: IMPERIALISM 0x00587130
void TradeScreenContext::InitializeTradeSellControlState(unsigned int styleSeed) {
  TradeControl* sellControl = ResolveControlByTag(kControlTagSell);
  if (sellControl != 0) {
    int styleDescriptor[5];
    int boundsBuffer[2] = {0, 0};
    reinterpret_cast<void(__cdecl*)(int, void*, int, int, int)>(
        thunk_InitializeUiTextStyleDescriptor)(0, styleDescriptor, 0xe, 0x2b68, 2);
    sellControl->ApplyStyleDescriptor(styleDescriptor, 0);
    sellControl->SetStyleState(-1, 0);
    sellControl->QueryBounds(boundsBuffer);
    boundsBuffer[1] = boundsBuffer[1] - 2;
    sellControl->ApplyBounds(boundsBuffer, 1);
    sellControl->SetStatePair(-1, 0);
  }

  TradeControl* barControl = ResolveControlByTag(kControlTagBar);
  if (barControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineInitBar);
  }
  barControl->SetStatePair(0, 0);

  TradeControl* leftControl = ResolveControlByTag(kControlTagLeft);
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineInitLeft);
  }
  TradeControl* rightControl = ResolveControlByTag(kControlTagRght);
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineInitRight);
  }
  leftControl->SetStatePair(0, 0);
  rightControl->SetStatePair(0, 0);

  short activeNationSlot = QueryActiveNationId();
  NationState* activeNationState = GetNationStateBySlot(activeNationSlot);
  if (activeNationState != 0 && QueryNationTradeCapacity(activeNationState) == 0) {
    leftControl->SetEnabledPair(0, 0);
    rightControl->SetEnabledPair(0, 0);
    barControl->SetEnabledPair(0, 0);
    TradeControl* greenControl = ResolveControlByTag(kControlTagGree);
    if (greenControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineInitGree);
    }
    if (greenControl != 0) {
      greenControl->SetEnabledPair(0, 0);
    }
  }

  InitializeTradeMoveAndBarControls(this, 0, styleSeed);
}

// FUNCTION: IMPERIALISM 0x005873e0
void TAmtBarClusterContext::HandleTradeSellControlCommand(int commandId, void* eventArg,
                                                          int eventExtra) {
  // ORIG_CALLCONV: __thiscall
  void* ownerPanel = CallOwnerPanelSlot58(this);

  switch (commandId) {
  case 100: {
    if (CallBoolSlot1DC(this) != '\0') {
      TradeControl* sellControl = ResolveOwnerControl(this, kControlTagSell);
      if (sellControl == 0) {
        FailNilPointerInUSmallViews(kAssertLineTradeSellIncSell);
      }

      int sellValue = sellControl->QueryValue();
      short activeNationSlot = QueryActiveNationId();
      NationState* activeNationState = GetNationStateBySlot(activeNationSlot);
      short maxByNationMetric = 0;
      if (activeNationState != 0) {
        maxByNationMetric = QueryNationMetricBySlot(activeNationState, metricSlotAt88);
      }

      TradeControl* capacityControl = ResolveOwnerControl(ownerPanel, 0x6d436170);
      if (capacityControl == 0) {
        FailNilPointerInUSmallViews(kAssertLineTradeSellIncCap);
      }

      if ((int)maxByNationMetric < sellValue) {
        int capacityValue = capacityControl->QueryValue();
        if ((int)maxByNationMetric < capacityValue) {
          sellControl->SetEnabledPair(maxByNationMetric + 1 != 0, 1);
          CallApplyMoveValueSlot1D0(this, maxByNationMetric + 1);
          return;
        }
      }
    }
    break;
  }
  case 0x65: {
    TradeControl* sellControl = ResolveOwnerControl(this, kControlTagSell);
    if (sellControl == 0) {
      MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
      break;
    }
    int sellValue = sellControl->QueryValue();
    if (1 < sellValue) {
      CallApplyMoveValueSlot1D0(this, sellValue - 1);
      return;
    }
    break;
  }
  case 0x67:
    CallUiRuntimeSlot68(g_pUiRuntimeContext, -1);
    if (QueryUiScreenModeRaw(g_pUiRuntimeContext) == 3) {
      for (int i = 0;
           i < (int)(sizeof(kTradeSellPropagationTags) / sizeof(kTradeSellPropagationTags[0]));
           ++i) {
        TradeControl* rowControl = ResolveOwnerControl(ownerPanel, kTradeSellPropagationTags[i]);
        if (rowControl != 0 && CallControlFlagSlot1D8(rowControl) == '\0') {
          CallControlActionSlot1E0(rowControl);
        }
      }
      return;
    }
    break;
  case 0x68:
    CallUiRuntimeSlot68(g_pUiRuntimeContext, 1);
    if (QueryUiScreenModeRaw(g_pUiRuntimeContext) == 4) {
      for (int i = 0;
           i < (int)(sizeof(kTradeSellPropagationTags) / sizeof(kTradeSellPropagationTags[0]));
           ++i) {
        TradeControl* rowControl = ResolveOwnerControl(ownerPanel, kTradeSellPropagationTags[i]);
        if (rowControl != 0 && CallControlFlagSlot1D8(rowControl) == '\0') {
          CallControlActionSlot1E0(rowControl);
        }
      }
      return;
    }
    break;
  case 0x69: {
    short activeNationSlot = QueryActiveNationId();
    NationState* activeNationState = GetNationStateBySlot(activeNationSlot);
    short maxByNationMetric = 0;
    if (activeNationState != 0) {
      maxByNationMetric = QueryNationMetricBySlot(activeNationState, metricSlotAt88);
    }

    TradeControl* capacityControl = ResolveOwnerControl(ownerPanel, 0x6d436170);
    if (capacityControl == 0) {
      MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    }
    short cappedValue = (short)capacityControl->QueryValue();
    int applyValue = (int)maxByNationMetric;
    if ((int)cappedValue <= (int)maxByNationMetric) {
      applyValue = (int)cappedValue;
    }

    TradeControl* sellControl = ResolveOwnerControl(this, kControlTagSell);
    sellControl->SetEnabledPair(1, 1);

    TradeControl* barControl = ResolveOwnerControl(this, kControlTagBar);
    if (barControl == 0) {
      MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    }
    barControl->SetStatePair(1, 0);
    CallApplyMoveValueSlot1D0(this, applyValue);
    return;
  }
  case 0x6a: {
    TradeControl* sellControl = ResolveOwnerControl(this, kControlTagSell);
    sellControl->SetEnabledPair(0, 1);

    TradeControl* barControl = ResolveOwnerControl(this, kControlTagBar);
    if (barControl == 0) {
      MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    }
    barControl->SetStatePair(0, 1);
    CallApplyMoveValueSlot1D0(this, 0);
    return;
  }
  default:
    HandleTradeMoveControlAdjustment(this, commandId, eventArg, eventExtra);
    return;
  }

  HandleTradeMoveControlAdjustment(this, commandId, eventArg, eventExtra);
}

// GHIDRA_NAME IsTradeSellControlAtMinimum
// GHIDRA_PROTO void __cdecl IsTradeSellControlAtMinimum(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Returns early if UI mode is outside trade range (>3). Otherwise queries current
// Sell control quantity. GHIDRA_COMMENT_END
//
// NOTE:
// GHIDRA showed `g_pUiRuntimeContext` as a global here; this reconstruction passes it explicitly.
//

// FUNCTION: IMPERIALISM 0x00587900
char __fastcall IsTradeSellControlAtMinimum(TradeScreenContext* context, int unusedEdx) {
  (void)unusedEdx;
  if (QueryUiScreenModeRaw(g_pUiRuntimeContext) > 3) {
    return 0;
  }
  TradeControl* sellControl = CallResolveControlByTagSlot94(context, kControlTagSell);
  return sellControl->QueryValue() <= 0 ? 1 : 0;
}

// GHIDRA_NAME QueryTradeSellControlQuantity
// GHIDRA_PROTO void __cdecl QueryTradeSellControlQuantity(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Returns current Sell control quantity via child control tag "Sell" and vfunc
// +0x1E8. GHIDRA_COMMENT_END
/* Returns current Sell control quantity via child control tag "Sell" and vfunc +0x1E8. */

// FUNCTION: IMPERIALISM 0x00587950
short TradeScreenContext::QueryTradeSellControlQuantity(void) {
  TradeControl* sellControl = CallResolveControlByTagSlot94(this, kControlTagSell);
  return sellControl->QueryValue();
}

// GHIDRA_NAME IsTradeBidControlActionable
// GHIDRA_PROTO void __cdecl IsTradeBidControlActionable(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Trade UI predicate for Bid control interactivity.
// GHIDRA_COMMENT Looks up control tag 'card' and returns true when control bitmap is 2111 (0x83F)
// or 2125 (0x84D) and control reports actionable state via vtable+0xEC. GHIDRA_COMMENT_END

/* Trade UI predicate for Bid control interactivity.
   Looks up control tag 'card' and returns true when control bitmap is 2111 (0x83F) or 2125 (0x84D)
   and control reports actionable state via vtable+0xEC. */

// FUNCTION: IMPERIALISM 0x00587980
char TradeScreenContext::IsTradeBidControlActionable(void) {
  TradeControl* bidControl = CallResolveControlByTagSlot94(this, kControlTagCard);
  if (bidControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidActionable);
  }

  if (bidControl->bitmapId != kTradeBitmapBidStateA &&
      bidControl->bitmapId != kTradeBitmapBidStateB) {
    return 0;
  }

  char actionable = bidControl->IsActionableSlotEC();
  if (actionable == 0) {
    return 0;
  }
  return 1;
}

// GHIDRA_NAME IsTradeOfferControlActionable
// GHIDRA_PROTO void __cdecl IsTradeOfferControlActionable(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Trade UI predicate for Offer control interactivity.
// GHIDRA_COMMENT Looks up control tag 'offr' and returns true when control bitmap is 2113 (0x841)
// or 2127 (0x84F) and control reports actionable state via vtable+0xEC. GHIDRA_COMMENT_END

/* Trade UI predicate for Offer control interactivity.
   Looks up control tag 'offr' and returns true when control bitmap is 2113 (0x841) or 2127 (0x84F)
   and control reports actionable state via vtable+0xEC. */

// FUNCTION: IMPERIALISM 0x00587a10
char TradeScreenContext::IsTradeOfferControlActionable(void) {
  TradeControl* offerControl = CallResolveControlByTagSlot94(this, kControlTagOffr);
  if (offerControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferActionable);
  }

  if (offerControl->bitmapId != kTradeBitmapOfferStateA &&
      offerControl->bitmapId != kTradeBitmapOfferStateB) {
    return 0;
  }

  char actionable = offerControl->IsActionableSlotEC();
  if (actionable == 0) {
    return 0;
  }
  return 1;
}

// GHIDRA_NAME SetTradeBidSecondaryBitmapState
// GHIDRA_PROTO void __cdecl SetTradeBidSecondaryBitmapState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Trade UI Bid secondary-state updater.
// GHIDRA_COMMENT Resolves 'card' control and assigns 2112 (0x840) or 2126 (0x84E) through
// vtable+0x1C8 based on row state field (+0x1C == 0x67643020) when nation availability gate passes.
// GHIDRA_COMMENT_END

/* Trade UI Bid secondary-state updater.
   Resolves 'card' control and assigns 2112 (0x840) or 2126 (0x84E) through vtable+0x1C8 based on
   row state field (+0x1C == 0x67643020) when nation availability gate passes. */

// NOTE:
// GHIDRA showed `g_pUiRuntimeContext` as a global here; this reconstruction passes it explicitly.
//

// FUNCTION: IMPERIALISM 0x00587aa0
void TradeScreenContext::SetTradeBidSecondaryBitmapState(void) {
  TradeControl* bidControl = ResolveControlByTag(kControlTagCard);
  if (bidControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidSecondary);
  }

  int layoutCapture[2];
  layoutCapture[0] = 0x11;
  layoutCapture[1] = 0x14;
  bidControl->CaptureLayout(layoutCapture, 1);

  if (QueryUiScreenModeRaw(g_pUiRuntimeContext) < 4) {
    bidControl->SetEnabledPair(1, 1);
    if (rowStateTag == kTradeRowStateTag_67643020) {
      bidControl->SetBitmap(kTradeBitmapBidSecondaryStateB, 0);
    } else {
      bidControl->SetBitmap(kTradeBitmapBidSecondaryStateA, 0);
    }
    bidControl->Refresh();
    bidControl->UpdateAfterBitmapChange(0);
    return;
  }

  bidControl->SetEnabledPair(0, 1);
}

// GHIDRA_NAME SetTradeBidControlBitmapState
// GHIDRA_PROTO void __cdecl SetTradeBidControlBitmapState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Trade UI Bid-state updater.
// GHIDRA_COMMENT Resolves control tag 'card' from current row context.
// GHIDRA_COMMENT If row state field (+0x1C) equals 0x67643020, assigns bitmap 2125 (0x84D);
// otherwise assigns bitmap 2111 (0x83F). GHIDRA_COMMENT Then refreshes related controls 'gree',
// 'left', 'rght' visibility/active flags. GHIDRA_COMMENT_END

/* Trade UI Bid-state updater.
   Resolves control tag 'card' from current row context.
   If row state field (+0x1C) equals 0x67643020, assigns bitmap 2125 (0x84D); otherwise assigns
   bitmap 2111 (0x83F).
   Then refreshes related controls 'gree', 'left', 'rght' visibility/active flags. */

// FUNCTION: IMPERIALISM 0x00587bb0
void TradeScreenContext::SetTradeBidControlBitmapState(void) {
  TradeControl* bidControl = ResolveControlByTag(kControlTagCard);
  if (bidControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidControl);
  }

  bidControl->SetEnabledPair(1, 0);
  if (rowStateTag == kTradeRowStateTag_67643020) {
    bidControl->SetBitmap(kTradeBitmapBidStateB, 0);
  } else {
    bidControl->SetBitmap(kTradeBitmapBidStateA, 0);
  }

  int layoutCapture[2] = {0x41, 0x14};
  bidControl->CaptureLayout(layoutCapture, 1);

  TradeControl* greenControl = ResolveControlByTag(kControlTagGree);
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidGree);
  }
  TradeControl* leftControl = ResolveControlByTag(kControlTagLeft);
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidLeft);
  }
  TradeControl* rightControl = ResolveControlByTag(kControlTagRght);
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidRight);
  }

  greenControl->SetEnabledPair(0, 1);
  leftControl->SetEnabledPair(0, 1);
  rightControl->SetEnabledPair(0, 1);
  greenControl->SetStatePair(0, 1);
  leftControl->SetStatePair(0, 1);
  rightControl->SetStatePair(0, 1);

  bidControl->Refresh();
  bidControl->UpdateAfterBitmapChange(0);
}

// GHIDRA_NAME SetTradeOfferControlBitmapState
// GHIDRA_PROTO void __cdecl SetTradeOfferControlBitmapState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Trade UI Offer-state updater.
// GHIDRA_COMMENT Resolves control tag 'offr' from current row context.
// GHIDRA_COMMENT If row state field (+0x1C) equals 0x67643020, assigns bitmap 2127 (0x84F);
// otherwise assigns bitmap 2113 (0x841). GHIDRA_COMMENT Then refreshes related controls 'gree',
// 'left', 'rght' visibility/active flags. GHIDRA_COMMENT_END

/* Trade UI Offer-state updater.
   Resolves control tag 'offr' from current row context.
   If row state field (+0x1C) equals 0x67643020, assigns bitmap 2127 (0x84F); otherwise assigns
   bitmap 2113 (0x841).
   Then refreshes related controls 'gree', 'left', 'rght' visibility/active flags. */

// FUNCTION: IMPERIALISM 0x00587dd0
void TradeScreenContext::SetTradeOfferControlBitmapState(void) {
  TradeControl*(__fastcall * resolveControl)(TradeScreenContext*, int) =
      reinterpret_cast<TradeControl*(__fastcall*)(TradeScreenContext*, int)>(
          (*reinterpret_cast<void***>(this))[0x94 / 4]);

  TradeControl* offerControl = resolveControl(this, kControlTagOffr);
  if (offerControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferControl);
  }

  offerControl->SetEnabledPair(1, 0);
  if (rowStateTag == kTradeRowStateTag_67643020) {
    offerControl->SetBitmap(kTradeBitmapOfferStateB, 0);
  } else {
    offerControl->SetBitmap(kTradeBitmapOfferStateA, 0);
  }

  int layoutCaptureF4[2] = {0x41, 0x14};
  offerControl->CaptureLayout(layoutCaptureF4, 1);
  int layoutCaptureF0[2] = {0x73, 0};
  offerControl->CaptureLayoutF0(layoutCaptureF0, 1);

  TradeControl* greenControl = resolveControl(this, kControlTagGree);
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferGree);
  }
  TradeControl* leftControl = resolveControl(this, kControlTagLeft);
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferLeft);
  }
  TradeControl* rightControl = resolveControl(this, kControlTagRght);
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferRight);
  }

  greenControl->SetEnabledPair(1, 1);
  leftControl->SetEnabledPair(1, 1);
  rightControl->SetEnabledPair(1, 1);
  greenControl->SetStatePair(1, 1);
  leftControl->SetStatePair(1, 1);
  rightControl->SetStatePair(1, 1);

  offerControl->Refresh();
  offerControl->UpdateAfterBitmapChange(0);
}

// GHIDRA_NAME SetTradeOfferSecondaryBitmapState
// GHIDRA_PROTO void __cdecl SetTradeOfferSecondaryBitmapState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Trade UI Offer secondary-state updater.
// GHIDRA_COMMENT Resolves 'offr' control and assigns 2114 (0x842) or 2128 (0x850) through
// vtable+0x1C8 based on row state field (+0x1C == 0x67643020) when nation availability gate passes.
// GHIDRA_COMMENT_END

/* Trade UI Offer secondary-state updater.
   Resolves 'offr' control and assigns 2114 (0x842) or 2128 (0x850) through vtable+0x1C8 based on
   row state field (+0x1C == 0x67643020) when nation availability gate passes. */

// FUNCTION: IMPERIALISM 0x00588030
void TradeScreenContext::SetTradeOfferSecondaryBitmapState(void) {
  TradeControl* offerControl = ResolveControlByTag(kControlTagOffr);
  if (offerControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryOffr);
  }

  int layoutCaptureF4[2] = {0x11, 0x14};
  offerControl->CaptureLayout(layoutCaptureF4, 1);

  short activeNationSlot = QueryActiveNationId();
  NationState* activeNationState = GetNationStateBySlot(activeNationSlot);
  short tradeMetricAvailable = QueryNationMetricBySlot(activeNationState, tradeMetricSlot);

  if (tradeMetricAvailable != 0) {
    short activeNationSlotAgain = QueryActiveNationId();
    NationState* activeNationStateAgain = GetNationStateBySlot(activeNationSlotAgain);
    if (QueryNationTradeCapacity(activeNationStateAgain) != 0) {
      offerControl->SetEnabledPair(1, 0);
      if (rowStateTag == kTradeRowStateTag_67643020) {
        offerControl->SetBitmap(kTradeBitmapOfferSecondaryStateB, 0);
      } else {
        offerControl->SetBitmap(kTradeBitmapOfferSecondaryStateA, 0);
      }
      int layoutCaptureF0[2] = {0xa3, 0};
      offerControl->CaptureLayoutF0(layoutCaptureF0, 1);
    } else {
      offerControl->SetEnabledPair(0, 1);
    }
  } else {
    offerControl->SetEnabledPair(0, 1);
  }

  TradeControl* greenControl = ResolveControlByTag(kControlTagGree);
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryGree);
  }
  TradeControl* leftControl = ResolveControlByTag(kControlTagLeft);
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryLeft);
  }
  TradeControl* rightControl = ResolveControlByTag(kControlTagRght);
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryRight);
  }

  greenControl->SetEnabledPair(0, 1);
  leftControl->SetEnabledPair(0, 1);
  rightControl->SetEnabledPair(0, 1);
  greenControl->SetStatePair(0, 1);
  leftControl->SetStatePair(0, 1);
  rightControl->SetStatePair(0, 1);

  offerControl->Refresh();
  offerControl->UpdateAfterBitmapChange(0);
}

// GHIDRA_NAME UpdateTradeSellControlAndBarFromNationMetric
// GHIDRA_PROTO void __fastcall UpdateTradeSellControlAndBarFromNationMetric(int * this)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Updates Sell control quantity
// GHIDRA_COMMENT_END
/* Updates Sell control quantity */

// FUNCTION: IMPERIALISM 0x005882f0
void TradeScreenContext::UpdateTradeSellControlAndBarFromNationMetric(int metricClampMax) {
  short activeNationSlot = QueryActiveNationId();
  NationState* activeNationState = GetNationStateBySlot(activeNationSlot);
  int tradeMetricValue = (int)QueryNationMetricBySlot(activeNationState, tradeMetricSlot);
  if (tradeMetricValue > metricClampMax) {
    tradeMetricValue = metricClampMax;
  }

  TradeControl* sellControl = ResolveControlByTag(kControlTagSell);
  if (sellControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateSell);
  }
  if (sellControl != 0) {
    sellControl->SetControlValue(tradeMetricValue, 1);
  }

  TradeControl* barControl = ResolveControlByTag(kControlTagBar);
  if (barControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateBar);
  }
  TradeControl* greenControl = ResolveControlByTag(kControlTagGree);
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateGree);
  }

  if (barControl != 0) {
    TradeBarControlLayout* barLayout = reinterpret_cast<TradeBarControlLayout*>(barControl);
    int barRange = (int)barLayout->barRange;
    if (tradeMetricValue != 0) {
      int barSteps = (int)barLayout->barSteps;
      float barScale = 9999.0f;
      if (barSteps != 0) {
        barScale = (float)barRange / (float)barSteps;
      }
      int scaledMetricValue = (int)((float)tradeMetricValue * barScale);
      barControl->SetBarMetric(scaledMetricValue, barRange);
      return;
    }

    barControl->SetBarMetric(0, barRange);
  }

  if (greenControl != 0) {
    greenControl->SetEnabledPair(0, 1);
  }
}

// GHIDRA_NAME TAmtBar::WrapperFor_thunk_NoOpUiLifecycleHook_At00588610
// GHIDRA_PROTO undefined WrapperFor_thunk_NoOpUiLifecycleHook_At00588610()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [WrapperShape] small wrapper around thunk_NoOpUiLifecycleHook; instructions=4,
// call_insns=1, internal_calls=1, unique_internal=1 GHIDRA_COMMENT_END
/* [WrapperShape] small wrapper around thunk_NoOpUiLifecycleHook; instructions=4, call_insns=1,
   internal_calls=1, unique_internal=1 */

// FUNCTION: IMPERIALISM 0x00588630
void __fastcall OrphanCallChain_C2_I15_00588630(TradeControl* control, int unusedEdx,
                                                short valueAt60, short valueAt62) {
  (void)unusedEdx;
  TradeAmountBarLayout* amountBar = reinterpret_cast<TradeAmountBarLayout*>(control);
  amountBar->stepOrCurrentValue = valueAt60;
  amountBar->rangeOrMaxValue = valueAt62;
  control->InvokeSlotE4();
  control->InvokeSlot13C();
}

// GHIDRA_NAME OrphanCallChain_C1_I03_00588670
// GHIDRA_PROTO undefined OrphanCallChain_C1_I03_00588670()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [OrphanCallChain] no incoming code refs; calls=1; instructions=3
// GHIDRA_COMMENT_END
/* [OrphanCallChain] no incoming code refs; calls=1; instructions=3 */

// FUNCTION: IMPERIALISM 0x00588670
void __fastcall OrphanCallChain_C1_I03_00588670(TradeControl* control, int unusedEdx,
                                                int unusedStackArg) {
  (void)unusedEdx;
  (void)unusedStackArg;
  control->InvokeSlot1A8();
}

// GHIDRA_NAME TIndustryCluster::CreateTradeMoveStepControlPanel
// GHIDRA_PROTO undefined CreateTradeMoveStepControlPanel()

// FUNCTION: IMPERIALISM 0x00588690
void __fastcall RenderPrimarySurfaceOverlayPanelWithClipCache(TradeControl* control) {
  // ORIG_CALLCONV: __thiscall
  if (control == 0) {
    return;
  }
  if (control->IsActionable() == 0) {
    return;
  }
  int bounds[4] = {0, 0, 0, 0};
  control->QueryBounds(bounds);
  control->CaptureLayout(bounds, 1);
  control->Refresh();
}

// FUNCTION: IMPERIALISM 0x00588950
void TradeMoveControlState::ClampAndApplyTradeMoveValue(int* requestedValuePtr) {
  int requestedValue = *requestedValuePtr;
  int baseValue = 0;
  if (barStepsRaw < 1 || (barRangeRaw / ((int)barStepsRaw << 1) <= *requestedValuePtr)) {
    baseValue = requestedValue;
  }

  TradeControl* moveControl = reinterpret_cast<TradeControl*>(this);
  int appliedValue = moveControl->ApplyMoveClamp(baseValue, (short)requestedValue);
  void* owner = ownerContext;
  if (((short)appliedValue == 0) && requestedValue != 0) {
    TradeControl* fallbackControl = ResolveOwnerControl(owner, kControlTagMove);
    if (fallbackControl == 0) {
      fallbackControl = ResolveOwnerControl(owner, kControlTagSell);
    }
    if (fallbackControl != 0 && fallbackControl->QueryValue() == 0) {
      appliedValue = 1;
    }
  }

  CallApplyMoveValueSlot1D0(owner, appliedValue);
}

// GHIDRA_NAME OrphanCallChain_C1_I06_00588c30
// GHIDRA_PROTO undefined OrphanCallChain_C1_I06_00588c30()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [OrphanCallChain] no incoming code refs; calls=1; instructions=6
// GHIDRA_COMMENT_END
/* [OrphanCallChain] no incoming code refs; calls=1; instructions=6 */

// FUNCTION: IMPERIALISM 0x00588af0
void __fastcall ConstructTradeMoveStepControlPanel(TradeMoveStepCluster* cluster) {
  TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
  cluster->vftable = reinterpret_cast<void*>(kVtableTIndustryCluster);
  cluster->field_88 = 0;
}

// GHIDRA_NAME TIndustryCluster::DestructTIndustryClusterMaybeFree
// GHIDRA_PROTO void __cdecl DestructTIndustryClusterMaybeFree(void)

// FUNCTION: IMPERIALISM 0x00588b70
void __fastcall
SyncTradeCommoditySelectionWithActiveNationAndInitControls(TradeMovePanelContext* context,
                                                           int unusedEdx, int styleSeed) {
  (void)unusedEdx;
  short tagIndex = 0;
  short activeNationId = QueryActiveNationId();
  NationState* activeNationState = GetNationStateBySlot(activeNationId);
  void* cityState =
      activeNationState == 0 ? 0 : reinterpret_cast<void*>(activeNationState->cityState);

  int mappedSummaryTag = GetTradeSummarySelectionTagByIndex(0);
  while (mappedSummaryTag != context->summaryTag) {
    tagIndex = (short)(tagIndex + 1);
    mappedSummaryTag = GetTradeSummarySelectionTagByIndex(tagIndex);
  }

  TradeCommodityMetricRecord* selectedMetricRecord = reinterpret_cast<TradeCommodityMetricRecord*>(
      *reinterpret_cast<int*>(reinterpret_cast<char*>(cityState) + (int)tagIndex * 4 + 0xe4));
  context->selectedMetricControl = reinterpret_cast<TradeControl*>(selectedMetricRecord);
  context->selectedMetricValue =
      (short)TradeScreenRuntimeBridge::GetCityBuildingProductionValueBySlot(
          cityState,
          *reinterpret_cast<short*>(reinterpret_cast<char*>(selectedMetricRecord) + 0x52));

  reinterpret_cast<void(__fastcall*)(TradeMovePanelContext*, int, unsigned int)>(
      thunk_InitializeTradeMoveAndBarControls)(context, 0, (unsigned int)styleSeed);
  CallPostMoveValueSlot1D4(
      context, *reinterpret_cast<short*>(reinterpret_cast<char*>(selectedMetricRecord) + 4), 1);
}

// FUNCTION: IMPERIALISM 0x00588c30
void TradeMovePanelContext::OrphanCallChain_C1_I06_00588c30(int value) {
  CallPostMoveValueSlot1D4(this, value, 0);
}

static __inline void UpdateTradeBarFromSelectedMetricRatio(TradeMovePanelContext* context,
                                                           int assertLine) {
  void* owner = context;
  TradeControl* barControl = ResolveOwnerControl(owner, kControlTagBar);
  if (barControl == 0) {
    FailNilPointerInUSmallViews(assertLine);
  }

  TradeMoveControlState* barLayout = reinterpret_cast<TradeMoveControlState*>(barControl);
  if (barLayout->barStepsRaw != 0) {
    int ratioValue =
        ((int)context->selectedMetricControl->QueryStepValue() * barLayout->barRangeRaw) /
        (int)barLayout->barStepsRaw;
    barControl->SetBarMetricRatio(ratioValue);
  }
}

// GHIDRA_NAME UpdateTradeBarFromSelectedMetricRatio_B
// GHIDRA_PROTO void __fastcall UpdateTradeBarFromSelectedMetricRatio_B(int * this)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Computes bar position from selected metric ratio and applies it to bar control.
// GHIDRA_COMMENT_END
/* Computes bar position from selected metric ratio and applies it to bar control. */

// FUNCTION: IMPERIALISM 0x00588c60
void TradeMovePanelContext::UpdateTradeMoveControlsFromDrag(int dragValue, int updateFlag) {
  // ORIG_CALLCONV: __thiscall
  TradeControl* selectedControl = selectedMetricControl;
  short previousValue = ReadControlValueFieldPlus4(selectedControl);
  if (selectedControl != 0) {
    selectedControl->SetControlValueRaw(dragValue);
  }

  if (((char)updateFlag == 0) && (ReadControlValueFieldPlus4(selectedControl) == previousValue)) {
    return;
  }

  TradeControl* moveControl = CallResolveControlByTagSlot94(this, kControlTagMove);
  if (moveControl == 0) {
    FailNilPointerInUSmallViews(0xb42);
  }

  moveControl->SetControlValue((int)ReadControlValueFieldPlus4(selectedControl), 0);

  RECT moveBoundsRect;
  RECT moveInvalidRect;
  moveControl->QueryBounds(reinterpret_cast<int*>(&moveBoundsRect));
  OffsetRect(&moveBoundsRect, ownerOffsetX, ownerOffsetY);
  CopyRect(&moveInvalidRect, &moveBoundsRect);
  reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
      (int)&moveInvalidRect, 1);

  TradeControl* barControl = CallResolveControlByTagSlot94(this, kControlTagBar);
  if (barControl == 0) {
    FailNilPointerInUSmallViews(0xb49);
  }

  TradeMoveControlState* barLayout = reinterpret_cast<TradeMoveControlState*>(barControl);
  TradeAmountBarLayout* barAmount = reinterpret_cast<TradeAmountBarLayout*>(barControl);
  float barScale = 9999.0f;
  if (barLayout->barStepsRaw != 0) {
    barScale = (float)barLayout->barRangeRaw / (float)barLayout->barStepsRaw;
  }

  if (ReadControlValueFieldPlus4(selectedControl) == selectedMetricValue) {
    barAmount->auxValueB = 0x34;
  } else {
    barAmount->auxValueB = 0x3a;
  }

  int scaledMetric = (int)((float)selectedControl->QueryValue() * barScale);
  int scaledRange = (int)((float)ReadControlValueFieldPlus4(selectedControl) * barScale);
  barControl->SetBarMetric(scaledMetric, scaledRange);
  CallNotifyMoveUpdatedSlot1D8(ownerContext);
}

// FUNCTION: IMPERIALISM 0x00588f60
void TradeMovePanelContext::UpdateTradeBarFromSelectedMetricRatio_B(void) {
  UpdateTradeBarFromSelectedMetricRatio(this, kAssertLineRatioB);
}

// GHIDRA_NAME TAmtBar::HandleTradeMoveStepCommand
// GHIDRA_PROTO void __thiscall HandleTradeMoveStepCommand(void)

// FUNCTION: IMPERIALISM 0x00589340
void __fastcall RenderQuickDrawControlWithHitRegionClip_A(TradeControl* control) {
  AcquireReusableQuickDrawSurface();
  reinterpret_cast<void(__cdecl*)()>(ApplyHitRegionToClipState)();

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      int boundsRect[4] = {0, 0, 0, 0};
      control->QueryBounds(boundsRect);
      ApplyRectClipRegion(boundsRect);
      control->QueryBounds(boundsRect);
      control->CtrlSlot78();

      short styleValueAt60 = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x60);
      if (styleValueAt60 > 0) {
        ApplyQuickDrawStyleFromRuntime(0);
        SetQuickDrawStylePair(1, 4);
        SetQuickDrawTextOrigin(0, 1);
        DrawCenteredGuideLine((short)(styleValueAt60 - 1), 1);
        reinterpret_cast<void(__cdecl*)()>(ResetQuickDrawStrokeState)();
      }

      short overlayOffsetX = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x62);
      short overlayOffsetY = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x38);
      SetQuickDrawTextOrigin(overlayOffsetX, 0);
      reinterpret_cast<void(__cdecl*)()>(SetQuickDrawFillColor)();
      reinterpret_cast<void(__cdecl*)()>(ResetQuickDrawStrokeState)();
      DrawCenteredGuideLine(overlayOffsetX, (short)(overlayOffsetY - 2));

      reinterpret_cast<void(__cdecl*)()>(SnapshotHitRegionToClipCache)();
      TradeControl* owner = reinterpret_cast<TradeControl*>(CallOwnerPanelSlot58(control));
      if (owner != 0) {
        owner->InvokeSlot13C();
      }
    }
  }

  ReleaseOrCacheQuickDrawSurface();
}

// FUNCTION: IMPERIALISM 0x00589540
void __fastcall RenderQuickDrawOverlayWithHitRegion_00589540(TradeControl* control, int unusedEdx,
                                                             short selectedValue) {
  (void)unusedEdx;
  AcquireReusableQuickDrawSurface();
  *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x62) = selectedValue;
  reinterpret_cast<void(__cdecl*)()>(ApplyHitRegionToClipState)();

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      int cachedX = ReadIntAt(kAddrOverlayClipCacheParamX);
      int cachedY = ReadIntAt(kAddrOverlayClipCacheParamY);
      int invalidRect[4] = {cachedX, cachedY, 0, 0};
      control->CtrlSlot78();
      invalidRect[2] =
          cachedX + (int)*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x34);
      invalidRect[3] =
          cachedY + (int)*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x38);
      reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
          (int)invalidRect, 1);
    }
  }

  ReleaseOrCacheQuickDrawSurface();
}

// FUNCTION: IMPERIALISM 0x00589720
void __fastcall ConstructTradeMoveScaledControlPanel(TradeMoveStepCluster* cluster) {
  TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
  cluster->vftable = reinterpret_cast<void*>(kVtableTRailCluster);
  cluster->field_88 = 0;
  cluster->field_8e = 0;
}

// FUNCTION: IMPERIALISM 0x005897b0
void __fastcall
SelectTradeCommodityPresetBySummaryTagAndInitControls(TradeMovePanelContext* context, int unusedEdx,
                                                      short recordIndex) {
  (void)unusedEdx;
  short activeNationId = QueryActiveNationId();
  NationState* activeNationState = GetNationStateBySlot(activeNationId);
  NationCityTradeState* cityState = activeNationState == 0 ? 0 : activeNationState->cityState;

  unsigned int summaryTag = (unsigned int)context->summaryTag;
  int scenarioDescriptor = *reinterpret_cast<int*>(reinterpret_cast<char*>(cityState) + 0x1d8);
  if (summaryTag < 0x706f7076) {
    if (summaryTag == kSummaryTagPopu) {
      recordIndex = 0x3c;
      context->selectedMetricStep = 1;
      context->selectedMetricValue =
          (short)TradeScreenRuntimeBridge::GetCityBuildingProductionValueBySlot(cityState, 0x0f);
    } else if (summaryTag == kSummaryTagFood) {
      context->selectedMetricStep = 2;
      recordIndex = 7;
      int productionSlots = *reinterpret_cast<int*>(
          *reinterpret_cast<int*>(reinterpret_cast<char*>(cityState) + 0x1d8) + 0x14);
      context->selectedMetricValue =
          (short)(((*reinterpret_cast<short*>(productionSlots + 8) * 2 +
                    *reinterpret_cast<short*>(productionSlots + 6)) *
                       2 +
                   *reinterpret_cast<short*>(
                       *reinterpret_cast<int*>(reinterpret_cast<char*>(cityState) + 0x1d8) + 0x1e) +
                   *reinterpret_cast<short*>(productionSlots + 4)) /
                  2);
    }
  } else if (summaryTag < 0x70726f67) {
    if (summaryTag == kSummaryTagProf) {
      context->selectedMetricStep = 1;
      recordIndex = 0x18;
      context->selectedMetricValue =
          *reinterpret_cast<short*>(*reinterpret_cast<int*>(scenarioDescriptor + 0x10) + 6);
    } else if (summaryTag == kSummaryTagPowe) {
      recordIndex = 0x34;
      context->selectedMetricStep = 6;
      context->selectedMetricValue = 999;
    }
  } else if (summaryTag == kSummaryTagRail) {
    context->selectedMetricStep = 1;
    recordIndex = 0x33;
    int productionSlots = *reinterpret_cast<int*>(
        *reinterpret_cast<int*>(reinterpret_cast<char*>(cityState) + 0x1d8) + 0x14);
    context->selectedMetricValue =
        (short)(((*reinterpret_cast<short*>(productionSlots + 8) * 2 +
                  *reinterpret_cast<short*>(productionSlots + 6)) *
                     2 +
                 *reinterpret_cast<short*>(productionSlots + 4) +
                 *reinterpret_cast<short*>(
                     *reinterpret_cast<int*>(reinterpret_cast<char*>(cityState) + 0x1d8) + 0x1e)) /
                2);
  } else if (summaryTag == kSummaryTagIart) {
    context->selectedMetricStep = 1;
    recordIndex = 0x17;
    context->selectedMetricValue =
        *reinterpret_cast<short*>(*reinterpret_cast<int*>(scenarioDescriptor + 0x10) + 4);
  }

  context->selectedMetricControl = reinterpret_cast<TradeControl*>(
      *reinterpret_cast<int*>(reinterpret_cast<char*>(cityState) + (int)recordIndex * 4 + 0xe4));
  reinterpret_cast<void(__fastcall*)(TradeMovePanelContext*, int, unsigned int)>(
      thunk_InitializeTradeMoveAndBarControls)(context, 0,
                                               (unsigned int)(unsigned short)recordIndex);
  CallPostMoveValueSlot1D4(
      context,
      *reinterpret_cast<short*>(reinterpret_cast<char*>(context->selectedMetricControl) + 4), 1);
}

// FUNCTION: IMPERIALISM 0x005899c0
void TradeMovePanelContext::OrphanCallChain_C1_I06_005899c0(int value) {
  CallPostMoveValueSlot1D4(this, value, 0);
}

// GHIDRA_NAME UpdateTradeBarFromSelectedMetricRatio_A
// GHIDRA_PROTO void __fastcall UpdateTradeBarFromSelectedMetricRatio_A(int * this)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Computes bar position from selected metric ratio and applies it to bar control.
// GHIDRA_COMMENT_END
/* Computes bar position from selected metric ratio and applies it to bar control. */

// FUNCTION: IMPERIALISM 0x005899f0
void TradeMovePanelContext::UpdateTradeMoveControlsFromScaledDrag(int dragValue, int updateFlag) {
  // ORIG_CALLCONV: __thiscall
  short step = selectedMetricStep;
  int quantizedDragValue = ((((int)step / 2) + (int)(short)dragValue) / (int)step) * (int)step;
  TradeControl* selectedControl = selectedMetricControl;
  short previousValue = ReadControlValueFieldPlus4(selectedControl);
  if (selectedControl != 0) {
    selectedControl->SetControlValueRaw(quantizedDragValue);
  }

  if (((char)updateFlag == 0) && (ReadControlValueFieldPlus4(selectedControl) == previousValue)) {
    return;
  }

  TradeControl* moveControl = CallResolveControlByTagSlot94(this, kControlTagMove);
  if (moveControl == 0) {
    FailNilPointerInUSmallViews(0xcf2);
  }

  moveControl->SetControlValue((int)ReadControlValueFieldPlus4(selectedControl), 0);

  RECT moveBoundsRect;
  RECT moveInvalidRect;
  moveControl->QueryBounds(reinterpret_cast<int*>(&moveBoundsRect));
  OffsetRect(&moveBoundsRect, ownerOffsetX, ownerOffsetY);
  CopyRect(&moveInvalidRect, &moveBoundsRect);
  reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
      (int)&moveInvalidRect, 1);

  TradeControl* barControl = CallResolveControlByTagSlot94(this, kControlTagBar);
  if (barControl == 0) {
    FailNilPointerInUSmallViews(0xcf9);
  }

  TradeMoveControlState* barLayout = reinterpret_cast<TradeMoveControlState*>(barControl);
  TradeAmountBarLayout* barAmount = reinterpret_cast<TradeAmountBarLayout*>(barControl);
  float barScale = 9999.0f;
  if (barLayout->barStepsRaw != 0) {
    barScale = (float)barLayout->barRangeRaw / (float)barLayout->barStepsRaw;
  }

  if (ReadControlValueFieldPlus4(selectedControl) == selectedMetricValue) {
    barAmount->auxValueB = 0x34;
  } else {
    barAmount->auxValueB = 0x3a;
  }

  int scaledMetric = (int)((float)selectedControl->QueryValue() * barScale);
  int scaledRange = (int)((float)ReadControlValueFieldPlus4(selectedControl) * barScale);
  barControl->SetBarMetric(scaledMetric, scaledRange);
  CallNotifyMoveUpdatedSlot1D8(ownerContext);
}

// FUNCTION: IMPERIALISM 0x00589d10
void TradeMovePanelContext::UpdateTradeBarFromSelectedMetricRatio_A(void) {
  UpdateTradeBarFromSelectedMetricRatio(this, kAssertLineRatioA);
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif

#include "TAmtBar.cpp"
#include "TIndustryCluster.cpp"
#include "TIndustryAmtBar.cpp"
#include "TRailCluster.cpp"
#include "TRailAmtBar.cpp"
#include "TShipyardCluster.cpp"
#include "TShipAmtBar.cpp"
#include "TTraderAmtBar.cpp"

// FUNCTION: IMPERIALISM 0x0058a1b0
void __fastcall RenderQuickDrawControlWithHitRegionClip_B(TradeControl* control) {
  AcquireReusableQuickDrawSurface();
  reinterpret_cast<void(__cdecl*)()>(ApplyHitRegionToClipState)();

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      int boundsRect[4] = {0, 0, 0, 0};
      control->QueryBounds(boundsRect);
      ApplyRectClipRegion(boundsRect);
      control->QueryBounds(boundsRect);
      control->CtrlSlot78();

      short styleValueAt60 = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x60);
      if (styleValueAt60 > 0) {
        SetQuickDrawTextOrigin(0, 1);
        ApplyQuickDrawStyleFromRuntime(0);
        SetQuickDrawStylePair(1, 4);
        DrawCenteredGuideLine((short)(styleValueAt60 - 1), 1);
        reinterpret_cast<void(__cdecl*)()>(ResetQuickDrawStrokeState)();
      }

      short overlayOffsetX = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x62);
      short overlayOffsetY = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x38);
      SetQuickDrawTextOrigin(overlayOffsetX, 0);
      reinterpret_cast<void(__cdecl*)()>(SetQuickDrawFillColor)();
      reinterpret_cast<void(__cdecl*)()>(ResetQuickDrawStrokeState)();
      DrawCenteredGuideLine(overlayOffsetX, (short)(overlayOffsetY - 2));

      reinterpret_cast<void(__cdecl*)()>(SnapshotHitRegionToClipCache)();
      TradeControl* owner = reinterpret_cast<TradeControl*>(CallOwnerPanelSlot58(control));
      if (owner != 0) {
        owner->InvokeSlot13C();
      }
    }
  }

  ReleaseOrCacheQuickDrawSurface();
}

// FUNCTION: IMPERIALISM 0x0058a3b0
void __fastcall RenderQuickDrawOverlayWithHitRegion_0058a3b0(TradeControl* control, int unusedEdx,
                                                             short selectedValue) {
  (void)unusedEdx;
  AcquireReusableQuickDrawSurface();
  *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x62) = selectedValue;
  reinterpret_cast<void(__cdecl*)()>(ApplyHitRegionToClipState)();

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      int boundsRect[4] = {0, 0, 0, 0};
      control->QueryBounds(boundsRect);
      control->CtrlSlot78();

      RECT invalidRect;
      invalidRect.left = boundsRect[0];
      invalidRect.top = boundsRect[1];
      invalidRect.right =
          boundsRect[0] + (int)*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x34);
      invalidRect.bottom =
          boundsRect[1] + (int)*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x38);
      reinterpret_cast<void(__stdcall*)(RECT*, int)>(thunk_InvalidateCityDialogRectRegion)(
          &invalidRect, 1);
    }
  }

  ReleaseOrCacheQuickDrawSurface();
}

// FUNCTION: IMPERIALISM 0x0058ac80
void __fastcall RenderQuickDrawControlWithHitRegionClip_C(TradeControl* control) {
  AcquireReusableQuickDrawSurface();
  reinterpret_cast<void(__cdecl*)()>(ApplyHitRegionToClipState)();

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      int boundsRect[4] = {0, 0, 0, 0};
      control->QueryBounds(boundsRect);
      ApplyRectClipRegion(boundsRect);
      control->QueryBounds(boundsRect);
      control->CtrlSlot78();

      short styleValueAt60 = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x60);
      if (styleValueAt60 > 0) {
        short styleValueAt66 = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x66);
        SetQuickDrawTextOrigin(0, 1);
        ApplyQuickDrawStyleFromRuntime(styleValueAt66);
        SetQuickDrawStylePair(1, 4);
        DrawCenteredGuideLine(styleValueAt60, 1);
        reinterpret_cast<void(__cdecl*)()>(ResetQuickDrawStrokeState)();
      }

      reinterpret_cast<void(__cdecl*)()>(SnapshotHitRegionToClipCache)();
      TradeControl* owner = reinterpret_cast<TradeControl*>(CallOwnerPanelSlot58(control));
      if (owner != 0) {
        owner->InvokeSlot13C();
      }
    }
  }

  ReleaseOrCacheQuickDrawSurface();
}

// FUNCTION: IMPERIALISM 0x0058b0f0
void __fastcall RenderControlWithTemporaryRectClipRegionAndChildren(TradeControl* control) {
  AcquireReusableQuickDrawSurface();
  reinterpret_cast<void(__cdecl*)()>(ApplyHitRegionToClipState)();

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      int boundsRect[4] = {0, 0, 0, 0};
      control->QueryBounds(boundsRect);
      control->ApplyBounds(boundsRect, 1);
      control->QueryBounds(boundsRect);
      control->CtrlSlot78();

      short styleValueAt60 = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x60);
      if (styleValueAt60 > 0) {
        short styleValueAt66 = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x66);
        SetQuickDrawTextOrigin(0, 0);
        ApplyQuickDrawStyleFromRuntime(styleValueAt66);
        SetQuickDrawStylePair(1, 5);
        DrawCenteredGuideLine((short)(styleValueAt60 - 1), 0);
        reinterpret_cast<void(__cdecl*)()>(ResetQuickDrawStrokeState)();
      }

      reinterpret_cast<void(__cdecl*)()>(SnapshotHitRegionToClipCache)();
      TradeControl* owner = reinterpret_cast<TradeControl*>(CallOwnerPanelSlot58(control));
      if (owner != 0) {
        owner->InvokeSlot13C();
      }
    }
  }

  ReleaseOrCacheQuickDrawSurface();
}

// FUNCTION: IMPERIALISM 0x0058b460
void __fastcall OrphanCallChain_C4_I34_0058b460(NumberedArrowButtonState* control, int unusedEdx,
                                                int selectedValue) {
  (void)unusedEdx;
  control->hoverTag4e = 0xc;
  *reinterpret_cast<int*>(reinterpret_cast<char*>(control) + 0x9c) = selectedValue;
  if (selectedValue != 0) {
    reinterpret_cast<TradeControl*>(control)->SetEnabledPair(1, 0);
    reinterpret_cast<TradeControl*>(control)->SetStatePair(1, 0);
    short mappedValue = (short)selectedValue;
    void* globalMapState = ReadPointerAt(kAddrGlobalMapState);
    if (globalMapState != 0) {
      mappedValue = reinterpret_cast<short(__fastcall*)(void*, int)>(
          (*reinterpret_cast<void***>(globalMapState))[0x118 / 4])(globalMapState, selectedValue);
    }
    *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x98) = mappedValue;
    return;
  }
  reinterpret_cast<TradeControl*>(control)->SetEnabledPair(0, 1);
}

// FUNCTION: IMPERIALISM 0x0058b4f0
void __fastcall BlitHintOverlayRectWithCtrlModifierPalette(void* control) {
  if (*reinterpret_cast<int*>(reinterpret_cast<char*>(control) + 4) != 0) {
    reinterpret_cast<void(__fastcall*)(void*)>(thunk_RenderHintHelperWithCtrlModifierOverlay)(
        control);
  }
  reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x10);

  RECT srcRect;
  srcRect.left = (int)*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x98);
  srcRect.top = 0;
  srcRect.right = srcRect.left + 0x40;
  srcRect.bottom = 0x40;

  RECT dstRect;
  dstRect.left = 0;
  dstRect.top = 2;
  dstRect.right = 0x40;
  dstRect.bottom = 0x42;

  int strategicMapViewSystem = (int)ReadPointerAt(kAddrStrategicMapViewSystem);
  int activeQuickDrawSurfaceContext = (int)ReadPointerAt(kAddrActiveQuickDrawSurfaceContext);
  reinterpret_cast<void(__stdcall*)(void*, void*, RECT*, RECT*, unsigned char, void*)>(
      BlitRectWithOptionalTransparency)(
      reinterpret_cast<void*>(*reinterpret_cast<int*>(strategicMapViewSystem + 0x66c) + 4),
      reinterpret_cast<void*>(activeQuickDrawSurfaceContext + 4), &srcRect, &dstRect, 0x24, 0);

  reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x13);
}

// FUNCTION: IMPERIALISM 0x0058b750
void __fastcall OrphanCallChain_C3_I43_0058b750(NumberedArrowButtonState* control, int unusedEdx,
                                                char mode, char refreshParent) {
  (void)unusedEdx;
  if (mode != *reinterpret_cast<char*>(reinterpret_cast<char*>(control) + 0x64)) {
    *reinterpret_cast<char*>(reinterpret_cast<char*>(control) + 0x64) = mode;
    short bitmapId = 0;
    short modeState = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x98);
    if (mode == 0) {
      if (modeState == 0) {
        bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x90);
      } else if (modeState == 1) {
        bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x94);
      } else {
        bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x96);
      }
    } else {
      bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x92);
    }
    reinterpret_cast<TradeControl*>(control)->SetBitmap(bitmapId, 1);
    if (refreshParent != 0) {
      TradeControl* owner = reinterpret_cast<TradeControl*>(CallOwnerPanelSlot58(control));
      if (owner != 0) {
        owner->InvokeSlot13C();
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0058b890
void __fastcall OrphanCallChain_C2_I16_0058b890(TradeControl* control, int unusedEdx, int arg2,
                                                int arg3) {
  (void)unusedEdx;
  if (CallBoolSlot28(control) != 0) {
    control->InvokeSlot1CC(arg2, arg3);
  }
}

// FUNCTION: IMPERIALISM 0x0058b8d0
void __fastcall OrphanCallChain_C2_I37_0058b8d0(NumberedArrowButtonState* control, int unusedEdx,
                                                short mode) {
  (void)unusedEdx;
  *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x98) = mode;
  *reinterpret_cast<char*>(reinterpret_cast<char*>(control) + 0x64) = 0;
  short bitmapId = 0;
  if (mode == 0) {
    bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x90);
  } else if (mode == 1) {
    bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x94);
  } else {
    bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x96);
  }
  reinterpret_cast<TradeControl*>(control)->SetBitmap(bitmapId, 1);
  reinterpret_cast<TradeControl*>(control)->SetStatePair(mode != 2, 0);
}

// FUNCTION: IMPERIALISM 0x0058bfe0
void __fastcall RenderRightAlignedNumericOverlayWithShadow(PlacardState* control) {
  int sharedStringRef = 0;
  InitializeSharedStringRefFromEmpty(&sharedStringRef);

  reinterpret_cast<void(__fastcall*)(void*)>(thunk_RenderHintHelperWithCtrlModifierOverlay)(
      control);

  if (control->placardValue != 0) {
    reinterpret_cast<void(__cdecl*)()>(ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor)();
    reinterpret_cast<void(__cdecl*)(int*, const char*, int)>(FormatStringWithVarArgsToSharedRef)(
        &sharedStringRef, reinterpret_cast<const char*>(kAddrDecimalFormat),
        (int)control->placardValue);

    short textWidth =
        reinterpret_cast<short(__cdecl*)()>(thunk_MeasureTextExtentWithCachedQuickDrawStyle)();
    short textX =
        (short)(*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x34) - textWidth);
    short textY = (short)(*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x38) - 2);
    SetQuickDrawTextOrigin(textX, textY);
    reinterpret_cast<void(__cdecl*)(int*)>(thunk_DrawTextWithCachedQuickDrawStyleState)(
        &sharedStringRef);

    reinterpret_cast<void(__cdecl*)()>(ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor)();
    SetQuickDrawTextOrigin((short)(textX - 1), (short)(textY - 1));
    reinterpret_cast<void(__cdecl*)(int*)>(thunk_DrawTextWithCachedQuickDrawStyleState)(
        &sharedStringRef);
  }

  ReleaseSharedStringRefIfNotEmpty(&sharedStringRef);
}

// FUNCTION: IMPERIALISM 0x0059a180
void TradeScreenContext::SetTradeToolSubcontrolEnabledStateByFlag(unsigned char enabledFlag) {
  TradeControl* toolControl = ResolveControlByTag(0x746f6f6c);
  if (toolControl == 0) {
    FailNilPointerWithAssert(kUSuperMapCppPath, kAssertLineToolSubcontrolToggle);
  }

  TradeControl* control = ResolveOwnerControl(toolControl, 0x73656173);
  if (control != 0) {
    control->SetEnabledPair((int)enabledFlag, 1);
  }
  control = ResolveOwnerControl(toolControl, 0x79656172);
  if (control != 0) {
    control->SetEnabledPair((int)enabledFlag, 1);
  }
  control = ResolveOwnerControl(toolControl, 0x74726561);
  if (control != 0) {
    control->SetEnabledPair((int)enabledFlag, 1);
  }
  control = ResolveOwnerControl(toolControl, 0x74726565);
  if (control != 0) {
    control->SetEnabledPair((int)enabledFlag, 1);
  }
}

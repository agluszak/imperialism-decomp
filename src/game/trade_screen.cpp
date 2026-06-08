// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#include "decomp_types.h"
#include "game/GameAssert.h"
#include "game/NationState.h"
#include "game/CString.h"
#include "game/ui_widget_shared.h"
#include "game/TView.h"
#include "game/TUberCluster.h"
#include "game/trade_quickdraw.h"
#include "game/TAmtBar.h"
#include "game/TTraderAmtBar.h"
#include "game/TIndustryAmtBar.h"
#include "game/TRailAmtBar.h"
#include "game/TShipAmtBar.h"
#include "game/TStatusButton.h"
#include "game/TProductionCluster.h"
#include "game/vcall_runtime.h"
#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"

typedef void code(void);
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
undefined4 thunk_ConstructUiResourceEntryType4B0C0(void);
undefined4 thunk_ConstructUiClickablePictureResourceEntry(void);
undefined4 thunk_DestructEngineerDialogBaseState(void);
undefined4 thunk_DestructCityDialogSharedBaseState(void); // GHIDRA_FUNCTION IMPERIALISM 0x004601B0
undefined4 thunk_DispatchPictureResourceCommand(void);
undefined4 thunk_DispatchPanelControlEvent(void);
undefined4 thunk_GetTickCountDiv16(void);
undefined4 thunk_InitializeUiTextStyleDescriptor(void);
undefined4 DispatchUiMouseEventToChildrenOrSelf(void);
undefined4 CreateClipStateRegionWrapperObject(void);
undefined4 WrapperFor_DeleteRegionHandleFromClipState_At00495520(void);
undefined4 FormatStringWithVarArgsToSharedRef(void);
undefined4 thunk_MeasureTextExtentWithCachedQuickDrawStyle(void);
undefined4 thunk_DrawTextWithCachedQuickDrawStyleState(void);
void __fastcall HandleTradeArrowAutoRepeatTickAndDispatch(void* self, int unusedEdx,
                                                          int repeatState, void* arg8, void* argC,
                                                          void* dispatchArg, void* arg14);
// GHIDRA_NAME: InitializeTradeScreenBitmapControls
// GHIDRA_PROTO: undefined InitializeTradeScreenBitmapControls()
/* DECOMPILATION FAILED: Exception while decompiling 004601b0: process: timeout */

// Symbol placeholders to preserve OFFSET-style codegen in ctor/dtor wrappers.
// GLOBAL: IMPERIALISM 0x663010
extern "C" char g_pClassDescTShipAmtBar = 0;
extern "C" char g_vtblTTraderAmtBar = 0;
// GLOBAL: IMPERIALISM 0x663028
extern "C" char g_pClassDescTTraderAmtBar = 0;
// GLOBAL: IMPERIALISM 0x662f68
extern "C" char g_pClassDescTTradeCluster = 0;
extern "C" char PTR_thunk_GetTTradeClusterClassNamePointer_00665a70 = 0;



const char kUSmallViewsCppPath[] = "D:\\Ambit\\Cross\\USmallViews.cpp";
const char kUSuperMapCppPath[] = "D:\\Ambit\\Cross\\USuperMap.cpp";
const char kQuickDrawCppPath[] = "D:\\Ambit\\QuickDraw.cpp";

extern const int kControlTagBar = 0x62617220;
const int kControlTagAvai = 0x61766169;
const int kControlTagCard = 0x63617264;
const int kControlTagBack = 0x6261636b;
const int kControlTagOffr = 0x6f666672;
const int kControlTagGree = 0x67726565;
const int kControlTagLeft = 0x6c656674;
const int kControlTagRght = 0x72676874;
const int kControlTagArms = 0x41726d73;
const int kControlTagClos = 0x436c6f73;
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
// Asserts moved
const int kAssertLineTradeSellIncSell = 0x816;
const int kAssertLineTradeSellIncCap = 0x81d;
const int kAssertLineMovePageMinus = 0xd34;
const int kAssertLineMovePagePlus = 0xd3c;
const int kAssertLineToolSubcontrolToggle = 0xac7;
const unsigned int kVtableTIndustryCluster = 0x00665ed0;
const unsigned int kAddrClassDescTIndustryCluster = 0x00662f98;
const unsigned int kVtableTIndustryAmtBar = 0x00666110;
const unsigned int kVtableTAmtBar = 0x00665cc8;
const unsigned int kVtableTRailCluster = 0x00666318;
const unsigned int kAddrClassDescTRailCluster = 0x00662fc8;
const unsigned int kVtableTRailAmtBar = 0x00666558;
const unsigned int kVtableTShipyardCluster = 0x00666760;
const unsigned int kAddrClassDescTShipyardCluster = 0x00662ff8;
// Removed TUnitToolbarCluster constants
// Constants moved
const unsigned int kAddrDecimalFormat = 0x0069430C;
const unsigned int kAddrStrategicMapViewSystem = 0x006A21A8;
const unsigned int kAddrGlobalMapState = 0x006A43D4;
const unsigned int kAddrOverlayClipCacheParamX = 0x006A4450;
const unsigned int kAddrOverlayClipCacheParamY = 0x006A4454;

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

struct TradeMovePanelContext;
struct CityTradeScenarioDescriptor;
struct TDocument;

struct TradeBarControlLayout {
  void* vftable;
  char pad_04[0x30];
  short barRange;
  char pad_36[0x2e];
  short barSteps;
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

struct TradeMovePanelContext;

// The trade-screen UI object is a cluster-family view: it dispatches through the
// TView vtable (ResolveControlByTag @0x94), reads TView::selectedControlTagOrState1c
// (0x1c), and carries a cluster field at 0x88. Model it as real TUberCluster
// inheritance instead of a standalone vftable struct, so member access and slot
// dispatch need no reinterpret_cast over the native object.
struct TradeScreenContext : public TUberCluster {
  short tradeMetricSlot;  // 0x88, first field past TUberCluster

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

// ApplicationUiRootControllerState moved to global scope

struct UnitToolbarClusterState {
  void* vftable;
  char pad_04[0x84];
};

struct CityBarClusterState {
  void* vftable;
  char pad_04[0x84];
};

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


static __inline char CallControlFlagSlot1D8(TradeControl* control) {
  return reinterpret_cast<char(__fastcall*)(TradeControl*)>(
      (*reinterpret_cast<void***>(control))[0x1d8 / 4])(control);
}

static __inline void CallControlActionSlot1E0(TradeControl* control) {
  reinterpret_cast<void(__fastcall*)(TradeControl*)>(
      (*reinterpret_cast<void***>(control))[0x1e0 / 4])(control);
}

static __inline short CallQueryNationMetricBySlot78(NationState* nationState, short metricSlot) {
  return nationState->QueryNationMetricBySlot78(metricSlot);
}

static __inline short CallQueryNationMetricBySlot7C(NationState* nationState, short metricSlot) {
  return nationState->QueryNationMetricBySlot7C(metricSlot);
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

static __inline void FailNilPointerWithAssert(const char* sourcePath, int line);
void FailNilPointerInUSmallViews(int line);

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

__inline TradeControl* TradeScreenContext::ResolveControlByTag(int controlTag) {
  // Shadows TView::ResolveControlByTag; call the base explicitly to avoid recursion.
  // The remaining cast is the TControl*->TradeControl* dispatch-view bridge for the
  // trade-specific control slots (e.g. QueryValue @0x1E8), not a this-pointer cast.
  return reinterpret_cast<TradeControl*>(TView::ResolveControlByTag(controlTag));
}

__inline TradeControl* TradeScreenContext::RequireControlByTag(int controlTag) {
  TradeControl* control = ResolveControlByTag(controlTag);
  if (control == 0) {
    GAME_FAIL_NIL_POINTER();
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
  GAME_FAIL_NIL_POINTER();
  reinterpret_cast<void(__cdecl*)(const char*, int)>(thunk_DestructTShipAndFreeIfOwned)(sourcePath,
                                                                                        line);
}

void FailNilPointerInUSmallViews(int line) {
  FailNilPointerWithAssert(kUSmallViewsCppPath, line);
}

static __inline short QueryUiScreenModeSafe(UiRuntimeContext* runtimeContext) {
  if (runtimeContext == 0 || *reinterpret_cast<void**>(runtimeContext) == 0) {
    return 4;
  }
  return runtimeContext->QueryUiScreenModeSlot54();
}

int QueryUiScreenModeRaw(UiRuntimeContext* runtimeContext) {
  return runtimeContext->QueryUiScreenModeSlot54();
}

NationState* GetNationStateBySlot(short slotId) {
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

short QueryNationMetricBySlot(NationState* nationState, short metricSlot) {
  return CallQueryNationMetricBySlot78(nationState, metricSlot);
}

static __inline short QueryNationTradeCapacity(NationState* nationState) {
  return nationState->tradeCapacity;
}

// GLOBAL: IMPERIALISM 0x6a18e0
// g_pApplicationUiRootController moved to global scope
// GLOBAL: IMPERIALISM 0x6a44b0
void* g_pActiveCityDialogLegendSelectionOwner = 0;
// GLOBAL: IMPERIALISM 0x6a44b4
unsigned char g_bCityDialogLegendSelectionInitialized = 0;



struct ApplicationUiRootControllerState {
  void* vftable;
  char pad_04[0x20];
  int screenModeAt24;
};

ApplicationUiRootControllerState* g_pApplicationUiRootController = 0;

// GLOBAL: IMPERIALISM 0x6a1c98
void* g_pReusableQuickDrawSurfaceListHead = 0;

// FUNCTION: IMPERIALISM 0x00497320
QuickDrawSurfaceGuard::QuickDrawSurfaceGuard() {
  // ORIG_CALLCONV: __thiscall
  if (g_pReusableQuickDrawSurfaceListHead != 0) {
    surfaceWrapper = reinterpret_cast<int>(g_pReusableQuickDrawSurfaceListHead);
    g_pReusableQuickDrawSurfaceListHead = 0;
    return;
  }
  surfaceWrapper = (int)CreateClipStateRegionWrapperObject();
  if (surfaceWrapper == 0) {
    GAME_FAIL_NIL_POINTER();
    reinterpret_cast<void(__cdecl*)(const char*, int)>(thunk_DestructTShipAndFreeIfOwned)(
        kQuickDrawCppPath, 0x7f6);
  }
}

// FUNCTION: IMPERIALISM 0x00497390
QuickDrawSurfaceGuard::~QuickDrawSurfaceGuard() {
  // ORIG_CALLCONV: __thiscall
  if (g_pReusableQuickDrawSurfaceListHead != 0) {
    int regionWrapper = surfaceWrapper;
    if (regionWrapper != 0) {
      int regionHandle = *reinterpret_cast<int*>(regionWrapper);
      if (regionHandle != 0) {
        reinterpret_cast<void(__cdecl*)()>(WrapperFor_DeleteRegionHandleFromClipState_At00495520)();
        FreeHeapBufferIfNotNull(regionHandle);
      }
    }
    FreeHeapBufferIfNotNull(regionWrapper);
    surfaceWrapper = 0;
    return;
  }
  g_pReusableQuickDrawSurfaceListHead = reinterpret_cast<void*>(surfaceWrapper);
  surfaceWrapper = 0;
}

// GLOBAL: IMPERIALISM 0x6a21bc
extern "C" UiRuntimeContext* g_pUiRuntimeContext = 0;

// FUNCTION: IMPERIALISM 0x00403b16
short UiRuntimeContext::GetActiveNationId(void) {
  return activeNationIdAt2E;
}

unsigned int __cdecl thunk_GetActiveNationId(void) {
  return g_pUiRuntimeContext->GetActiveNationId();
}

undefined4 thunk_NoOpUiLifecycleHook(void) {
  return 0;
}

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
void __fastcall HandleTradeArrowAutoRepeatTickAndDispatch(void* self, int unusedEdx,
                                                          int repeatState, void* arg8, void* argC,
                                                          void* dispatchArg, void* arg14) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  reinterpret_cast<void(__fastcall*)(void*, int, int, void*, void*, void*, void*)>(
      ::thunk_DispatchPictureResourceCommand)(self, 0, repeatState, arg8, argC, dispatchArg, arg14);

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

// TUnitToolbarCluster moved to its own file

// FUNCTION: IMPERIALISM 0x00586280
TStatusButton* __cdecl CreateTStatusButtonInstance(void) {
  return new TStatusButton();
}

// FUNCTION: IMPERIALISM 0x00586310
void* __cdecl GetTStatusButtonClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTStatusButton);
}

// Destructor is compiler-generated (implicit) from real TButton inheritance.
// SYNTHETIC: IMPERIALISM 0x005863b0
// TStatusButton::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00586400
void __fastcall HandleCityDialogSelectionAndBackControlReset(TStatusButton* button, int unusedEdx,
                                                             int selectedIndex) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;

  if (selectedIndex == button->QuerySelectedIndexSlotBC() && button->GetBoolSlot28() != '\0') {
    if (button->GetBoolSlot1BC() == '\0') {
      if (g_pActiveCityDialogLegendSelectionOwner != 0) {
        reinterpret_cast<TView*>(g_pActiveCityDialogLegendSelectionOwner)->CallVoidSlotA0();
        g_pActiveCityDialogLegendSelectionOwner = 0;
        g_bCityDialogLegendSelectionInitialized = 0;
      }

      TradeControl* backControl =
          reinterpret_cast<TradeControl*>(reinterpret_cast<TView*>(button->OwnerPanel())->ResolveControlByTag(kControlTagBack));
      if (backControl != 0) {
        reinterpret_cast<TView*>(backControl)->CallVoidSlot1C();
        reinterpret_cast<TView*>(button->OwnerPanel())->RefreshControl();
      }

      if (button->ControlTag() != kControlTagArms && button->ControlTag() == kControlTagClos) {
        if (g_pActiveCityDialogLegendSelectionOwner != 0) {
          reinterpret_cast<TView*>(g_pActiveCityDialogLegendSelectionOwner)->CallVoidSlotA0();
          g_pActiveCityDialogLegendSelectionOwner = 0;
        }
        g_bCityDialogLegendSelectionInitialized = 0;
        TView* ownerPanel = reinterpret_cast<TView*>(button)->OwnerPanel();
        if (ownerPanel != 0) {
          ownerPanel->CallVoidSlotA0();
        }
      }
    }
  }

  thunk_HandleCityDialogToggleCommandOrForward();
}

// TCityBarCluster moved

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

// 0x00586c40 CreateInstance, 0x00586cc0 GetClassNamePointer, 0x00586ce0 ctor and
// 0x00586d10 (scalar deleting destructor) are owned by src/game/TAmtBarCluster.cpp
// as real C++ construction/inheritance.

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
      reinterpret_cast<TControl*>(this)->ApplyMoveValue(moveValue + 1);
    }
  } else if (normalizedCommand == 1) {
    TradeControl* moveControl =
        reinterpret_cast<TradeControl*>(resolveByTag(this, kControlTagMove));
    if (moveControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineMoveAdjustMoveMinus);
    }
    int moveValue = moveControl->QueryValue();
    if ((short)moveValue != 0) {
      reinterpret_cast<TControl*>(this)->ApplyMoveValue(moveValue - 1);
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
    TradeScreenRuntimeBridge::ConstructTUberClusterObject(cluster);
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
  TradeScreenRuntimeBridge::ConstructTUberClusterObject(self);
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
  TradeControl* sellControl = context->ResolveControlByTag(kControlTagSell);
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
  TradeControl* sellControl = this->ResolveControlByTag(kControlTagSell);
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
  TradeControl* bidControl = this->ResolveControlByTag(kControlTagCard);
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
  TradeControl* offerControl = this->ResolveControlByTag(kControlTagOffr);
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
    if (selectedControlTagOrState1c == kTradeRowStateTag_67643020) {
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
  if (selectedControlTagOrState1c == kTradeRowStateTag_67643020) {
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
  if (selectedControlTagOrState1c == kTradeRowStateTag_67643020) {
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
      if (selectedControlTagOrState1c == kTradeRowStateTag_67643020) {
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

// GHIDRA_NAME TAmtBar::HandleTradeMoveStepCommand
// GHIDRA_PROTO void __thiscall HandleTradeMoveStepCommand(void)

// FUNCTION: IMPERIALISM 0x00589340

// FUNCTION: IMPERIALISM 0x00589540
void __fastcall RenderQuickDrawOverlayWithHitRegion_00589540(TradeControl* control, int unusedEdx,
                                                             short selectedValue) {
  (void)unusedEdx;
  QuickDrawSurfaceGuard surface;
  *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x62) = selectedValue;
  reinterpret_cast<void(__cdecl*)(int)>(ApplyHitRegionToClipState)(surface.surfaceWrapper);

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
}

// FUNCTION: IMPERIALISM 0x00589720
void __fastcall ConstructTradeMoveScaledControlPanel(TradeMoveStepCluster* cluster) {
  TradeScreenRuntimeBridge::ConstructTUberClusterObject(cluster);
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
  NationCityTradeState* cityState =
      activeNationState == 0
          ? 0
          : activeNationState->cityState;

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

  TradeControl* moveControl = reinterpret_cast<TradeControl*>(reinterpret_cast<TView*>(this)->ResolveControlByTag(kControlTagMove));
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

  TradeControl* barControl = reinterpret_cast<TradeControl*>(reinterpret_cast<TView*>(this)->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(0xcf9);
  }

  TradeMoveControlState* barLayout = reinterpret_cast<TradeMoveControlState*>(barControl);
  TAmtBar* barAmount = reinterpret_cast<TAmtBar*>(barControl);
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

#include "game/TAmtBar.h"
#include "game/TIndustryAmtBar.h"
#include "game/TRailAmtBar.h"
#include "game/TShipAmtBar.h"

// FUNCTION: IMPERIALISM 0x0058a3b0
void __fastcall RenderQuickDrawOverlayWithHitRegion_0058a3b0(TradeControl* control, int unusedEdx,
                                                             short selectedValue) {
  (void)unusedEdx;
  QuickDrawSurfaceGuard surface;
  *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x62) = selectedValue;
  reinterpret_cast<void(__cdecl*)(int)>(ApplyHitRegionToClipState)(surface.surfaceWrapper);

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
      TradeControl* owner = reinterpret_cast<TradeControl*>(reinterpret_cast<TView*>(control)->OwnerPanel());
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
  if (reinterpret_cast<TView*>(control)->GetBoolSlot28() != 0) {
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
  CString sharedStringRef;
  int* sharedStringRefPtr = reinterpret_cast<int*>(&sharedStringRef);

  reinterpret_cast<void(__fastcall*)(void*)>(thunk_RenderHintHelperWithCtrlModifierOverlay)(
      control);

  if (control->glyph90 != 0) {
    reinterpret_cast<void(__cdecl*)()>(ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor)();
    reinterpret_cast<void(__cdecl*)(int*, const char*, int)>(FormatStringWithVarArgsToSharedRef)(
        sharedStringRefPtr, reinterpret_cast<const char*>(kAddrDecimalFormat),
        static_cast<int>(control->glyph90));

    short textWidth =
        reinterpret_cast<short(__cdecl*)()>(thunk_MeasureTextExtentWithCachedQuickDrawStyle)();
    short textX =
        (short)(*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x34) - textWidth);
    short textY = (short)(*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x38) - 2);
    SetQuickDrawTextOrigin(textX, textY);
    reinterpret_cast<void(__cdecl*)(int*)>(thunk_DrawTextWithCachedQuickDrawStyleState)(
        sharedStringRefPtr);

    reinterpret_cast<void(__cdecl*)()>(ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor)();
    SetQuickDrawTextOrigin((short)(textX - 1), (short)(textY - 1));
    reinterpret_cast<void(__cdecl*)(int*)>(thunk_DrawTextWithCachedQuickDrawStyleState)(
        sharedStringRefPtr);
  }

  sharedStringRef.~CString();
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

// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#include "decomp_types.h"

#include "game/TNumberedArrowButton.h"
#include "game/TPlacard.h"
#include "game/TCivilianButton.h"
#include "game/THQButton.h"
#include "game/TCombatReportView.h"
#include "game/TTradeCluster.h"
#include "game/TPictureResourceEntryBase.h"

#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/win_rect.h"
#include "game/ui_widget_thunks.h"
#include <new>
#include "game/GameAssert.h"
#include "game/NationState.h"
#include "game/CString.h"
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
extern "C" char PTR_thunk_GetTTradeClusterClassNamePointer_00665a70 = 0;
extern "C" char g_pClassDescTTradeCluster = 0;



const char kUSmallViewsCppPath[] = "D:\\Ambit\\Cross\\USmallViews.cpp";
const char kQuickDrawCppPath[] = "D:\\Ambit\\QuickDraw.cpp";

extern const int kControlTagBar = 0x62617220;

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

const int kTradeSellPropagationTags[] = {
    0x72733020, 0x72733120, 0x72733220, 0x72733320, 0x72733420, 0x72733520,
    0x72733620, 0x6d613020, 0x6d613120, 0x6d613220, 0x6d613320, 0x6d613420,
    0x6d613520, 0x67643020, 0x67643120, 0x67643220, 0x67643320,
};

struct TradeMovePanelContext;
struct CityTradeScenarioDescriptor;
struct TDocument;


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
  void HandleTradeMoveArrowControlEvent(int commandId, TAmtBar* sourceControl, int eventExtra);
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

static __inline short ReadControlValueFieldPlus4(TAmtBar* control) {
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 4);
}


static __inline char CallControlFlagSlot1D8(TAmtBar* control) {
  return reinterpret_cast<char(__fastcall*)(TAmtBar*)>(
      (*reinterpret_cast<void***>(control))[0x1d8 / 4])(control);
}

static __inline void CallControlActionSlot1E0(TAmtBar* control) {
  reinterpret_cast<void(__fastcall*)(TAmtBar*)>(
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
  TAmtBar* selectedMetricControl;
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



#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif

// FUNCTION: IMPERIALISM 0x00401b3b
void __fastcall thunk_HandleTradeArrowAutoRepeatTickAndDispatch(TAmtBar* self, int unusedEdx,
                                                                int repeatState, void* arg8,
                                                                void* argC, void* dispatchArg,
                                                                void* arg14) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  HandleTradeArrowAutoRepeatTickAndDispatch(self, 0, repeatState, arg8, argC, dispatchArg, arg14);
}

// FUNCTION: IMPERIALISM 0x004032fb
void __fastcall thunk_SetTradeToolSubcontrolEnabledStateByFlag(TTradeCluster* self,
                                                               int unusedEdx,
                                                               unsigned char enabledFlag) {
  (void)unusedEdx;
  self->SetTradeToolSubcontrolEnabledStateByFlag(enabledFlag);
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

  TAmtBar* selfControl = reinterpret_cast<TAmtBar*>(self);
  char isActive = selfControl->vmethod_0091(dispatchArg);
  if (isActive == '\0') {
    return;
  }

  if (*reinterpret_cast<int*>(reinterpret_cast<char*>(self) + 0x1c) == kControlTagRght) {
    selfControl->DispatchEvent(100, 0, 0);
    return;
  }

  selfControl->DispatchEvent(0x65, self, 0);
}

#if defined(_MSC_VER)
#pragma optimize("y", off)
#endif

// TUnitToolbarCluster moved to its own file

// TStatusButton functions moved to TStatusButton.cpp

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
  TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(ResolveOwnerControl(panel, kControlTagMove));
  unsigned int styleDescriptor = styleSeed & 0xffff0000;
  if (moveControl != 0) {
    reinterpret_cast<void(__cdecl*)(int, unsigned int*, int, int)>(
        thunk_BuildUiTextStyleDescriptor)(0, &styleDescriptor, 0xa, 0x2b67);
    moveControl->ApplyStyleDescriptor(&styleDescriptor, 0);
    moveControl->SetStyleState(-2, 0);
  }

  TAmtBar* barControl = reinterpret_cast<TAmtBar*>(ResolveOwnerControl(panel, kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineMoveBarInitNil);
  }
  reinterpret_cast<void(__fastcall*)(TAmtBar*, int, unsigned int)>(
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
    TAmtBar* moveControl =
        reinterpret_cast<TAmtBar*>(resolveByTag(this, kControlTagMove));
    if (moveControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineMoveAdjustMove);
    }
    short moveValue = moveControl->QueryValue();

    TAmtBar* availableControl =
        reinterpret_cast<TAmtBar*>(resolveByTag(this, kControlTagAvai));
    if (availableControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineMoveAdjustAvai);
    }
    short availableValue = (short)availableControl->QueryValue();
    if (moveValue < availableValue) {
      reinterpret_cast<TCluster*>(this)->ApplyMoveValue(moveValue + 1);
    }
  } else if (normalizedCommand == 1) {
    TAmtBar* moveControl =
        reinterpret_cast<TAmtBar*>(resolveByTag(this, kControlTagMove));
    if (moveControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineMoveAdjustMoveMinus);
    }
    int moveValue = moveControl->QueryValue();
    if ((short)moveValue != 0) {
      reinterpret_cast<TCluster*>(this)->ApplyMoveValue(moveValue - 1);
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
    new (cluster) TUberCluster();
    *reinterpret_cast<void**>(cluster) =
        reinterpret_cast<void*>(&PTR_thunk_GetTTradeClusterClassNamePointer_00665a70);
  }
  return cluster;
}

// FUNCTION: IMPERIALISM 0x005870b0
void __fastcall ConstructTradeSellControlPanel(void* self)

{
  new (self) TUberCluster();
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


static __inline void UpdateTradeBarFromSelectedMetricRatio(TradeMovePanelContext* context,
                                                           int assertLine) {
  void* owner = context;
  TAmtBar* barControl = reinterpret_cast<TAmtBar*>(ResolveOwnerControl(owner, kControlTagBar));
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
void __fastcall RenderQuickDrawOverlayWithHitRegion_00589540(TAmtBar* control, int unusedEdx,
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
      control->vmethod_0078();
      invalidRect[2] =
          cachedX + (int)*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x34);
      invalidRect[3] =
          cachedY + (int)*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x38);
      reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
          (int)invalidRect, 1);
    }
  }
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
  TAmtBar* selectedControl = selectedMetricControl;
  short previousValue = ReadControlValueFieldPlus4(selectedControl);
  if (selectedControl != 0) {
    selectedControl->SetControlValue(quantizedDragValue);
  }

  if (((char)updateFlag == 0) && (ReadControlValueFieldPlus4(selectedControl) == previousValue)) {
    return;
  }

  TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(reinterpret_cast<TView*>(this)->ResolveControlByTag(kControlTagMove));
  if (moveControl == 0) {
    FailNilPointerInUSmallViews(0xcf2);
  }

  moveControl->SetControlValueSlot1E4((int)ReadControlValueFieldPlus4(selectedControl), 0);

  RECT moveBoundsRect;
  RECT moveInvalidRect;
  moveControl->QueryBounds(reinterpret_cast<int*>(&moveBoundsRect));
  OffsetRect(&moveBoundsRect, ownerOffsetX, ownerOffsetY);
  CopyRect(&moveInvalidRect, &moveBoundsRect);
  reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
      (int)&moveInvalidRect, 1);

  TAmtBar* barControl = reinterpret_cast<TAmtBar*>(reinterpret_cast<TView*>(this)->ResolveControlByTag(kControlTagBar));
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
void __fastcall RenderQuickDrawOverlayWithHitRegion_0058a3b0(TAmtBar* control, int unusedEdx,
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
      control->vmethod_0078();

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

// TNumberedArrowButton functions moved to TNumberedArrowButton.cpp
// TPlacard functions moved to TPlacard.cpp


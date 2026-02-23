// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#include "decomp_types.h"

typedef void *hwnd_t;
extern "C" int __stdcall MessageBoxA(hwnd_t hWnd, const char *text, const char *caption, unsigned int type);
undefined4 TemporarilyClearAndRestoreUiInvalidationFlag(void);
unsigned int __cdecl thunk_GetActiveNationId(void);
undefined4 InitializeTradeMoveAndBarControls(void);



// GHIDRA_FUNCTION IMPERIALISM 0x004601B0
// GHIDRA_NAME: InitializeTradeScreenBitmapControls
// GHIDRA_PROTO: undefined InitializeTradeScreenBitmapControls()
/* DECOMPILATION FAILED: Exception while decompiling 004601b0: process: timeout */

namespace {

const char kNilPointerText[] = "Nil Pointer";
const char kFailureCaption[] = "Failure";
const char kUSmallViewsCppPath[] = "D:\\Ambit\\Cross\\USmallViews.cpp";

const int kControlTagSell = 0x53656c6c;
const int kControlTagBar = 0x62617220;
const int kControlTagCard = 0x63617264;
const int kControlTagOffr = 0x6f666672;
const int kControlTagGree = 0x67726565;
const int kControlTagLeft = 0x6c656674;
const int kControlTagRght = 0x72676874;
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
const int kAssertLineInitBar = 0x7a2;
const int kAssertLineInitLeft = 0x7a6;
const int kAssertLineInitRight = 0x7a8;
const int kAssertLineUpdateSell = 0x9e0;
const int kAssertLineUpdateBar = 0x9e4;
const int kAssertLineUpdateGree = 0x9e7;

const short kTradeBitmapBidStateA = 0x083f;
const short kTradeBitmapBidStateB = 0x084d;
const short kTradeBitmapBidSecondaryStateA = 0x0840;
const short kTradeBitmapBidSecondaryStateB = 0x084e;
const short kTradeBitmapOfferStateA = 0x0841;
const short kTradeBitmapOfferStateB = 0x084f;
const short kTradeBitmapOfferSecondaryStateA = 0x0842;
const short kTradeBitmapOfferSecondaryStateB = 0x0850;
const int kTradeRowStateTag_67643020 = 0x67643020;
const unsigned int kAddrGlobalNationStates = 0x006A4370;

struct TradeControl {
  void *vftable;
  char pad_04[0x80];
  short bitmapId;

  __inline int QueryValue();
  __inline char IsActionable();
  __inline void SetEnabledSingle(int enabled);
  __inline void SetEnabledPair(int enabled, int unknownFlag);
  __inline void SetStatePair(int enabled, int unknownFlag);
  __inline void SetBitmap(int bitmapIdValue, int unknownFlag);
  __inline void SetBarMetric(int value, int range);
  __inline void SetControlValue(int value, int updateFlag);
  __inline void ApplyStyleDescriptor(void *descriptorBuffer, int modeFlag);
  __inline void SetStyleState(int stateValue, int modeFlag);
  __inline void QueryBounds(int *boundsBuffer);
  __inline void ApplyBounds(int *boundsBuffer, int modeFlag);
  __inline void CaptureLayoutF0(int *buffer, int modeFlag);
  __inline void CaptureLayout(int *buffer, int modeFlag);
  __inline void CaptureLayoutPreset11_14();
  __inline void Refresh();
  __inline void UpdateAfterBitmapChange(int unknownFlag);
};

struct UiRuntimeContext;

struct NationState {
  void *vftable;
  char pad_04[0xa0];
  short tradeCapacity;
};

struct TradeBarControlLayout {
  void *vftable;
  char pad_04[0x30];
  short barRange;
  char pad_36[0x2e];
  short barSteps;
};

struct TradeScreenContext {
  void *vftable;
  char pad_04[0x18];
  int rowStateTag;
  char pad_20[0x68];
  short tradeMetricSlot;

  __inline TradeControl *ResolveControlByTag(int controlTag);
  __inline TradeControl *RequireControlByTag(int controlTag);
  void InitializeTradeSellControlState();
  void QueryTradeSellControlQuantity();
  char IsTradeBidControlActionable();
  char IsTradeOfferControlActionable();
  void SetTradeBidSecondaryBitmapState();
  void SetTradeBidControlBitmapState();
  void SetTradeOfferControlBitmapState();
  void SetTradeOfferSecondaryBitmapState();
  void UpdateTradeSellControlAndBarFromNationMetric();
};

struct UiRuntimeContext {
  void *vftable;
};

class TradeControlVirtualShape {
public:
  char pad_00[0x80];
  short bitmapId;

  virtual void CtrlSlot00(void) = 0;
  virtual void CtrlSlot01(void) = 0;
  virtual void CtrlSlot02(void) = 0;
  virtual void CtrlSlot03(void) = 0;
  virtual void CtrlSlot04(void) = 0;
  virtual void CtrlSlot05(void) = 0;
  virtual void CtrlSlot06(void) = 0;
  virtual void CtrlSlot07(void) = 0;
  virtual void CtrlSlot08(void) = 0;
  virtual void CtrlSlot09(void) = 0;
  virtual void CtrlSlot10(void) = 0;
  virtual void CtrlSlot11(void) = 0;
  virtual void CtrlSlot12(void) = 0;
  virtual void CtrlSlot13(void) = 0;
  virtual void CtrlSlot14(void) = 0;
  virtual void CtrlSlot15(void) = 0;
  virtual void CtrlSlot16(void) = 0;
  virtual void CtrlSlot17(void) = 0;
  virtual void CtrlSlot18(void) = 0;
  virtual void CtrlSlot19(void) = 0;
  virtual void CtrlSlot20(void) = 0;
  virtual void CtrlSlot21(void) = 0;
  virtual void CtrlSlot22(void) = 0;
  virtual void CtrlSlot23(void) = 0;
  virtual void CtrlSlot24(void) = 0;
  virtual void CtrlSlot25(void) = 0;
  virtual void CtrlSlot26(void) = 0;
  virtual void CtrlSlot27(void) = 0;
  virtual void CtrlSlot28(void) = 0;
  virtual void CtrlSlot29(void) = 0;
  virtual void CtrlSlot30(void) = 0;
  virtual void CtrlSlot31(void) = 0;
  virtual void CtrlSlot32(void) = 0;
  virtual void CtrlSlot33(void) = 0;
  virtual void CtrlSlot34(void) = 0;
  virtual void CtrlSlot35(void) = 0;
  virtual void CtrlSlot36(void) = 0;
  virtual void CtrlSlot37(void) = 0;
  virtual void CtrlSlot38(void) = 0;
  virtual void CtrlSlot39(void) = 0;
  virtual void CtrlSlot40(void) = 0;
  virtual void SetEnabledSlotA4(int enabled, int unknownFlag) = 0;
  virtual void SetStateSlotA8(int enabled, int unknownFlag) = 0;
  virtual void CtrlSlot43(void) = 0;
  virtual void CtrlSlot44(void) = 0;
  virtual void CtrlSlot45(void) = 0;
  virtual void CtrlSlot46(void) = 0;
  virtual void CtrlSlot47(void) = 0;
  virtual void CtrlSlot48(void) = 0;
  virtual void CtrlSlot49(void) = 0;
  virtual void CtrlSlot50(void) = 0;
  virtual void CtrlSlot51(void) = 0;
  virtual void CtrlSlot52(void) = 0;
  virtual void CtrlSlot53(void) = 0;
  virtual void CtrlSlot54(void) = 0;
  virtual void CtrlSlot55(void) = 0;
  virtual void CtrlSlot56(void) = 0;
  virtual void CtrlSlot57(void) = 0;
  virtual void CtrlSlot58(void) = 0;
  virtual char IsActionableSlotEC(void) = 0;
  virtual void CaptureLayoutSlotF0(int *buffer, int modeFlag) = 0;
  virtual void CaptureLayoutSlotF4(int *buffer, int modeFlag) = 0;
  virtual void RefreshSlotF8(void) = 0;
  virtual void CtrlSlot63(void) = 0;
  virtual void CtrlSlot64(void) = 0;
  virtual void CtrlSlot65(void) = 0;
  virtual void CtrlSlot66(void) = 0;
  virtual void CtrlSlot67(void) = 0;
  virtual void CtrlSlot68(void) = 0;
  virtual void UpdateAfterBitmapChangeSlot114(int unknownFlag) = 0;
  virtual void CtrlSlot70(void) = 0;
  virtual void CtrlSlot71(void) = 0;
  virtual void CtrlSlot72(void) = 0;
  virtual void CtrlSlot73(void) = 0;
  virtual void CtrlSlot74(void) = 0;
  virtual void QueryBoundsSlot12C(int *boundsBuffer) = 0;
  virtual void CtrlSlot76(void) = 0;
  virtual void CtrlSlot77(void) = 0;
  virtual void CtrlSlot78(void) = 0;
  virtual void CtrlSlot79(void) = 0;
  virtual void CtrlSlot80(void) = 0;
  virtual void CtrlSlot81(void) = 0;
  virtual void CtrlSlot82(void) = 0;
  virtual void CtrlSlot83(void) = 0;
  virtual void CtrlSlot84(void) = 0;
  virtual void CtrlSlot85(void) = 0;
  virtual void CtrlSlot86(void) = 0;
  virtual void CtrlSlot87(void) = 0;
  virtual void CtrlSlot88(void) = 0;
  virtual void CtrlSlot89(void) = 0;
  virtual void ApplyBoundsSlot168(int *boundsBuffer, int modeFlag) = 0;
  virtual void CtrlSlot91(void) = 0;
  virtual void CtrlSlot92(void) = 0;
  virtual void CtrlSlot93(void) = 0;
  virtual void CtrlSlot94(void) = 0;
  virtual void CtrlSlot95(void) = 0;
  virtual void CtrlSlot96(void) = 0;
  virtual void CtrlSlot97(void) = 0;
  virtual void CtrlSlot98(void) = 0;
  virtual void CtrlSlot99(void) = 0;
  virtual void CtrlSlot100(void) = 0;
  virtual void CtrlSlot101(void) = 0;
  virtual void CtrlSlot102(void) = 0;
  virtual void CtrlSlot103(void) = 0;
  virtual void CtrlSlot104(void) = 0;
  virtual void SetBarMetricSlot1A4(int value, int range) = 0;
  virtual void CtrlSlot106(void) = 0;
  virtual void CtrlSlot107(void) = 0;
  virtual void CtrlSlot108(void) = 0;
  virtual void ApplyStyleDescriptorSlot1B4(void *descriptorBuffer, int modeFlag) = 0;
  virtual void CtrlSlot110(void) = 0;
  virtual void CtrlSlot111(void) = 0;
  virtual void CtrlSlot112(void) = 0;
  virtual void SetStyleStateSlot1C4(int stateValue, int modeFlag) = 0;
  virtual void SetBitmapSlot1C8(int bitmapIdValue, int unknownFlag) = 0;
  virtual void CtrlSlot115(void) = 0;
  virtual void CtrlSlot116(void) = 0;
  virtual void CtrlSlot117(void) = 0;
  virtual void CtrlSlot118(void) = 0;
  virtual void CtrlSlot119(void) = 0;
  virtual void CtrlSlot120(void) = 0;
  virtual void SetControlValueSlot1E4(int value, int updateFlag) = 0;
  virtual int QueryValueSlot1E8(void) = 0;
};

class TradeScreenVirtualShape {
public:
  virtual void CtxSlot00(void) = 0;
  virtual void CtxSlot01(void) = 0;
  virtual void CtxSlot02(void) = 0;
  virtual void CtxSlot03(void) = 0;
  virtual void CtxSlot04(void) = 0;
  virtual void CtxSlot05(void) = 0;
  virtual void CtxSlot06(void) = 0;
  virtual void CtxSlot07(void) = 0;
  virtual void CtxSlot08(void) = 0;
  virtual void CtxSlot09(void) = 0;
  virtual void CtxSlot10(void) = 0;
  virtual void CtxSlot11(void) = 0;
  virtual void CtxSlot12(void) = 0;
  virtual void CtxSlot13(void) = 0;
  virtual void CtxSlot14(void) = 0;
  virtual void CtxSlot15(void) = 0;
  virtual void CtxSlot16(void) = 0;
  virtual void CtxSlot17(void) = 0;
  virtual void CtxSlot18(void) = 0;
  virtual void CtxSlot19(void) = 0;
  virtual void CtxSlot20(void) = 0;
  virtual void CtxSlot21(void) = 0;
  virtual void CtxSlot22(void) = 0;
  virtual void CtxSlot23(void) = 0;
  virtual void CtxSlot24(void) = 0;
  virtual void CtxSlot25(void) = 0;
  virtual void CtxSlot26(void) = 0;
  virtual void CtxSlot27(void) = 0;
  virtual void CtxSlot28(void) = 0;
  virtual void CtxSlot29(void) = 0;
  virtual void CtxSlot30(void) = 0;
  virtual void CtxSlot31(void) = 0;
  virtual void CtxSlot32(void) = 0;
  virtual void CtxSlot33(void) = 0;
  virtual void CtxSlot34(void) = 0;
  virtual void CtxSlot35(void) = 0;
  virtual void CtxSlot36(void) = 0;
  virtual TradeControlVirtualShape *ResolveControlByTagSlot94(int controlTag) = 0;
};

class UiRuntimeVirtualShape {
public:
  virtual void RuntimeSlot00(void) = 0;
  virtual void RuntimeSlot01(void) = 0;
  virtual void RuntimeSlot02(void) = 0;
  virtual void RuntimeSlot03(void) = 0;
  virtual void RuntimeSlot04(void) = 0;
  virtual void RuntimeSlot05(void) = 0;
  virtual void RuntimeSlot06(void) = 0;
  virtual void RuntimeSlot07(void) = 0;
  virtual void RuntimeSlot08(void) = 0;
  virtual void RuntimeSlot09(void) = 0;
  virtual void RuntimeSlot10(void) = 0;
  virtual void RuntimeSlot11(void) = 0;
  virtual void RuntimeSlot12(void) = 0;
  virtual void RuntimeSlot13(void) = 0;
  virtual void RuntimeSlot14(void) = 0;
  virtual void RuntimeSlot15(void) = 0;
  virtual void RuntimeSlot16(void) = 0;
  virtual void RuntimeSlot17(void) = 0;
  virtual void RuntimeSlot18(void) = 0;
  virtual void RuntimeSlot19(void) = 0;
  virtual void RuntimeSlot20(void) = 0;
  virtual short QueryUiScreenModeSlot54(void) = 0;
};

class NationStateVirtualShape {
public:
  virtual void Slot00(void) = 0;
  virtual void Slot01(void) = 0;
  virtual void Slot02(void) = 0;
  virtual void Slot03(void) = 0;
  virtual void Slot04(void) = 0;
  virtual void Slot05(void) = 0;
  virtual void Slot06(void) = 0;
  virtual void Slot07(void) = 0;
  virtual void Slot08(void) = 0;
  virtual void Slot09(void) = 0;
  virtual void Slot10(void) = 0;
  virtual void Slot11(void) = 0;
  virtual void Slot12(void) = 0;
  virtual void Slot13(void) = 0;
  virtual void Slot14(void) = 0;
  virtual void Slot15(void) = 0;
  virtual void Slot16(void) = 0;
  virtual void Slot17(void) = 0;
  virtual void Slot18(void) = 0;
  virtual void Slot19(void) = 0;
  virtual void Slot20(void) = 0;
  virtual void Slot21(void) = 0;
  virtual void Slot22(void) = 0;
  virtual void Slot23(void) = 0;
  virtual void Slot24(void) = 0;
  virtual void Slot25(void) = 0;
  virtual void Slot26(void) = 0;
  virtual void Slot27(void) = 0;
  virtual void Slot28(void) = 0;
  virtual void Slot29(void) = 0;
  virtual short QueryMetricBySlot78(short metricSlot) = 0;
};

static __inline TradeControlVirtualShape *AsTradeControlVirtualShape(TradeControl *control)
{
  return reinterpret_cast<TradeControlVirtualShape *>(control);
}

static __inline TradeScreenVirtualShape *AsTradeScreenVirtualShape(TradeScreenContext *context)
{
  return reinterpret_cast<TradeScreenVirtualShape *>(context);
}

static __inline UiRuntimeVirtualShape *AsUiRuntimeVirtualShape(UiRuntimeContext *runtimeContext)
{
  return reinterpret_cast<UiRuntimeVirtualShape *>(runtimeContext);
}

static __inline NationStateVirtualShape *AsNationStateVirtualShape(NationState *nationState)
{
  return reinterpret_cast<NationStateVirtualShape *>(nationState);
}

__inline int TradeControl::QueryValue()
{
  return AsTradeControlVirtualShape(this)->QueryValueSlot1E8();
}

__inline char TradeControl::IsActionable()
{
  return AsTradeControlVirtualShape(this)->IsActionableSlotEC();
}

__inline void TradeControl::SetEnabledSingle(int enabled)
{
  AsTradeControlVirtualShape(this)->SetEnabledSlotA4(enabled, 1);
}

__inline void TradeControl::SetEnabledPair(int enabled, int unknownFlag)
{
  AsTradeControlVirtualShape(this)->SetEnabledSlotA4(enabled, unknownFlag);
}

__inline void TradeControl::SetStatePair(int enabled, int unknownFlag)
{
  AsTradeControlVirtualShape(this)->SetStateSlotA8(enabled, unknownFlag);
}

__inline void TradeControl::SetBitmap(int bitmapIdValue, int unknownFlag)
{
  AsTradeControlVirtualShape(this)->SetBitmapSlot1C8(bitmapIdValue, unknownFlag);
}

__inline void TradeControl::SetBarMetric(int value, int range)
{
  AsTradeControlVirtualShape(this)->SetBarMetricSlot1A4(value, range);
}

__inline void TradeControl::SetControlValue(int value, int updateFlag)
{
  AsTradeControlVirtualShape(this)->SetControlValueSlot1E4(value, updateFlag);
}

__inline void TradeControl::ApplyStyleDescriptor(void *descriptorBuffer, int modeFlag)
{
  AsTradeControlVirtualShape(this)->ApplyStyleDescriptorSlot1B4(descriptorBuffer, modeFlag);
}

__inline void TradeControl::SetStyleState(int stateValue, int modeFlag)
{
  AsTradeControlVirtualShape(this)->SetStyleStateSlot1C4(stateValue, modeFlag);
}

__inline void TradeControl::QueryBounds(int *boundsBuffer)
{
  AsTradeControlVirtualShape(this)->QueryBoundsSlot12C(boundsBuffer);
}

__inline void TradeControl::ApplyBounds(int *boundsBuffer, int modeFlag)
{
  AsTradeControlVirtualShape(this)->ApplyBoundsSlot168(boundsBuffer, modeFlag);
}

__inline void TradeControl::CaptureLayoutF0(int *buffer, int modeFlag)
{
  AsTradeControlVirtualShape(this)->CaptureLayoutSlotF0(buffer, modeFlag);
}

__inline void TradeControl::CaptureLayout(int *buffer, int modeFlag)
{
  AsTradeControlVirtualShape(this)->CaptureLayoutSlotF4(buffer, modeFlag);
}

__inline void TradeControl::CaptureLayoutPreset11_14()
{
  int layoutCapture[2] = {0x11, 0x14};
  CaptureLayout(layoutCapture, 1);
}

__inline void TradeControl::Refresh()
{
  AsTradeControlVirtualShape(this)->RefreshSlotF8();
}

__inline void TradeControl::UpdateAfterBitmapChange(int unknownFlag)
{
  AsTradeControlVirtualShape(this)->UpdateAfterBitmapChangeSlot114(unknownFlag);
}

__inline TradeControl *TradeScreenContext::ResolveControlByTag(int controlTag)
{
  return reinterpret_cast<TradeControl *>(
      AsTradeScreenVirtualShape(this)->ResolveControlByTagSlot94(controlTag));
}

__inline TradeControl *TradeScreenContext::RequireControlByTag(int controlTag)
{
  TradeControl *control = ResolveControlByTag(controlTag);
  if (control == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return 0;
  }
  return control;
}

static __inline void FailNilPointerInUSmallViews(int line)
{
  MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
  ((void(__cdecl *)(const char *, int))TemporarilyClearAndRestoreUiInvalidationFlag)(
      kUSmallViewsCppPath, line);
}

static __inline short QueryUiScreenMode(UiRuntimeContext *runtimeContext)
{
  if (runtimeContext == 0 || runtimeContext->vftable == 0) {
    return 4;
  }
  return AsUiRuntimeVirtualShape(runtimeContext)->QueryUiScreenModeSlot54();
}

static __inline short QueryUiScreenModeRaw(UiRuntimeContext *runtimeContext)
{
  return AsUiRuntimeVirtualShape(runtimeContext)->QueryUiScreenModeSlot54();
}

static __inline short QueryActiveNationId(void)
{
  return (short)thunk_GetActiveNationId();
}

static __inline NationState *GetNationStateBySlot(short slotId)
{
  NationState **ppNationStates = reinterpret_cast<NationState **>(kAddrGlobalNationStates);
  return ppNationStates[slotId];
}

static __inline short QueryNationMetricBySlot(NationState *nationState, short metricSlot)
{
  return AsNationStateVirtualShape(nationState)->QueryMetricBySlot78(metricSlot);
}

static __inline short QueryNationTradeCapacity(NationState *nationState)
{
  return nationState->tradeCapacity;
}

UiRuntimeContext *g_pUiRuntimeContext = 0;

}  // namespace

// GHIDRA_NAME InitializeTradeSellControlState
// GHIDRA_PROTO void __cdecl InitializeTradeSellControlState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context; then initializes move/bar controls baseline.
// GHIDRA_COMMENT_END
/* Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context;
   then initializes move/bar controls baseline. */

// FUNCTION: IMPERIALISM 0x00587130
void TradeScreenContext::InitializeTradeSellControlState(void)
{
  TradeControl *sellControl = ResolveControlByTag(kControlTagSell);
  if (sellControl != 0) {
    int styleDescriptor[5] = {0, 0, 0, 0, 0};
    int boundsBuffer[2] = {0, 0};
    sellControl->ApplyStyleDescriptor(styleDescriptor, 0);
    sellControl->SetStyleState(-1, 0);
    sellControl->QueryBounds(boundsBuffer);
    boundsBuffer[1] = boundsBuffer[1] - 2;
    sellControl->ApplyBounds(boundsBuffer, 1);
    sellControl->SetStatePair(-1, 0);
  }

  TradeControl *barControl = ResolveControlByTag(kControlTagBar);
  if (barControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineInitBar);
  }
  barControl->SetStatePair(0, 0);

  TradeControl *leftControl = ResolveControlByTag(kControlTagLeft);
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineInitLeft);
  }
  TradeControl *rightControl = ResolveControlByTag(kControlTagRght);
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineInitRight);
  }
  leftControl->SetStatePair(0, 0);
  rightControl->SetStatePair(0, 0);

  short activeNationSlot = QueryActiveNationId();
  NationState *activeNationState = GetNationStateBySlot(activeNationSlot);
  if (activeNationState != 0 && QueryNationTradeCapacity(activeNationState) == 0) {
    leftControl->SetEnabledPair(0, 0);
    rightControl->SetEnabledPair(0, 0);
    barControl->SetEnabledPair(0, 0);
    TradeControl *greenControl = RequireControlByTag(kControlTagGree);
    if (greenControl != 0) {
      greenControl->SetEnabledPair(0, 0);
    }
  }

  InitializeTradeMoveAndBarControls();
}

// GHIDRA_NAME IsTradeSellControlAtMinimum
// GHIDRA_PROTO void __cdecl IsTradeSellControlAtMinimum(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Returns early if UI mode is outside trade range (>3). Otherwise queries current Sell control quantity.
// GHIDRA_COMMENT_END
//
// NOTE:
// GHIDRA showed `g_pUiRuntimeContext` as a global here; this reconstruction passes it explicitly.
//

// FUNCTION: IMPERIALISM 0x00587900
void __cdecl IsTradeSellControlAtMinimum(TradeScreenContext *context, UiRuntimeContext *runtimeContext)
{
  if (QueryUiScreenMode(runtimeContext) > 3) {
    return;
  }
  TradeControl *sellControl = context->RequireControlByTag(kControlTagSell);
  if (sellControl == 0) {
    return;
  }
  sellControl->QueryValue();
}

// GHIDRA_NAME QueryTradeSellControlQuantity
// GHIDRA_PROTO void __cdecl QueryTradeSellControlQuantity(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Returns current Sell control quantity via child control tag "Sell" and vfunc +0x1E8.
// GHIDRA_COMMENT_END
/* Returns current Sell control quantity via child control tag "Sell" and vfunc +0x1E8. */

// FUNCTION: IMPERIALISM 0x00587950
void TradeScreenContext::QueryTradeSellControlQuantity(void)
{
  TradeControl *sellControl = RequireControlByTag(kControlTagSell);
  if (sellControl == 0) {
    return;
  }
  sellControl->QueryValue();
}

// GHIDRA_NAME IsTradeBidControlActionable
// GHIDRA_PROTO void __cdecl IsTradeBidControlActionable(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Trade UI predicate for Bid control interactivity.
// GHIDRA_COMMENT Looks up control tag 'card' and returns true when control bitmap is 2111 (0x83F) or 2125 (0x84D) and control reports actionable state via vtable+0xEC.
// GHIDRA_COMMENT_END

/* Trade UI predicate for Bid control interactivity.
   Looks up control tag 'card' and returns true when control bitmap is 2111 (0x83F) or 2125 (0x84D)
   and control reports actionable state via vtable+0xEC. */

// FUNCTION: IMPERIALISM 0x00587980
char TradeScreenContext::IsTradeBidControlActionable(void)
{
  TradeScreenVirtualShape *screen = reinterpret_cast<TradeScreenVirtualShape *>(this);
  TradeControlVirtualShape *bidControl = screen->ResolveControlByTagSlot94(kControlTagCard);
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
// GHIDRA_COMMENT Looks up control tag 'offr' and returns true when control bitmap is 2113 (0x841) or 2127 (0x84F) and control reports actionable state via vtable+0xEC.
// GHIDRA_COMMENT_END

/* Trade UI predicate for Offer control interactivity.
   Looks up control tag 'offr' and returns true when control bitmap is 2113 (0x841) or 2127 (0x84F)
   and control reports actionable state via vtable+0xEC. */



// FUNCTION: IMPERIALISM 0x00587A10
char TradeScreenContext::IsTradeOfferControlActionable(void)
{
  TradeScreenVirtualShape *screen = reinterpret_cast<TradeScreenVirtualShape *>(this);
  TradeControlVirtualShape *offerControl = screen->ResolveControlByTagSlot94(kControlTagOffr);
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
// GHIDRA_COMMENT Resolves 'card' control and assigns 2112 (0x840) or 2126 (0x84E) through vtable+0x1C8 based on row state field (+0x1C == 0x67643020) when nation availability gate passes.
// GHIDRA_COMMENT_END

/* Trade UI Bid secondary-state updater.
   Resolves 'card' control and assigns 2112 (0x840) or 2126 (0x84E) through vtable+0x1C8 based on
   row state field (+0x1C == 0x67643020) when nation availability gate passes. */

// NOTE:
// GHIDRA showed `g_pUiRuntimeContext` as a global here; this reconstruction passes it explicitly.
//
// FUNCTION: IMPERIALISM 0x00587AA0
void TradeScreenContext::SetTradeBidSecondaryBitmapState(void)
{
  TradeScreenVirtualShape *screen = reinterpret_cast<TradeScreenVirtualShape *>(this);
  TradeControl *bidControl = reinterpret_cast<TradeControl *>(screen->ResolveControlByTagSlot94(kControlTagCard));
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
// GHIDRA_COMMENT If row state field (+0x1C) equals 0x67643020, assigns bitmap 2125 (0x84D); otherwise assigns bitmap 2111 (0x83F).
// GHIDRA_COMMENT Then refreshes related controls 'gree', 'left', 'rght' visibility/active flags.
// GHIDRA_COMMENT_END

/* Trade UI Bid-state updater.
   Resolves control tag 'card' from current row context.
   If row state field (+0x1C) equals 0x67643020, assigns bitmap 2125 (0x84D); otherwise assigns
   bitmap 2111 (0x83F).
   Then refreshes related controls 'gree', 'left', 'rght' visibility/active flags. */

// FUNCTION: IMPERIALISM 0x00587BB0
void TradeScreenContext::SetTradeBidControlBitmapState(void)
{
  TradeControl *bidControl = ResolveControlByTag(kControlTagCard);
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

  TradeControl *greenControl = ResolveControlByTag(kControlTagGree);
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidGree);
  }
  TradeControl *leftControl = ResolveControlByTag(kControlTagLeft);
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidLeft);
  }
  TradeControl *rightControl = ResolveControlByTag(kControlTagRght);
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
// GHIDRA_COMMENT If row state field (+0x1C) equals 0x67643020, assigns bitmap 2127 (0x84F); otherwise assigns bitmap 2113 (0x841).
// GHIDRA_COMMENT Then refreshes related controls 'gree', 'left', 'rght' visibility/active flags.
// GHIDRA_COMMENT_END

/* Trade UI Offer-state updater.
   Resolves control tag 'offr' from current row context.
   If row state field (+0x1C) equals 0x67643020, assigns bitmap 2127 (0x84F); otherwise assigns
   bitmap 2113 (0x841).
   Then refreshes related controls 'gree', 'left', 'rght' visibility/active flags. */

// FUNCTION: IMPERIALISM 0x00587DD0
void TradeScreenContext::SetTradeOfferControlBitmapState(void)
{
  TradeControl *offerControl = ResolveControlByTag(kControlTagOffr);
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

  TradeControl *greenControl = ResolveControlByTag(kControlTagGree);
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferGree);
  }
  TradeControl *leftControl = ResolveControlByTag(kControlTagLeft);
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferLeft);
  }
  TradeControl *rightControl = ResolveControlByTag(kControlTagRght);
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
// GHIDRA_COMMENT Resolves 'offr' control and assigns 2114 (0x842) or 2128 (0x850) through vtable+0x1C8 based on row state field (+0x1C == 0x67643020) when nation availability gate passes.
// GHIDRA_COMMENT_END

/* Trade UI Offer secondary-state updater.
   Resolves 'offr' control and assigns 2114 (0x842) or 2128 (0x850) through vtable+0x1C8 based on
   row state field (+0x1C == 0x67643020) when nation availability gate passes. */

// FUNCTION: IMPERIALISM 0x00588030
void TradeScreenContext::SetTradeOfferSecondaryBitmapState(void)
{
  TradeControl *offerControl = RequireControlByTag(kControlTagOffr);
  if (offerControl == 0) {
    return;
  }

  int layoutCaptureF4[2] = {0x11, 0x14};
  offerControl->CaptureLayout(layoutCaptureF4, 1);

  short tradeMetricAvailable = 0;
  short activeNationSlot = QueryActiveNationId();
  NationState *activeNationState = GetNationStateBySlot(activeNationSlot);
  if (activeNationState != 0) {
    tradeMetricAvailable = QueryNationMetricBySlot(activeNationState, tradeMetricSlot);
  }

  if (tradeMetricAvailable != 0) {
    short activeNationSlotAgain = QueryActiveNationId();
    NationState *activeNationStateAgain = GetNationStateBySlot(activeNationSlotAgain);
    if (activeNationStateAgain != 0 && QueryNationTradeCapacity(activeNationStateAgain) != 0) {
      offerControl->SetEnabledPair(1, 0);
      if (rowStateTag == kTradeRowStateTag_67643020) {
        offerControl->SetBitmap(kTradeBitmapOfferSecondaryStateB, 0);
      } else {
        offerControl->SetBitmap(kTradeBitmapOfferSecondaryStateA, 0);
      }
      int layoutCaptureF0[2] = {0xa3, 1};
      offerControl->CaptureLayoutF0(layoutCaptureF0, 1);
    } else {
      offerControl->SetEnabledPair(0, 1);
    }
  } else {
    offerControl->SetEnabledPair(0, 1);
  }

  TradeControl *greenControl = RequireControlByTag(kControlTagGree);
  TradeControl *leftControl = RequireControlByTag(kControlTagLeft);
  TradeControl *rightControl = RequireControlByTag(kControlTagRght);

  if (greenControl != 0) {
    greenControl->SetEnabledPair(0, 1);
    greenControl->SetStatePair(0, 1);
  }
  if (leftControl != 0) {
    leftControl->SetEnabledPair(0, 1);
    leftControl->SetStatePair(0, 1);
  }
  if (rightControl != 0) {
    rightControl->SetEnabledPair(0, 1);
    rightControl->SetStatePair(0, 1);
  }

  offerControl->Refresh();
  offerControl->UpdateAfterBitmapChange(0);
}

// GHIDRA_NAME UpdateTradeSellControlAndBarFromNationMetric
// GHIDRA_PROTO void __fastcall UpdateTradeSellControlAndBarFromNationMetric(int * this)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Updates Sell control quantity
// GHIDRA_COMMENT_END
/* Updates Sell control quantity */

// FUNCTION: IMPERIALISM 0x005882F0
void TradeScreenContext::UpdateTradeSellControlAndBarFromNationMetric(void)
{
  short activeNationSlot = QueryActiveNationId();
  NationState *activeNationState = GetNationStateBySlot(activeNationSlot);
  short tradeMetricValue = 0;
  if (activeNationState != 0) {
    tradeMetricValue = QueryNationMetricBySlot(activeNationState, tradeMetricSlot);
  }
  short clampedTradeMetricValue = tradeMetricValue;
  if (clampedTradeMetricValue > tradeMetricSlot) {
    clampedTradeMetricValue = tradeMetricSlot;
  }

  TradeControl *sellControl = ResolveControlByTag(kControlTagSell);
  if (sellControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateSell);
  }
  sellControl->SetControlValue(clampedTradeMetricValue, 1);

  TradeControl *barControl = ResolveControlByTag(kControlTagBar);
  if (barControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateBar);
  }
  TradeControl *greenControl = ResolveControlByTag(kControlTagGree);
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateGree);
  }

  TradeBarControlLayout *barLayout = reinterpret_cast<TradeBarControlLayout *>(barControl);
  short barRange = barLayout->barRange;
  if (clampedTradeMetricValue != 0) {
    short barSteps = barLayout->barSteps;
    float barScale = 9999.0f;
    if (barSteps != 0) {
      barScale = (float)barRange / (float)barSteps;
    }
    int scaledMetricValue = (int)((float)clampedTradeMetricValue * barScale);
    barControl->SetBarMetric(scaledMetricValue, barRange);
    return;
  }

  barControl->SetBarMetric(0, barRange);
  greenControl->SetEnabledPair(0, 1);
}

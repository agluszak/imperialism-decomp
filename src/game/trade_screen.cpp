// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#include "decomp_types.h"

typedef void *hwnd_t;
extern "C" int __stdcall MessageBoxA(hwnd_t hWnd, const char *text, const char *caption, unsigned int type);
undefined4 TemporarilyClearAndRestoreUiInvalidationFlag(void);
unsigned int __cdecl thunk_GetActiveNationId(void);
undefined4 InitializeTradeMoveAndBarControls(void);
undefined4 thunk_InitializeTradeMoveAndBarControls(void);
undefined4 thunk_NoOpUiLifecycleHook(void);
undefined4 thunk_GetCityBuildingProductionValueBySlot(void);
undefined4 HandleTradeMoveControlAdjustment(void);
undefined4 thunk_HandleTradeMoveControlAdjustment(void);
undefined4 thunk_HandleCityDialogToggleCommandOrForward(void);
undefined4 thunk_HandleCursorHoverSelectionByChildHitTestAndFallback(void);
undefined4 ActivateFirstIdleTacticalUnitByCategoryAtTile(void);
undefined4 ActivateFirstActiveTacticalUnitByCategoryAtTile(void);
int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 ConstructTUberClusterBaseState(void);
undefined4 thunk_ConstructUiResourceEntryBase(void);
undefined4 thunk_ConstructUiResourceEntryType4B0C0(void);
undefined4 thunk_ConstructUiClickablePictureResourceEntry(void);
undefined4 thunk_ConstructUiCommandTagResourceEntryBase(void);
undefined4 thunk_ConstructPictureResourceEntryBase(void);
undefined4 thunk_DestructEngineerDialogBaseState(void);
undefined4 thunk_DestructCityDialogSharedBaseState(void);

















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
const int kControlTagMove = 0x6d6f7665;
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
const int kAssertLineUpdateSell = 0x9e0;
const int kAssertLineUpdateBar = 0x9e4;
const int kAssertLineUpdateGree = 0x9e7;
const int kAssertLineRatioB = 0xb73;
const int kAssertLineRatioA = 0xd1d;
const int kAssertLineMovePageMinus = 0xd34;
const int kAssertLineMovePagePlus = 0xd3c;
const unsigned int kVtableTIndustryCluster = 0x00665ed0;
const unsigned int kAddrClassDescTIndustryCluster = 0x00662f98;
const unsigned int kVtableTIndustryAmtBar = 0x00666110;
const unsigned int kAddrClassDescTIndustryAmtBar = 0x00662fb0;
const unsigned int kVtableTRailCluster = 0x00666318;
const unsigned int kAddrClassDescTRailCluster = 0x00662fc8;
const unsigned int kVtableTRailAmtBar = 0x00666558;
const unsigned int kAddrClassDescTRailAmtBar = 0x00662fe0;
const unsigned int kVtableTShipyardCluster = 0x00666760;
const unsigned int kAddrClassDescTShipyardCluster = 0x00662ff8;
const unsigned int kAddrTradeSummarySelectionMap = 0x006960e0;

// Symbol placeholders to preserve OFFSET-style codegen in ctor/dtor wrappers.
char g_vtblTShipAmtBar;
char g_pClassDescTShipAmtBar;
char g_vtblTTraderAmtBar;
char g_pClassDescTTraderAmtBar;

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
  char pad_04[0x18];
  int controlTag;
  char pad_20[0x64];
  short bitmapId;

  __inline int QueryValue();
  __inline short QueryStepValue();
  __inline char IsActionable();
  __inline void SetEnabledSingle(int enabled);
  __inline void SetEnabledPair(int enabled, int unknownFlag);
  __inline void SetStatePair(int enabled, int unknownFlag);
  __inline void SetBitmap(int bitmapIdValue, int unknownFlag);
  __inline void SetBarMetric(int value, int range);
  __inline void SetBarMetricRatio(int value);
  __inline int ApplyMoveClamp(int baseValue, int requestedValue);
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
  __inline void InvokeSlotE4();
  __inline void InvokeSlot1CC(int value, int modeFlag);
  __inline void InvokeSlot13C();
  __inline void InvokeSlot1A8();
};

struct UiRuntimeContext;
struct NationCityTradeState;
struct TradeMovePanelContext;
struct TradeCommodityMetricRecord;
struct CityTradeScenarioDescriptor;

struct NationState {
  void *vftable;
  char pad_04[0xa0];
  short tradeCapacity;
  char pad_a6[0x7ee];
  NationCityTradeState *cityState;
};

struct TradeBarControlLayout {
  void *vftable;
  char pad_04[0x30];
  short barRange;
  char pad_36[0x2e];
  short barSteps;
};

struct TradeAmountBarLayout {
  void *vftable;
  char pad_04[0x5c];
  short rangeOrMaxValue;
  short stepOrCurrentValue;
  short auxValueA;
  short auxValueB;
};

struct TradeMoveStepCluster {
  void *vftable;
  char pad_04[0x84];
  int field_88;
  short field_8c;
  short field_8e;

  void HandleTradeMovePageStepCommand(int commandId, void *eventArg, int eventExtra);
  void SelectTradeSpecialCommodityAndInitializeControls();
  void HandleTradeMoveArrowControlEvent(int commandId, TradeControl *sourceControl, int eventExtra);
};

struct IndustryAmtBarState {
  void *vftable;
  char pad_04[0x1c];
  TradeMovePanelContext *ownerPanelContext;
  char pad_24[0x10];
  int barRangeRaw;
  char pad_38[0x28];
  short cachedRangeAt60;
  short cachedRatioAt62;
  short cachedProductionAt64;
  short cachedStyleAt66;
  TradeCommodityMetricRecord *selectedMetricRecord;

  IndustryAmtBarState *ConstructTRailAmtBarBaseState();
  IndustryAmtBarState *DestructTRailAmtBarAndMaybeFree(unsigned char freeSelfFlag);
  void SelectTradeSummaryMetricByTagAndUpdateBarValues();
  IndustryAmtBarState *ConstructTShipAmtBarBaseState();
  IndustryAmtBarState *DestructTShipAmtBarAndMaybeFree(unsigned char freeSelfFlag);
  void SelectTradeSpecialCommodityAndRecomputeBarLimits(int passthroughArg);
};

struct TradeCommodityMetricRecord {
  void *vftable;
  short controlValue;
  char pad_06[0x4c];
  short buildingSlot;

  __inline short QueryStepValue();
};

struct NationCityTradeState {
  char pad_00[0xe4];
  TradeCommodityMetricRecord *tradeCommodityRecordPtrs[32];
  char pad_164[0x2c];
  TradeCommodityMetricRecord *specialCommodityRecordAt190;
  char pad_194[0x44];
  CityTradeScenarioDescriptor *scenarioTradeDescriptor;
};

struct CityTradeProductionSlots {
  char pad_00[4];
  short valueAt4;
  short valueAt6;
  short valueAt8;
};

struct CityTradeScenarioDescriptor {
  char pad_00[0x10];
  CityTradeProductionSlots *productionSlots;
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
  void UpdateTradeSellControlAndBarFromNationMetric(int metricClampMax);
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
  virtual short QueryStepValueSlot30(void) = 0;
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
  virtual int ApplyMoveClampSlot1A0(int baseValue, int requestedValue) = 0;
  virtual void SetBarMetricSlot1A4(int value, int range) = 0;
  virtual void CtrlSlot106(void) = 0;
  virtual void SetBarMetricRatioSlot1AC(int value) = 0;
  virtual void CtrlSlot108(void) = 0;
  virtual void ApplyStyleDescriptorSlot1B4(void *descriptorBuffer, int modeFlag) = 0;
  virtual void CtrlSlot110(void) = 0;
  virtual void CtrlSlot111(void) = 0;
  virtual void CtrlSlot112(void) = 0;
  virtual void SetStyleStateSlot1C4(int stateValue, int modeFlag) = 0;
  virtual void SetBitmapSlot1C8(int bitmapIdValue, int unknownFlag) = 0;
  virtual void InvokeSlot1CC(int value, int modeFlag) = 0;
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

#define TRADE_OWNER_SLOT_DECL(n) virtual void OwnerSlot##n(void) = 0;
class TradeOwnerVirtualShape : public TradeScreenVirtualShape {
public:
  TRADE_OWNER_SLOT_DECL(38)
  TRADE_OWNER_SLOT_DECL(39)
  TRADE_OWNER_SLOT_DECL(40)
  TRADE_OWNER_SLOT_DECL(41)
  TRADE_OWNER_SLOT_DECL(42)
  TRADE_OWNER_SLOT_DECL(43)
  TRADE_OWNER_SLOT_DECL(44)
  TRADE_OWNER_SLOT_DECL(45)
  TRADE_OWNER_SLOT_DECL(46)
  TRADE_OWNER_SLOT_DECL(47)
  TRADE_OWNER_SLOT_DECL(48)
  TRADE_OWNER_SLOT_DECL(49)
  TRADE_OWNER_SLOT_DECL(50)
  TRADE_OWNER_SLOT_DECL(51)
  TRADE_OWNER_SLOT_DECL(52)
  TRADE_OWNER_SLOT_DECL(53)
  TRADE_OWNER_SLOT_DECL(54)
  TRADE_OWNER_SLOT_DECL(55)
  TRADE_OWNER_SLOT_DECL(56)
  TRADE_OWNER_SLOT_DECL(57)
  TRADE_OWNER_SLOT_DECL(58)
  TRADE_OWNER_SLOT_DECL(59)
  TRADE_OWNER_SLOT_DECL(60)
  TRADE_OWNER_SLOT_DECL(61)
  TRADE_OWNER_SLOT_DECL(62)
  TRADE_OWNER_SLOT_DECL(63)
  TRADE_OWNER_SLOT_DECL(64)
  TRADE_OWNER_SLOT_DECL(65)
  TRADE_OWNER_SLOT_DECL(66)
  TRADE_OWNER_SLOT_DECL(67)
  TRADE_OWNER_SLOT_DECL(68)
  TRADE_OWNER_SLOT_DECL(69)
  TRADE_OWNER_SLOT_DECL(70)
  TRADE_OWNER_SLOT_DECL(71)
  TRADE_OWNER_SLOT_DECL(72)
  TRADE_OWNER_SLOT_DECL(73)
  TRADE_OWNER_SLOT_DECL(74)
  TRADE_OWNER_SLOT_DECL(75)
  TRADE_OWNER_SLOT_DECL(76)
  TRADE_OWNER_SLOT_DECL(77)
  TRADE_OWNER_SLOT_DECL(78)
  TRADE_OWNER_SLOT_DECL(79)
  TRADE_OWNER_SLOT_DECL(80)
  TRADE_OWNER_SLOT_DECL(81)
  TRADE_OWNER_SLOT_DECL(82)
  TRADE_OWNER_SLOT_DECL(83)
  TRADE_OWNER_SLOT_DECL(84)
  TRADE_OWNER_SLOT_DECL(85)
  TRADE_OWNER_SLOT_DECL(86)
  TRADE_OWNER_SLOT_DECL(87)
  TRADE_OWNER_SLOT_DECL(88)
  TRADE_OWNER_SLOT_DECL(89)
  TRADE_OWNER_SLOT_DECL(90)
  TRADE_OWNER_SLOT_DECL(91)
  TRADE_OWNER_SLOT_DECL(92)
  TRADE_OWNER_SLOT_DECL(93)
  TRADE_OWNER_SLOT_DECL(94)
  TRADE_OWNER_SLOT_DECL(95)
  TRADE_OWNER_SLOT_DECL(96)
  TRADE_OWNER_SLOT_DECL(97)
  TRADE_OWNER_SLOT_DECL(98)
  TRADE_OWNER_SLOT_DECL(99)
  TRADE_OWNER_SLOT_DECL(100)
  TRADE_OWNER_SLOT_DECL(101)
  TRADE_OWNER_SLOT_DECL(102)
  TRADE_OWNER_SLOT_DECL(103)
  TRADE_OWNER_SLOT_DECL(104)
  TRADE_OWNER_SLOT_DECL(105)
  TRADE_OWNER_SLOT_DECL(106)
  TRADE_OWNER_SLOT_DECL(107)
  TRADE_OWNER_SLOT_DECL(108)
  TRADE_OWNER_SLOT_DECL(109)
  TRADE_OWNER_SLOT_DECL(110)
  TRADE_OWNER_SLOT_DECL(111)
  TRADE_OWNER_SLOT_DECL(112)
  TRADE_OWNER_SLOT_DECL(113)
  TRADE_OWNER_SLOT_DECL(114)
  TRADE_OWNER_SLOT_DECL(115)
  virtual void ApplyMoveValueSlot1D0(int value) = 0;
  virtual void PostMoveValueSlot1D4(int value, int commitFlag) = 0;
  virtual void NotifyMoveUpdatedSlot1D8(void) = 0;
};
#undef TRADE_OWNER_SLOT_DECL

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

static __inline TradeOwnerVirtualShape *AsTradeOwnerVirtualShape(void *context)
{
  return reinterpret_cast<TradeOwnerVirtualShape *>(context);
}

static __inline UiRuntimeVirtualShape *AsUiRuntimeVirtualShape(UiRuntimeContext *runtimeContext)
{
  return reinterpret_cast<UiRuntimeVirtualShape *>(runtimeContext);
}

static __inline NationStateVirtualShape *AsNationStateVirtualShape(NationState *nationState)
{
  return reinterpret_cast<NationStateVirtualShape *>(nationState);
}

class TradeScreenRuntimeBridge {
public:
  static __inline void ConstructTUberClusterBaseState(TradeMoveStepCluster *self)
  {
    reinterpret_cast<void (__fastcall *)(TradeMoveStepCluster *)>(
        ::ConstructTUberClusterBaseState)(self);
  }

  static __inline void ConstructUiResourceEntryBase(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(::thunk_ConstructUiResourceEntryBase)(self);
  }

  static __inline void ConstructUiResourceEntryType4B0C0(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(::thunk_ConstructUiResourceEntryType4B0C0)(self);
  }

  static __inline void ConstructUiClickablePictureResourceEntry(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(
        ::thunk_ConstructUiClickablePictureResourceEntry)(self);
  }

  static __inline void ConstructUiCommandTagResourceEntryBase(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(
        ::thunk_ConstructUiCommandTagResourceEntryBase)(self);
  }

  static __inline void ConstructPictureResourceEntryBase(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(::thunk_ConstructPictureResourceEntryBase)(self);
  }

  static __inline void InitializeTradeMoveAndBarControls(TradeMovePanelContext *self)
  {
    reinterpret_cast<void (__fastcall *)(TradeMovePanelContext *)>(
        ::thunk_InitializeTradeMoveAndBarControls)(self);
  }

  static __inline int GetCityBuildingProductionValueBySlot(NationCityTradeState *cityState, short slot)
  {
    return (int)reinterpret_cast<undefined4 (__fastcall *)(NationCityTradeState *, short)>(
        ::thunk_GetCityBuildingProductionValueBySlot)(cityState, slot);
  }

  static __inline void DestructCityDialogSharedBaseState(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(::thunk_DestructCityDialogSharedBaseState)(self);
  }
};

static __inline void FailNilPointerInUSmallViews(int line);

struct TradeMoveControlState {
  void *vftable;
  char pad_04[0x1c];
  void *ownerContext;
  char pad_24[0x10];
  int barRangeRaw;
  char pad_38[0x2c];
  short barStepsRaw;

  void ClampAndApplyTradeMoveValue(int *requestedValuePtr);
};

struct TradeMovePanelContext {
  void *vftable;
  char pad_04[0x18];
  int summaryTag;
  void *ownerContext;
  int ownerOffsetX;
  int ownerOffsetY;
  char pad_2c[0x5c];
  TradeControl *selectedMetricControl;
  short selectedMetricValue;
  short selectedMetricStep;

  void OrphanCallChain_C1_I06_00588c30(int value);
  void UpdateTradeBarFromSelectedMetricRatio_B(void);
  void HandleTradeMoveStepCommand(int commandId);
  void OrphanCallChain_C1_I06_005899c0(int value);
  void UpdateTradeMoveControlsFromScaledDrag(int dragValue, int updateFlag);
  void UpdateTradeBarFromSelectedMetricRatio_A(void);
};

__inline int TradeControl::QueryValue()
{
  return AsTradeControlVirtualShape(this)->QueryValueSlot1E8();
}

__inline short TradeControl::QueryStepValue()
{
  return AsTradeControlVirtualShape(this)->QueryStepValueSlot30();
}

__inline short TradeCommodityMetricRecord::QueryStepValue()
{
  return reinterpret_cast<TradeControlVirtualShape *>(this)->QueryStepValueSlot30();
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

__inline void TradeControl::SetBarMetricRatio(int value)
{
  AsTradeControlVirtualShape(this)->SetBarMetricRatioSlot1AC(value);
}

__inline int TradeControl::ApplyMoveClamp(int baseValue, int requestedValue)
{
  return AsTradeControlVirtualShape(this)->ApplyMoveClampSlot1A0(baseValue, requestedValue);
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

__inline void TradeControl::InvokeSlotE4()
{
  AsTradeControlVirtualShape(this)->CtrlSlot57();
}

__inline void TradeControl::InvokeSlot1CC(int value, int modeFlag)
{
  AsTradeControlVirtualShape(this)->InvokeSlot1CC(value, modeFlag);
}

__inline void TradeControl::InvokeSlot13C()
{
  AsTradeControlVirtualShape(this)->CtrlSlot79();
}

__inline void TradeControl::InvokeSlot1A8()
{
  AsTradeControlVirtualShape(this)->CtrlSlot106();
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

static __inline NationCityTradeState *GetNationCityStateBySlot(short slotId)
{
  NationState *nationState = GetNationStateBySlot(slotId);
  if (nationState == 0) {
    return 0;
  }
  return nationState->cityState;
}

static __inline int GetTradeSummarySelectionTagByIndex(short index)
{
  TradeSummarySelectionMap *selectionMap =
      reinterpret_cast<TradeSummarySelectionMap *>(kAddrTradeSummarySelectionMap);
  return selectionMap->summaryTags[index];
}

static __inline short QueryNationMetricBySlot(NationState *nationState, short metricSlot)
{
  return AsNationStateVirtualShape(nationState)->QueryMetricBySlot78(metricSlot);
}

static __inline short QueryNationTradeCapacity(NationState *nationState)
{
  return nationState->tradeCapacity;
}

static __inline TradeControl *ResolveOwnerControl(TradeOwnerVirtualShape *owner, int controlTag)
{
  return reinterpret_cast<TradeControl *>(owner->ResolveControlByTagSlot94(controlTag));
}

UiRuntimeContext *g_pUiRuntimeContext = 0;

}  // namespace

#include "trade_screen_parts/part_1.cpp"
#include "trade_screen_parts/part_2.cpp"

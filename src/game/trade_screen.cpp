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
int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 ConstructTUberClusterBaseState(void);
undefined4 thunk_ConstructUiResourceEntryBase(void);
undefined4 thunk_ConstructUiClickablePictureResourceEntry(void);
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
char g_vtblTCivilianButton;
char g_pClassDescTCivilianButton;
char g_vtblTHQButton;
char g_pClassDescTHQButton;
char g_vtblTPlacard;
char g_pClassDescTPlacard;
char g_vtblTArmyPlacard;
char g_pClassDescTArmyPlacard;

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

struct CivilianButtonState {
  void *vftable;
  char pad_04[0x5c];
  int buttonTag;
};

struct HQButtonState {
  void *vftable;
  char pad_04[0x98];
};

struct PlacardState {
  void *vftable;
  char pad_04[0x8c];
  short placardValue;
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

  static __inline void ConstructUiClickablePictureResourceEntry(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(
        ::thunk_ConstructUiClickablePictureResourceEntry)(self);
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
  TradeScreenVirtualShape *screen = AsTradeScreenVirtualShape(this);
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
  TradeScreenVirtualShape *screen = AsTradeScreenVirtualShape(this);
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
  TradeControl *bidControl = ResolveControlByTag(kControlTagCard);
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
  TradeControl *offerControl = ResolveControlByTag(kControlTagOffr);
  if (offerControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryOffr);
  }

  int layoutCaptureF4[2] = {0x11, 0x14};
  offerControl->CaptureLayout(layoutCaptureF4, 1);

  short activeNationSlot = QueryActiveNationId();
  NationState *activeNationState = GetNationStateBySlot(activeNationSlot);
  short tradeMetricAvailable = QueryNationMetricBySlot(activeNationState, tradeMetricSlot);

  if (tradeMetricAvailable != 0) {
    short activeNationSlotAgain = QueryActiveNationId();
    NationState *activeNationStateAgain = GetNationStateBySlot(activeNationSlotAgain);
    if (QueryNationTradeCapacity(activeNationStateAgain) != 0) {
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

  TradeControl *greenControl = ResolveControlByTag(kControlTagGree);
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryGree);
  }
  TradeControl *leftControl = ResolveControlByTag(kControlTagLeft);
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryLeft);
  }
  TradeControl *rightControl = ResolveControlByTag(kControlTagRght);
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryRight);
  }

  greenControl->SetEnabledPair(0, 1);
  greenControl->SetStatePair(0, 1);
  leftControl->SetEnabledPair(0, 1);
  leftControl->SetStatePair(0, 1);
  rightControl->SetEnabledPair(0, 1);
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









// FUNCTION: IMPERIALISM 0x005882F0
void TradeScreenContext::UpdateTradeSellControlAndBarFromNationMetric(int metricClampMax)
{
  short activeNationSlot = QueryActiveNationId();
  NationState *activeNationState = GetNationStateBySlot(activeNationSlot);
  int tradeMetricValue = (int)QueryNationMetricBySlot(activeNationState, tradeMetricSlot);
  if (tradeMetricValue > metricClampMax) {
    tradeMetricValue = metricClampMax;
  }

  TradeControl *sellControl = ResolveControlByTag(kControlTagSell);
  if (sellControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateSell);
  }
  if (sellControl != 0) {
    sellControl->SetControlValue(tradeMetricValue, 1);
  }

  TradeControl *barControl = ResolveControlByTag(kControlTagBar);
  if (barControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateBar);
  }
  TradeControl *greenControl = ResolveControlByTag(kControlTagGree);
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateGree);
  }

  if (barControl != 0) {
    TradeBarControlLayout *barLayout = reinterpret_cast<TradeBarControlLayout *>(barControl);
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
// GHIDRA_COMMENT [WrapperShape] small wrapper around thunk_NoOpUiLifecycleHook; instructions=4, call_insns=1, internal_calls=1, unique_internal=1
// GHIDRA_COMMENT_END
/* [WrapperShape] small wrapper around thunk_NoOpUiLifecycleHook; instructions=4, call_insns=1,
   internal_calls=1, unique_internal=1 */









// FUNCTION: IMPERIALISM 0x00588610
void __stdcall WrapperFor_thunk_NoOpUiLifecycleHook_At00588610(int passthroughArg)
{
  ((void(__cdecl *)(int))thunk_NoOpUiLifecycleHook)(passthroughArg);
}

// GHIDRA_NAME OrphanCallChain_C2_I15_00588630
// GHIDRA_PROTO undefined OrphanCallChain_C2_I15_00588630()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [OrphanCallChain] no incoming code refs; calls=2; instructions=15
// GHIDRA_COMMENT_END
/* [OrphanCallChain] no incoming code refs; calls=2; instructions=15 */









// FUNCTION: IMPERIALISM 0x00588630
void __fastcall OrphanCallChain_C2_I15_00588630(
    TradeControl *control, int unusedEdx, short valueAt60, short valueAt62)
{
  (void)unusedEdx;
  TradeAmountBarLayout *amountBar = reinterpret_cast<TradeAmountBarLayout *>(control);
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
void __fastcall OrphanCallChain_C1_I03_00588670(
    TradeControl *control, int unusedEdx, int unusedStackArg)
{
  (void)unusedEdx;
  (void)unusedStackArg;
  control->InvokeSlot1A8();
}

// GHIDRA_NAME TIndustryCluster::CreateTradeMoveStepControlPanel
// GHIDRA_PROTO undefined CreateTradeMoveStepControlPanel()









// FUNCTION: IMPERIALISM 0x00588950
void TradeMoveControlState::ClampAndApplyTradeMoveValue(int *requestedValuePtr)
{
  int requestedValue = *requestedValuePtr;
  int baseValue = 0;
  if (barStepsRaw < 1 ||
      (barRangeRaw / ((int)barStepsRaw << 1) <= *requestedValuePtr)) {
    baseValue = requestedValue;
  }

  TradeControl *moveControl = reinterpret_cast<TradeControl *>(this);
  int appliedValue = moveControl->ApplyMoveClamp(baseValue, (short)requestedValue);
  TradeOwnerVirtualShape *owner = AsTradeOwnerVirtualShape(ownerContext);
  if (((short)appliedValue == 0) && requestedValue != 0) {
    TradeControl *fallbackControl =
        ResolveOwnerControl(owner, kControlTagMove);
    if (fallbackControl == 0) {
      fallbackControl = ResolveOwnerControl(owner, kControlTagSell);
    }
    if (fallbackControl != 0 && fallbackControl->QueryValue() == 0) {
      appliedValue = 1;
    }
  }

  owner->ApplyMoveValueSlot1D0(appliedValue);
}

// GHIDRA_NAME OrphanCallChain_C1_I06_00588c30
// GHIDRA_PROTO undefined OrphanCallChain_C1_I06_00588c30()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [OrphanCallChain] no incoming code refs; calls=1; instructions=6
// GHIDRA_COMMENT_END
/* [OrphanCallChain] no incoming code refs; calls=1; instructions=6 */









// FUNCTION: IMPERIALISM 0x00588A30
TradeMoveStepCluster *__cdecl CreateTradeMoveStepControlPanel(void)
{
  TradeMoveStepCluster *cluster = reinterpret_cast<TradeMoveStepCluster *>(
      AllocateWithFallbackHandler(0x90));
  if (cluster != 0) {
    TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
    cluster->vftable = reinterpret_cast<void *>(kVtableTIndustryCluster);
    cluster->field_88 = 0;
  }
  return cluster;
}

// GHIDRA_NAME TIndustryCluster::GetTIndustryClusterClassNamePointer
// GHIDRA_PROTO void * __cdecl GetTIndustryClusterClassNamePointer(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Returns class descriptor pointer for TIndustryCluster.
// GHIDRA_COMMENT_END
/* Returns class descriptor pointer for TIndustryCluster. */









// FUNCTION: IMPERIALISM 0x00588AD0
void *__cdecl GetTIndustryClusterClassNamePointer(void)
{
  return reinterpret_cast<void *>(kAddrClassDescTIndustryCluster);
}

// GHIDRA_NAME ConstructTradeMoveStepControlPanel
// GHIDRA_PROTO void __cdecl ConstructTradeMoveStepControlPanel(void)









// FUNCTION: IMPERIALISM 0x00588AF0
void __fastcall ConstructTradeMoveStepControlPanel(TradeMoveStepCluster *cluster)
{
  TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
  cluster->vftable = reinterpret_cast<void *>(kVtableTIndustryCluster);
  cluster->field_88 = 0;
}

// GHIDRA_NAME TIndustryCluster::DestructTIndustryClusterMaybeFree
// GHIDRA_PROTO void __cdecl DestructTIndustryClusterMaybeFree(void)









// FUNCTION: IMPERIALISM 0x00588B20
void __fastcall DestructTIndustryClusterMaybeFree(
    TradeMoveStepCluster *cluster, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)cluster);
  }
}

// GHIDRA_NAME ClampAndApplyTradeMoveValue
// GHIDRA_PROTO void __cdecl ClampAndApplyTradeMoveValue(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Clamps requested move value and applies through control vfunc +0x1A0; enforces nonzero fallback when move/sell controls are both at zero edge case.
// GHIDRA_COMMENT_END
/* Clamps requested move value and applies through control vfunc +0x1A0; enforces nonzero fallback
   when move/sell controls are both at zero edge case. */








// FUNCTION: IMPERIALISM 0x00588B70
void __fastcall SyncTradeCommoditySelectionWithActiveNationAndInitControls(
    TradeMovePanelContext *context, int unusedEdx)
{
  (void)unusedEdx;
  short tagIndex = 0;
  NationCityTradeState *cityState = GetNationCityStateBySlot(QueryActiveNationId());
  int currentSummaryTag = context->summaryTag;
  int mappedSummaryTag = GetTradeSummarySelectionTagByIndex(tagIndex);
  while (mappedSummaryTag != currentSummaryTag) {
    tagIndex = (short)(tagIndex + 1);
    mappedSummaryTag = GetTradeSummarySelectionTagByIndex(tagIndex);
  }

  TradeCommodityMetricRecord *selectedMetricRecord = 0;
  if (cityState != 0) {
    selectedMetricRecord = cityState->tradeCommodityRecordPtrs[tagIndex];
  }
  context->selectedMetricControl = reinterpret_cast<TradeControl *>(selectedMetricRecord);
  if (selectedMetricRecord != 0) {
    context->selectedMetricValue = (short)TradeScreenRuntimeBridge::GetCityBuildingProductionValueBySlot(
        cityState, selectedMetricRecord->buildingSlot);
  } else {
    context->selectedMetricValue = 0;
  }

  TradeScreenRuntimeBridge::InitializeTradeMoveAndBarControls(context);

  short selectedControlValue = 0;
  if (selectedMetricRecord != 0) {
    selectedControlValue = selectedMetricRecord->controlValue;
  }
  TradeOwnerVirtualShape *owner =
      AsTradeOwnerVirtualShape(context->ownerContext != 0 ? context->ownerContext : context);
  owner->PostMoveValueSlot1D4(selectedControlValue, 1);
}









// FUNCTION: IMPERIALISM 0x00588C30
void TradeMovePanelContext::OrphanCallChain_C1_I06_00588c30(int value)
{
  AsTradeOwnerVirtualShape(this)->PostMoveValueSlot1D4(value, 0);
}

static __inline void UpdateTradeBarFromSelectedMetricRatio(
    TradeMovePanelContext *context, int assertLine)
{
  TradeOwnerVirtualShape *owner = AsTradeOwnerVirtualShape(context);
  TradeControl *barControl =
      ResolveOwnerControl(owner, kControlTagBar);
  if (barControl == 0) {
    FailNilPointerInUSmallViews(assertLine);
  }

  TradeMoveControlState *barLayout = reinterpret_cast<TradeMoveControlState *>(barControl);
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








// FUNCTION: IMPERIALISM 0x00588C60
void __fastcall UpdateTradeMoveControlsFromDrag(
    TradeMovePanelContext *context, int unusedEdx, int dragValue, int updateFlag)
{
  (void)unusedEdx;
  TradeControl *selectedControl = context->selectedMetricControl;
  int previousValue = 0;
  if (selectedControl != 0) {
    previousValue = selectedControl->QueryValue();
    selectedControl->SetControlValue(dragValue, 0);
  }

  if (((char)updateFlag == 0) &&
      (selectedControl != 0) &&
      (selectedControl->QueryStepValue() == (short)previousValue)) {
    return;
  }

  TradeOwnerVirtualShape *owner =
      AsTradeOwnerVirtualShape(context->ownerContext != 0 ? context->ownerContext : context);

  TradeControl *moveControl =
      ResolveOwnerControl(owner, kControlTagMove);
  if (moveControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return;
  }
  if (selectedControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return;
  }

  moveControl->SetControlValue(selectedControl->QueryStepValue(), 0);

  TradeControl *barControl =
      ResolveOwnerControl(owner, kControlTagBar);
  if (barControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return;
  }

  TradeMoveControlState *barLayout = reinterpret_cast<TradeMoveControlState *>(barControl);
  TradeAmountBarLayout *barAmount = reinterpret_cast<TradeAmountBarLayout *>(barControl);
  float barScale = 9999.0f;
  if (barLayout->barStepsRaw != 0) {
    barScale = (float)barLayout->barRangeRaw / (float)barLayout->barStepsRaw;
  }

  if (selectedControl->QueryStepValue() == context->selectedMetricValue) {
    barAmount->auxValueB = 0x34;
  } else {
    barAmount->auxValueB = 0x3a;
  }

  int scaledMetric = (int)((float)selectedControl->QueryValue() * barScale);
  int scaledRange = (int)((float)selectedControl->QueryStepValue() * barScale);
  barControl->SetBarMetric(scaledMetric, scaledRange);
  owner->NotifyMoveUpdatedSlot1D8();
}









// FUNCTION: IMPERIALISM 0x00588F60
void TradeMovePanelContext::UpdateTradeBarFromSelectedMetricRatio_B(void)
{
  UpdateTradeBarFromSelectedMetricRatio(this, kAssertLineRatioB);
}

// GHIDRA_NAME TAmtBar::HandleTradeMoveStepCommand
// GHIDRA_PROTO void __thiscall HandleTradeMoveStepCommand(void)









// FUNCTION: IMPERIALISM 0x00588FF0
void TradeMovePanelContext::HandleTradeMoveStepCommand(int commandId)
{
  TradeOwnerVirtualShape *owner = AsTradeOwnerVirtualShape(this);
  if (commandId == 100) {
    TradeControl *moveControl =
        ResolveOwnerControl(owner, kControlTagMove);
    if (moveControl == 0) {
      MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    }
    int moveValue = moveControl->QueryValue();
    owner->ApplyMoveValueSlot1D0(moveValue + 1);
    return;
  }
  if (commandId != 0x65) {
    HandleTradeMoveControlAdjustment();
    return;
  }

  TradeControl *moveControl =
      ResolveOwnerControl(owner, kControlTagMove);
  if (moveControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
  }
  int moveValue = moveControl->QueryValue();
  if (commandId == 0x65) {
    owner->ApplyMoveValueSlot1D0(moveValue - 1);
  }
}

// GHIDRA_NAME OrphanCallChain_C1_I06_005899c0
// GHIDRA_PROTO undefined OrphanCallChain_C1_I06_005899c0()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [OrphanCallChain] no incoming code refs; calls=1; instructions=6
// GHIDRA_COMMENT_END
/* [OrphanCallChain] no incoming code refs; calls=1; instructions=6 */








// FUNCTION: IMPERIALISM 0x00589110
TradeAmountBarLayout *__cdecl CreateTIndustryAmtBarInstance(void)
{
  TradeAmountBarLayout *amountBar = reinterpret_cast<TradeAmountBarLayout *>(
      AllocateWithFallbackHandler(0x6c));
  if (amountBar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
    amountBar->vftable = reinterpret_cast<void *>(kVtableTIndustryAmtBar);
    amountBar->rangeOrMaxValue = 0;
    amountBar->stepOrCurrentValue = 0;
    amountBar->auxValueA = 0;
    amountBar->auxValueB = 0;
  }
  return amountBar;
}








// FUNCTION: IMPERIALISM 0x005891B0
void *__cdecl GetTIndustryAmtBarClassNamePointer(void)
{
  return reinterpret_cast<void *>(kAddrClassDescTIndustryAmtBar);
}








// FUNCTION: IMPERIALISM 0x005891D0
TradeAmountBarLayout *__fastcall ConstructTIndustryAmtBarBaseState(TradeAmountBarLayout *amountBar)
{
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
  amountBar->vftable = reinterpret_cast<void *>(kVtableTIndustryAmtBar);
  amountBar->rangeOrMaxValue = 0;
  amountBar->stepOrCurrentValue = 0;
  amountBar->auxValueA = 0;
  amountBar->auxValueB = 0;
  return amountBar;
}








// FUNCTION: IMPERIALISM 0x00589210
TradeAmountBarLayout *__fastcall DestructTIndustryAmtBarAndMaybeFree(
    TradeAmountBarLayout *amountBar, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)amountBar);
  }
  return amountBar;
}







// FUNCTION: IMPERIALISM 0x00589260
void __fastcall InitializeTradeBarsFromSelectedCommodityControl(IndustryAmtBarState *amountBar)
{
  NationCityTradeState *cityState = GetNationCityStateBySlot(QueryActiveNationId());
  short summaryTagIndex = 0;
  int mappedTag = GetTradeSummarySelectionTagByIndex(summaryTagIndex);
  while (mappedTag != amountBar->ownerPanelContext->summaryTag) {
    summaryTagIndex = (short)(summaryTagIndex + 1);
    mappedTag = GetTradeSummarySelectionTagByIndex(summaryTagIndex);
  }

  amountBar->selectedMetricRecord = cityState->tradeCommodityRecordPtrs[summaryTagIndex];
  int productionValue = TradeScreenRuntimeBridge::GetCityBuildingProductionValueBySlot(
      cityState, amountBar->selectedMetricRecord->buildingSlot);
  amountBar->cachedProductionAt64 = (short)productionValue;

  short stepValue = amountBar->selectedMetricRecord->QueryStepValue();
  amountBar->cachedRatioAt62 = (short)((stepValue * amountBar->barRangeRaw) / amountBar->cachedProductionAt64);

  amountBar->cachedStyleAt66 = 0x3a;
  amountBar->cachedRangeAt60 = (short)(
      (amountBar->selectedMetricRecord->controlValue * amountBar->barRangeRaw) /
      amountBar->cachedProductionAt64);

  thunk_NoOpUiLifecycleHook();
}






// FUNCTION: IMPERIALISM 0x00589660
TradeMoveStepCluster *__cdecl CreateTradeMoveScaledControlPanel(void)
{
  TradeMoveStepCluster *cluster = reinterpret_cast<TradeMoveStepCluster *>(
      AllocateWithFallbackHandler(0x90));
  if (cluster != 0) {
    TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
    cluster->vftable = reinterpret_cast<void *>(kVtableTRailCluster);
    cluster->field_88 = 0;
    cluster->field_8e = 0;
  }
  return cluster;
}








// FUNCTION: IMPERIALISM 0x00589700
void *__cdecl GetTRailClusterClassNamePointer(void)
{
  return reinterpret_cast<void *>(kAddrClassDescTRailCluster);
}








// FUNCTION: IMPERIALISM 0x00589720
void __fastcall ConstructTradeMoveScaledControlPanel(TradeMoveStepCluster *cluster)
{
  TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
  cluster->vftable = reinterpret_cast<void *>(kVtableTRailCluster);
  cluster->field_88 = 0;
  cluster->field_8e = 0;
}








// FUNCTION: IMPERIALISM 0x00589760
void __fastcall DestructTRailClusterMaybeFree(
    TradeMoveStepCluster *cluster, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)cluster);
  }
}






// FUNCTION: IMPERIALISM 0x005897B0
void __fastcall SelectTradeCommodityPresetBySummaryTagAndInitControls(
    TradeMovePanelContext *context, int unusedEdx)
{
  (void)unusedEdx;
  NationCityTradeState *cityState = GetNationCityStateBySlot(QueryActiveNationId());
  CityTradeScenarioDescriptor *scenario =
      cityState != 0 ? cityState->scenarioTradeDescriptor : 0;

  short recordIndex = 0;
  context->selectedMetricStep = 0;
  context->selectedMetricValue = 0;

  if (context->summaryTag == kSummaryTagPopu) {
    recordIndex = 0x3c;
    context->selectedMetricStep = 1;
    if (cityState != 0) {
      context->selectedMetricValue = (short)TradeScreenRuntimeBridge::GetCityBuildingProductionValueBySlot(
          cityState, 0x0f);
    }
  } else if (context->summaryTag == kSummaryTagFood) {
    recordIndex = 7;
    context->selectedMetricStep = 2;
    if (scenario != 0 && scenario->productionSlots != 0) {
      CityTradeProductionSlots *slots = scenario->productionSlots;
      context->selectedMetricValue = (short)(
          ((slots->valueAt8 * 2 + slots->valueAt6) * 2 + scenario->extraAt1E + slots->valueAt4) / 2);
    }
  } else if (context->summaryTag == kSummaryTagProf) {
    recordIndex = 0x18;
    context->selectedMetricStep = 1;
    if (scenario != 0 && scenario->productionSlots != 0) {
      context->selectedMetricValue = scenario->productionSlots->valueAt6;
    }
  } else if (context->summaryTag == kSummaryTagPowe) {
    recordIndex = 0x34;
    context->selectedMetricStep = 6;
    context->selectedMetricValue = 999;
  } else if (context->summaryTag == kSummaryTagRail) {
    recordIndex = 0x33;
    context->selectedMetricStep = 1;
    if (scenario != 0 && scenario->productionSlots != 0) {
      CityTradeProductionSlots *slots = scenario->productionSlots;
      context->selectedMetricValue = (short)(
          ((slots->valueAt8 * 2 + slots->valueAt6) * 2 + slots->valueAt4 + scenario->extraAt1E) / 2);
    }
  } else if (context->summaryTag == kSummaryTagIart) {
    recordIndex = 0x17;
    context->selectedMetricStep = 1;
    if (scenario != 0 && scenario->productionSlots != 0) {
      context->selectedMetricValue = scenario->productionSlots->valueAt4;
    }
  }

  TradeCommodityMetricRecord *metricRecord = 0;
  if (cityState != 0) {
    metricRecord = cityState->tradeCommodityRecordPtrs[recordIndex];
  }
  context->selectedMetricControl = reinterpret_cast<TradeControl *>(metricRecord);

  TradeScreenRuntimeBridge::InitializeTradeMoveAndBarControls(context);

  short selectedControlValue = metricRecord != 0 ? metricRecord->controlValue : 0;
  TradeOwnerVirtualShape *owner =
      AsTradeOwnerVirtualShape(context->ownerContext != 0 ? context->ownerContext : context);
  owner->PostMoveValueSlot1D4(selectedControlValue, 1);
}









// FUNCTION: IMPERIALISM 0x005899C0
void TradeMovePanelContext::OrphanCallChain_C1_I06_005899c0(int value)
{
  AsTradeOwnerVirtualShape(this)->PostMoveValueSlot1D4(value, 0);
}

// GHIDRA_NAME UpdateTradeBarFromSelectedMetricRatio_A
// GHIDRA_PROTO void __fastcall UpdateTradeBarFromSelectedMetricRatio_A(int * this)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Computes bar position from selected metric ratio and applies it to bar control.
// GHIDRA_COMMENT_END
/* Computes bar position from selected metric ratio and applies it to bar control. */






// FUNCTION: IMPERIALISM 0x005899F0
void TradeMovePanelContext::UpdateTradeMoveControlsFromScaledDrag(int dragValue, int updateFlag)
{
  short step = selectedMetricStep;
  int quantizedDragValue = dragValue;
  if (step != 0) {
    quantizedDragValue = (((int)step / 2 + (int)(short)dragValue) / (int)step) * (int)step;
  }

  TradeControl *selectedControl = selectedMetricControl;
  int previousValue = 0;
  if (selectedControl != 0) {
    previousValue = selectedControl->QueryValue();
    selectedControl->SetControlValue(quantizedDragValue, 0);
  }

  if (((char)updateFlag == 0) &&
      (selectedControl != 0) &&
      (selectedControl->QueryStepValue() == (short)previousValue)) {
    return;
  }

  TradeOwnerVirtualShape *owner =
      AsTradeOwnerVirtualShape(ownerContext != 0 ? ownerContext : this);

  TradeControl *moveControl =
      ResolveOwnerControl(owner, kControlTagMove);
  if (moveControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return;
  }
  if (selectedControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return;
  }

  moveControl->SetControlValue(selectedControl->QueryStepValue(), 0);

  TradeControl *barControl =
      ResolveOwnerControl(owner, kControlTagBar);
  if (barControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return;
  }

  TradeMoveControlState *barLayout = reinterpret_cast<TradeMoveControlState *>(barControl);
  TradeAmountBarLayout *barAmount = reinterpret_cast<TradeAmountBarLayout *>(barControl);
  float barScale = 9999.0f;
  if (barLayout->barStepsRaw != 0) {
    barScale = (float)barLayout->barRangeRaw / (float)barLayout->barStepsRaw;
  }

  if (selectedControl->QueryStepValue() == selectedMetricValue) {
    barAmount->auxValueB = 0x34;
  } else {
    barAmount->auxValueB = 0x3a;
  }

  int scaledMetric = (int)((float)selectedControl->QueryValue() * barScale);
  int scaledRange = (int)((float)selectedControl->QueryStepValue() * barScale);
  barControl->SetBarMetric(scaledMetric, scaledRange);
  owner->NotifyMoveUpdatedSlot1D8();
}









// FUNCTION: IMPERIALISM 0x00589D10
void TradeMovePanelContext::UpdateTradeBarFromSelectedMetricRatio_A(void)
{
  UpdateTradeBarFromSelectedMetricRatio(this, kAssertLineRatioA);
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif





// FUNCTION: IMPERIALISM 0x00589DA0
void TradeMoveStepCluster::HandleTradeMovePageStepCommand(
    int commandId, void *eventArg, int eventExtra)
{
  TradeOwnerVirtualShape *owner = AsTradeOwnerVirtualShape(this);

  int relative = commandId - 100;
  if (relative != 0) {
    if (relative == 1) {
      TradeControl *moveControl = ResolveOwnerControl(owner, kControlTagMove);
      if (moveControl == 0) {
        FailNilPointerInUSmallViews(kAssertLineMovePageMinus);
        return;
      }
      short moveValue = (short)moveControl->QueryValue();
      owner->ApplyMoveValueSlot1D0((int)moveValue - (int)field_8e);
      return;
    }
    reinterpret_cast<void (*)(TradeMoveStepCluster *, int, void *, int)>(
        ::thunk_HandleTradeMoveControlAdjustment)(this, commandId, eventArg, eventExtra);
    return;
  }

  TradeControl *moveControl = ResolveOwnerControl(owner, kControlTagMove);
  if (moveControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineMovePagePlus);
    return;
  }
  short moveValue = (short)moveControl->QueryValue();
  owner->ApplyMoveValueSlot1D0((int)field_8e + (int)moveValue);
}





// FUNCTION: IMPERIALISM 0x00589ED0
IndustryAmtBarState *__cdecl CreateTRailAmtBarInstance(void)
{
  IndustryAmtBarState *amountBar = reinterpret_cast<IndustryAmtBarState *>(
      AllocateWithFallbackHandler(0x6c));
  if (amountBar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
    amountBar->vftable = reinterpret_cast<void *>(kVtableTRailAmtBar);
    amountBar->cachedRangeAt60 = 0;
    amountBar->cachedRatioAt62 = 0;
    amountBar->cachedProductionAt64 = 0;
    amountBar->cachedStyleAt66 = 0;
  }
  return amountBar;
}





// FUNCTION: IMPERIALISM 0x00589F70
void *__cdecl GetTRailAmtBarClassNamePointer(void)
{
  return reinterpret_cast<void *>(kAddrClassDescTRailAmtBar);
}





// FUNCTION: IMPERIALISM 0x00589F90
IndustryAmtBarState *IndustryAmtBarState::ConstructTRailAmtBarBaseState()
{
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(this);
  vftable = reinterpret_cast<void *>(kVtableTRailAmtBar);
  cachedRangeAt60 = 0;
  cachedRatioAt62 = 0;
  cachedProductionAt64 = 0;
  cachedStyleAt66 = 0;
  return this;
}





// FUNCTION: IMPERIALISM 0x00589FD0
IndustryAmtBarState *IndustryAmtBarState::DestructTRailAmtBarAndMaybeFree(unsigned char freeSelfFlag)
{
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)this);
  }
  return this;
}





// FUNCTION: IMPERIALISM 0x0058A020
void IndustryAmtBarState::SelectTradeSummaryMetricByTagAndUpdateBarValues()
{
  NationCityTradeState *cityState = GetNationCityStateBySlot(QueryActiveNationId());
  int summaryTag = ownerPanelContext->summaryTag;

  short recordIndex = 0;
  if ((unsigned int)summaryTag < 0x706f7076) {
    if (summaryTag == kSummaryTagPopu) {
      recordIndex = 0x3c;
    } else if (summaryTag == kSummaryTagFood) {
      recordIndex = 7;
    }
  } else if ((unsigned int)summaryTag < 0x70726f67) {
    if (summaryTag == kSummaryTagProf) {
      recordIndex = 0x18;
    } else if (summaryTag == kSummaryTagPowe) {
      recordIndex = 0x34;
    }
  } else if (summaryTag == kSummaryTagRail) {
    recordIndex = 0x33;
  } else if (summaryTag == kSummaryTagIart) {
    recordIndex = 0x17;
  }

  selectedMetricRecord = cityState->tradeCommodityRecordPtrs[recordIndex];

  short productionOrCapValue = 0;
  if (recordIndex == 0x33 || recordIndex == 7) {
    CityTradeScenarioDescriptor *scenario = cityState->scenarioTradeDescriptor;
    CityTradeProductionSlots *slots = scenario->productionSlots;
    productionOrCapValue = (short)(
        ((slots->valueAt8 * 2 + slots->valueAt6) * 2 + scenario->extraAt1E + slots->valueAt4) / 2);
  } else {
    productionOrCapValue = selectedMetricRecord->QueryStepValue();
  }

  if (productionOrCapValue == 0) {
    cachedRatioAt62 = 9999;
  } else {
    short selectedStep = selectedMetricRecord->QueryStepValue();
    cachedRatioAt62 = (short)(((int)selectedStep * barRangeRaw) / (int)productionOrCapValue);
  }
  cachedProductionAt64 = productionOrCapValue;
  if (productionOrCapValue == 0) {
    cachedRangeAt60 = 9999;
  } else {
    cachedRangeAt60 = (short)((barRangeRaw * (int)selectedMetricRecord->controlValue) /
                              (int)productionOrCapValue);
  }
  cachedStyleAt66 = 0x3a;
  thunk_NoOpUiLifecycleHook();
}




// FUNCTION: IMPERIALISM 0x0058A4D0
TradeMoveStepCluster *__cdecl CreateTradeMoveArrowControlPanel(void)
{
  TradeMoveStepCluster *cluster = reinterpret_cast<TradeMoveStepCluster *>(
      AllocateWithFallbackHandler(0x90));
  if (cluster != 0) {
    TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
    cluster->vftable = reinterpret_cast<void *>(kVtableTShipyardCluster);
    cluster->field_88 = 0;
  }
  return cluster;
}




// FUNCTION: IMPERIALISM 0x0058A570
void *__cdecl GetTShipyardClusterClassNamePointer(void)
{
  return reinterpret_cast<void *>(kAddrClassDescTShipyardCluster);
}




// FUNCTION: IMPERIALISM 0x0058A590
TradeMoveStepCluster *__fastcall ConstructTradeMoveArrowControlPanel(TradeMoveStepCluster *cluster)
{
  TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
  cluster->vftable = reinterpret_cast<void *>(kVtableTShipyardCluster);
  cluster->field_88 = 0;
  return cluster;
}




// FUNCTION: IMPERIALISM 0x0058A5C0
void __fastcall DestructTShipyardClusterMaybeFree(
    TradeMoveStepCluster *cluster, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)cluster);
  }
}




// FUNCTION: IMPERIALISM 0x0058A610
void TradeMoveStepCluster::SelectTradeSpecialCommodityAndInitializeControls()
{
  NationCityTradeState *cityState = GetNationCityStateBySlot(QueryActiveNationId());
  field_88 = cityState != 0 ? (int)cityState->specialCommodityRecordAt190 : 0;
  field_8c = 999;
  TradeScreenRuntimeBridge::InitializeTradeMoveAndBarControls(
      reinterpret_cast<TradeMovePanelContext *>(this));
  AsTradeOwnerVirtualShape(this)->ApplyMoveValueSlot1D0(0);
}




// FUNCTION: IMPERIALISM 0x0058A940
void TradeMoveStepCluster::HandleTradeMoveArrowControlEvent(
    int commandId, TradeControl *sourceControl, int eventExtra)
{
  if (commandId != 10) {
    reinterpret_cast<void (*)(TradeMoveStepCluster *, int, TradeControl *, int)>(
        ::thunk_HandleTradeMoveControlAdjustment)(this, commandId, sourceControl, eventExtra);
    return;
  }

  if (sourceControl != 0 && sourceControl->controlTag == kControlTagRght) {
    TradeControl *moveControl = ResolveOwnerControl(AsTradeOwnerVirtualShape(this), kControlTagMove);
    if (moveControl == 0) {
      MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
      return;
    }
    AsTradeOwnerVirtualShape(this)->ApplyMoveValueSlot1D0(moveControl->QueryValue() + 1);
    return;
  }

  if (sourceControl == 0 || sourceControl->controlTag != kControlTagLeft) {
    reinterpret_cast<void (*)(TradeMoveStepCluster *, int, TradeControl *, int)>(
        ::thunk_HandleTradeMoveControlAdjustment)(this, commandId, sourceControl, eventExtra);
    return;
  }

  TradeControl *moveControl = ResolveOwnerControl(AsTradeOwnerVirtualShape(this), kControlTagMove);
  if (moveControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    return;
  }
  int moveValue = moveControl->QueryValue();
  if ((short)moveValue != 0) {
    AsTradeOwnerVirtualShape(this)->ApplyMoveValueSlot1D0(moveValue - 1);
  }
}



// FUNCTION: IMPERIALISM 0x0058AAA0
IndustryAmtBarState *__cdecl CreateTShipAmtBarInstance(void)
{
  IndustryAmtBarState *amountBar = reinterpret_cast<IndustryAmtBarState *>(
      AllocateWithFallbackHandler(0x6c));
  if (amountBar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
    amountBar->vftable = reinterpret_cast<void *>(&g_vtblTShipAmtBar);
    amountBar->cachedRangeAt60 = 0;
    amountBar->cachedRatioAt62 = 0;
    amountBar->cachedProductionAt64 = 0;
    amountBar->cachedStyleAt66 = 0;
  }
  return amountBar;
}



// FUNCTION: IMPERIALISM 0x0058AB40
void *__cdecl GetTShipAmtBarClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTShipAmtBar);
}



// FUNCTION: IMPERIALISM 0x0058AB60
IndustryAmtBarState *IndustryAmtBarState::ConstructTShipAmtBarBaseState()
{
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(this);
  vftable = reinterpret_cast<void *>(&g_vtblTShipAmtBar);
  cachedRangeAt60 = 0;
  cachedRatioAt62 = 0;
  cachedProductionAt64 = 0;
  cachedStyleAt66 = 0;
  return this;
}



// FUNCTION: IMPERIALISM 0x0058ABA0
IndustryAmtBarState *
IndustryAmtBarState::DestructTShipAmtBarAndMaybeFree(unsigned char freeSelfFlag)
{
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)this);
  }
  return this;
}



// FUNCTION: IMPERIALISM 0x0058ABF0
void IndustryAmtBarState::SelectTradeSpecialCommodityAndRecomputeBarLimits(int passthroughArg)
{
  NationState *nationState =
      reinterpret_cast<NationState **>(kAddrGlobalNationStates)[QueryActiveNationId()];
  NationCityTradeState *cityState = nationState != 0 ? nationState->cityState : 0;
  selectedMetricRecord = cityState->specialCommodityRecordAt190;
  short productionCap =
      *(short *)(reinterpret_cast<char *>(cityState->scenarioTradeDescriptor) + 0x1c);
  cachedRatioAt62 = (short)barRangeRaw;
  cachedProductionAt64 = productionCap;
  cachedStyleAt66 = 0x3a;
  cachedRangeAt60 = (short)(0 / (int)productionCap);
  reinterpret_cast<void (__fastcall *)(IndustryAmtBarState *, int)>(::thunk_NoOpUiLifecycleHook)(
      this, passthroughArg);
}


// FUNCTION: IMPERIALISM 0x0058AE30
TradeAmountBarLayout *__cdecl CreateTTraderAmtBarInstance(void)
{
  TradeAmountBarLayout *amountBar = reinterpret_cast<TradeAmountBarLayout *>(
      AllocateWithFallbackHandler(0x68));
  if (amountBar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
    amountBar->vftable = reinterpret_cast<void *>(&g_vtblTTraderAmtBar);
    amountBar->rangeOrMaxValue = 0;
    amountBar->stepOrCurrentValue = 0;
    amountBar->auxValueA = 0;
    amountBar->auxValueB = 0;
  }
  return amountBar;
}


// FUNCTION: IMPERIALISM 0x0058AED0
void *__cdecl GetTTraderAmtBarClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTTraderAmtBar);
}


// FUNCTION: IMPERIALISM 0x0058AEF0
TradeAmountBarLayout *__fastcall ConstructTTraderAmtBar_Vtbl00666ba0(TradeAmountBarLayout *amountBar)
{
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
  amountBar->vftable = reinterpret_cast<void *>(&g_vtblTTraderAmtBar);
  amountBar->rangeOrMaxValue = 0;
  amountBar->stepOrCurrentValue = 0;
  amountBar->auxValueA = 0;
  amountBar->auxValueB = 0;
  return amountBar;
}


// FUNCTION: IMPERIALISM 0x0058AF30
void __fastcall DestructTTraderAmtBarMaybeFree(
    TradeAmountBarLayout *amountBar, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)amountBar);
  }
}

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif


// GHIDRA_FUNCTION IMPERIALISM 0x0058B340
// GHIDRA_NAME TCivilianButton::CreateTCivilianButtonInstance
// GHIDRA_PROTO void * __cdecl CreateTCivilianButtonInstance(void)

// FUNCTION: IMPERIALISM 0x0058B340
CivilianButtonState *__cdecl CreateTCivilianButtonInstance(void)
{
  CivilianButtonState *button = reinterpret_cast<CivilianButtonState *>(
      AllocateWithFallbackHandler(0xa0));
  if (button != 0) {
    TradeScreenRuntimeBridge::ConstructUiClickablePictureResourceEntry(button);
    button->vftable = reinterpret_cast<void *>(&g_vtblTCivilianButton);
    button->buttonTag = 0xc;
  }
  return button;
}


// GHIDRA_FUNCTION IMPERIALISM 0x0058B3C0
// GHIDRA_NAME TCivilianButton::GetTCivilianButtonClassNamePointer
// GHIDRA_PROTO void * __cdecl GetTCivilianButtonClassNamePointer(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Returns class descriptor pointer for TCivilianButton.
// GHIDRA_COMMENT_END

/* Returns class descriptor pointer for TCivilianButton. */

// FUNCTION: IMPERIALISM 0x0058B3C0
void *__cdecl GetTCivilianButtonClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTCivilianButton);
}


// GHIDRA_FUNCTION IMPERIALISM 0x0058B3E0
// GHIDRA_NAME TCivilianButton::ConstructTCivilianButtonBaseState
// GHIDRA_PROTO void * __thiscall ConstructTCivilianButtonBaseState(void)

// FUNCTION: IMPERIALISM 0x0058B3E0
CivilianButtonState *__fastcall ConstructTCivilianButtonBaseState(CivilianButtonState *button)
{
  TradeScreenRuntimeBridge::ConstructUiClickablePictureResourceEntry(button);
  button->vftable = reinterpret_cast<void *>(&g_vtblTCivilianButton);
  button->buttonTag = 0xc;
  return button;
}


// GHIDRA_FUNCTION IMPERIALISM 0x0058B410
// GHIDRA_NAME TCivilianButton::DestructTCivilianButtonAndMaybeFree
// GHIDRA_PROTO void * __thiscall DestructTCivilianButtonAndMaybeFree(byte freeSelfFlag)

// FUNCTION: IMPERIALISM 0x0058B410
CivilianButtonState *__fastcall DestructTCivilianButtonAndMaybeFree(
    CivilianButtonState *button, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  TradeScreenRuntimeBridge::DestructCityDialogSharedBaseState(button);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)button);
  }
  return button;
}


// GHIDRA_FUNCTION IMPERIALISM 0x0058B5C0
// GHIDRA_NAME THQButton::CreateTHQButtonInstance
// GHIDRA_PROTO void * __cdecl CreateTHQButtonInstance(void)

// FUNCTION: IMPERIALISM 0x0058B5C0
HQButtonState *__cdecl CreateTHQButtonInstance(void)
{
  HQButtonState *button = reinterpret_cast<HQButtonState *>(AllocateWithFallbackHandler(0x9c));
  if (button != 0) {
    TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(button);
    button->vftable = reinterpret_cast<void *>(&g_vtblTHQButton);
  }
  return button;
}


// GHIDRA_FUNCTION IMPERIALISM 0x0058B640
// GHIDRA_NAME THQButton::GetTHQButtonClassNamePointer
// GHIDRA_PROTO void * __cdecl GetTHQButtonClassNamePointer(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Returns class descriptor pointer for THQButton.
// GHIDRA_COMMENT_END

/* Returns class descriptor pointer for THQButton. */

// FUNCTION: IMPERIALISM 0x0058B640
void *__cdecl GetTHQButtonClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTHQButton);
}


// GHIDRA_FUNCTION IMPERIALISM 0x0058B660
// GHIDRA_NAME THQButton::ConstructTHQButtonBaseState
// GHIDRA_PROTO void * __thiscall ConstructTHQButtonBaseState(void)

// FUNCTION: IMPERIALISM 0x0058B660
HQButtonState *__fastcall ConstructTHQButtonBaseState(HQButtonState *button)
{
  TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(button);
  button->vftable = reinterpret_cast<void *>(&g_vtblTHQButton);
  return button;
}


// GHIDRA_FUNCTION IMPERIALISM 0x0058B690
// GHIDRA_NAME THQButton::DestructTHQButtonAndMaybeFree
// GHIDRA_PROTO void * __thiscall DestructTHQButtonAndMaybeFree(byte freeSelfFlag)

// FUNCTION: IMPERIALISM 0x0058B690
HQButtonState *__fastcall DestructTHQButtonAndMaybeFree(
    HQButtonState *button, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  TradeScreenRuntimeBridge::DestructCityDialogSharedBaseState(button);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)button);
  }
  return button;
}


// GHIDRA_FUNCTION IMPERIALISM 0x0058B960
// GHIDRA_NAME TPlacard::CreateTPlacardInstance
// GHIDRA_PROTO void * __cdecl CreateTPlacardInstance(void)

// FUNCTION: IMPERIALISM 0x0058B960
PlacardState *__cdecl CreateTPlacardInstance(void)
{
  PlacardState *placard = reinterpret_cast<PlacardState *>(AllocateWithFallbackHandler(0x94));
  if (placard != 0) {
    TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(placard);
    placard->vftable = reinterpret_cast<void *>(&g_vtblTPlacard);
    placard->placardValue = 0;
  }
  return placard;
}


// GHIDRA_FUNCTION IMPERIALISM 0x0058B9F0
// GHIDRA_NAME TPlacard::GetTPlacardClassNamePointer
// GHIDRA_PROTO void * __cdecl GetTPlacardClassNamePointer(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Returns class descriptor pointer for TPlacard.
// GHIDRA_COMMENT_END

/* Returns class descriptor pointer for TPlacard. */

// FUNCTION: IMPERIALISM 0x0058B9F0
void *__cdecl GetTPlacardClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTPlacard);
}


// GHIDRA_FUNCTION IMPERIALISM 0x0058BA10
// GHIDRA_NAME TPlacard::ConstructTPlacardBaseState
// GHIDRA_PROTO void * __thiscall ConstructTPlacardBaseState(void)

// FUNCTION: IMPERIALISM 0x0058BA10
PlacardState *__fastcall ConstructTPlacardBaseState(PlacardState *placard)
{
  TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(placard);
  placard->vftable = reinterpret_cast<void *>(&g_vtblTPlacard);
  placard->placardValue = 0;
  return placard;
}


// GHIDRA_FUNCTION IMPERIALISM 0x0058BA40
// GHIDRA_NAME TPlacard::DestructTPlacardAndMaybeFree
// GHIDRA_PROTO void * __thiscall DestructTPlacardAndMaybeFree(byte freeSelfFlag)

// FUNCTION: IMPERIALISM 0x0058BA40
PlacardState *__fastcall DestructTPlacardAndMaybeFree(
    PlacardState *placard, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  TradeScreenRuntimeBridge::DestructCityDialogSharedBaseState(placard);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)placard);
  }
  return placard;
}


// GHIDRA_FUNCTION IMPERIALISM 0x0058BE30
// GHIDRA_NAME TArmyPlacard::CreateTArmyPlacardInstance
// GHIDRA_PROTO void * __cdecl CreateTArmyPlacardInstance(void)

// FUNCTION: IMPERIALISM 0x0058BE30
PlacardState *__cdecl CreateTArmyPlacardInstance(void)
{
  PlacardState *placard = reinterpret_cast<PlacardState *>(AllocateWithFallbackHandler(0x94));
  if (placard != 0) {
    TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(placard);
    placard->vftable = reinterpret_cast<void *>(&g_vtblTArmyPlacard);
    placard->placardValue = (short)0xffff;
  }
  return placard;
}


// GHIDRA_FUNCTION IMPERIALISM 0x0058BEB0
// GHIDRA_NAME TArmyPlacard::GetTArmyPlacardClassNamePointer
// GHIDRA_PROTO void * __cdecl GetTArmyPlacardClassNamePointer(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Returns class descriptor pointer for TArmyPlacard.
// GHIDRA_COMMENT_END

/* Returns class descriptor pointer for TArmyPlacard. */

// FUNCTION: IMPERIALISM 0x0058BEB0
void *__cdecl GetTArmyPlacardClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTArmyPlacard);
}


// GHIDRA_FUNCTION IMPERIALISM 0x0058BED0
// GHIDRA_NAME TArmyPlacard::ConstructTArmyPlacardBaseState
// GHIDRA_PROTO void * __thiscall ConstructTArmyPlacardBaseState(void)

// FUNCTION: IMPERIALISM 0x0058BED0
PlacardState *__fastcall ConstructTArmyPlacardBaseState(PlacardState *placard)
{
  TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(placard);
  placard->vftable = reinterpret_cast<void *>(&g_vtblTArmyPlacard);
  placard->placardValue = (short)0xffff;
  return placard;
}


// GHIDRA_FUNCTION IMPERIALISM 0x0058BF00
// GHIDRA_NAME TArmyPlacard::DestructTArmyPlacardAndMaybeFree
// GHIDRA_PROTO void * __thiscall DestructTArmyPlacardAndMaybeFree(byte freeSelfFlag)

// FUNCTION: IMPERIALISM 0x0058BF00
PlacardState *__fastcall DestructTArmyPlacardAndMaybeFree(
    PlacardState *placard, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  TradeScreenRuntimeBridge::DestructCityDialogSharedBaseState(placard);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)placard);
  }
  return placard;
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif

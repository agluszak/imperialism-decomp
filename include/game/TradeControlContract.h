#pragma once

// Redecomp contract generated from Ghidra-export artifacts.
// Source artifacts:
// - tmp_decomp/batch725_tradecontrol_struct_post_semantics.log
// - tmp_decomp/batch723_tcontrol_methods_post_move.csv
// - tmp_decomp/batch723_tradecontrol_methods_post_move.csv
// - tmp_decomp/batch724_tradecontract_vtbl_slot_summary.csv

#include "decomp_types.h"

namespace trade_contract {

struct TradeControlLayout {
  void* pVtable;              // +0x00
  u32 cityDialogFlag4;        // +0x04
  u32 controlActiveFlag8;     // +0x08
  u32 dialogValueDwordC;      // +0x0c
  u32 dialogValueDword10;     // +0x10
  u8  pad14[0x04];            // +0x14
  void* pUiOwner18;           // +0x18
  u32 controlTag;             // +0x1c
  void* pChildMapView20;      // +0x20
  u32 controlPosX24;          // +0x24
  u32 controlPosY28;          // +0x28
  u32 cachedPosX2c;           // +0x2c
  u32 cachedPosY30;           // +0x30
  u32 controlWidth34;         // +0x34
  u32 controlHeight38;        // +0x38
  u8  pad3c[0x08];            // +0x3c
  void* pChildControlList44;  // +0x44
  u8  pad48[0x08];            // +0x48
  void* pWindowOwner50;       // +0x50
  u8  pad54[0x0c];            // +0x54
  u16 barValue60;             // +0x60
  u16 barSelected62;          // +0x62
  u16 barLimit64;             // +0x64
  u16 barAux66;               // +0x66
  u8  pad68[0x1c];            // +0x68
  u16 bitmapId;               // +0x84
  u8  pad86[0x0e];            // +0x86
  u32 autoRepeatTick94;       // +0x94
}; // size: 0x98

enum TradeControlVtableOffset {
  kVSlot_CtrlSlot00 = 0x0000,
  kVSlot_CtrlSlot01 = 0x0004,
  kVSlot_CtrlSlot02 = 0x0008,
  kVSlot_CtrlSlot03 = 0x000c,
  kVSlot_CtrlSlot04 = 0x0010,
  kVSlot_CtrlSlot05 = 0x0014,
  kVSlot_CtrlSlot06 = 0x0018,
  kVSlot_CtrlSlot07 = 0x001c,
  kVSlot_CtrlSlot08 = 0x0020,
  kVSlot_CtrlSlot09 = 0x0024,
  kVSlot_CtrlSlot10 = 0x0028,
  kVSlot_SetControlValueSlot2C = 0x002c,
  kVSlot_QueryStepValueSlot30 = 0x0030,
  kVSlot_CtrlSlot13 = 0x0034,
  kVSlot_CtrlSlot14 = 0x0038,
  kVSlot_CtrlSlot15 = 0x003c,
  kVSlot_CtrlSlot16 = 0x0040,
  kVSlot_CtrlSlot17 = 0x0044,
  kVSlot_CtrlSlot18 = 0x0048,
  kVSlot_CtrlSlot19 = 0x004c,
  kVSlot_CtrlSlot20 = 0x0050,
  kVSlot_CtrlSlot21 = 0x0054,
  kVSlot_CtrlSlot22 = 0x0058,
  kVSlot_CtrlSlot23 = 0x005c,
  kVSlot_CtrlSlot24 = 0x0060,
  kVSlot_CtrlSlot25 = 0x0064,
  kVSlot_CtrlSlot26 = 0x0068,
  kVSlot_CtrlSlot27 = 0x006c,
  kVSlot_CtrlSlot28 = 0x0070,
  kVSlot_CtrlSlot29 = 0x0074,
  kVSlot_CtrlSlot30 = 0x0078,
  kVSlot_CtrlSlot31 = 0x007c,
  kVSlot_CtrlSlot32 = 0x0080,
  kVSlot_CtrlSlot33 = 0x0084,
  kVSlot_CtrlSlot34 = 0x0088,
  kVSlot_CtrlSlot35 = 0x008c,
  kVSlot_CtrlSlot36 = 0x0090,
  kVSlot_CtrlSlot37 = 0x0094,
  kVSlot_CtrlSlot38 = 0x0098,
  kVSlot_CtrlSlot39 = 0x009c,
  kVSlot_CtrlSlot40 = 0x00a0,
  kVSlot_SetEnabledSlotA4 = 0x00a4,
  kVSlot_SetStateSlotA8 = 0x00a8,
  kVSlot_CtrlSlot43 = 0x00ac,
  kVSlot_CtrlSlot44 = 0x00b0,
  kVSlot_CtrlSlot45 = 0x00b4,
  kVSlot_CtrlSlot46 = 0x00b8,
  kVSlot_CtrlSlot47 = 0x00bc,
  kVSlot_CtrlSlot48 = 0x00c0,
  kVSlot_CtrlSlot49 = 0x00c4,
  kVSlot_CtrlSlot50 = 0x00c8,
  kVSlot_CtrlSlot51 = 0x00cc,
  kVSlot_CtrlSlot52 = 0x00d0,
  kVSlot_CtrlSlot53 = 0x00d4,
  kVSlot_CtrlSlot54 = 0x00d8,
  kVSlot_CtrlSlot55 = 0x00dc,
  kVSlot_CtrlSlot56 = 0x00e0,
  kVSlot_CtrlSlot57 = 0x00e4,
  kVSlot_CtrlSlot58 = 0x00e8,
  kVSlot_IsActionableSlotEC = 0x00ec,
  kVSlot_CaptureLayoutSlotF0 = 0x00f0,
  kVSlot_CaptureLayoutSlotF4 = 0x00f4,
  kVSlot_RefreshSlotF8 = 0x00f8,
  kVSlot_CtrlSlot63 = 0x00fc,
  kVSlot_CtrlSlot64 = 0x0100,
  kVSlot_CtrlSlot65 = 0x0104,
  kVSlot_CtrlSlot66 = 0x0108,
  kVSlot_CtrlSlot67 = 0x010c,
  kVSlot_CtrlSlot68 = 0x0110,
  kVSlot_UpdateAfterBitmapChangeSlot114 = 0x0114,
  kVSlot_CtrlSlot70 = 0x0118,
  kVSlot_CtrlSlot71 = 0x011c,
  kVSlot_CtrlSlot72 = 0x0120,
  kVSlot_CtrlSlot73 = 0x0124,
  kVSlot_CtrlSlot74 = 0x0128,
  kVSlot_QueryBoundsSlot12C = 0x012c,
  kVSlot_CtrlSlot76 = 0x0130,
  kVSlot_CtrlSlot77 = 0x0134,
  kVSlot_CtrlSlot78 = 0x0138,
  kVSlot_CtrlSlot79 = 0x013c,
  kVSlot_CtrlSlot80 = 0x0140,
  kVSlot_CtrlSlot81 = 0x0144,
  kVSlot_CtrlSlot82 = 0x0148,
  kVSlot_CtrlSlot83 = 0x014c,
  kVSlot_CtrlSlot84 = 0x0150,
  kVSlot_CtrlSlot85 = 0x0154,
  kVSlot_CtrlSlot86 = 0x0158,
  kVSlot_CtrlSlot87 = 0x015c,
  kVSlot_CtrlSlot88 = 0x0160,
  kVSlot_CtrlSlot89 = 0x0164,
  kVSlot_ApplyBoundsSlot168 = 0x0168,
  kVSlot_CtrlSlot91 = 0x016c,
  kVSlot_CtrlSlot92 = 0x0170,
  kVSlot_CtrlSlot93 = 0x0174,
  kVSlot_CtrlSlot94 = 0x0178,
  kVSlot_CtrlSlot95 = 0x017c,
  kVSlot_CtrlSlot96 = 0x0180,
  kVSlot_CtrlSlot97 = 0x0184,
  kVSlot_CtrlSlot98 = 0x0188,
  kVSlot_CtrlSlot99 = 0x018c,
  kVSlot_CtrlSlot100 = 0x0190,
  kVSlot_CtrlSlot101 = 0x0194,
  kVSlot_CtrlSlot102 = 0x0198,
  kVSlot_CtrlSlot103 = 0x019c,
  kVSlot_ApplyMoveClampSlot1A0 = 0x01a0,
  kVSlot_SetBarMetricSlot1A4 = 0x01a4,
  kVSlot_CtrlSlot106 = 0x01a8,
  kVSlot_SetBarMetricRatioSlot1AC = 0x01ac,
  kVSlot_CtrlSlot108 = 0x01b0,
  kVSlot_ApplyStyleDescriptorSlot1B4 = 0x01b4,
  kVSlot_CtrlSlot110 = 0x01b8,
  kVSlot_CtrlSlot111 = 0x01bc,
  kVSlot_CtrlSlot112 = 0x01c0,
  kVSlot_SetStyleStateSlot1C4 = 0x01c4,
  kVSlot_SetBitmapSlot1C8 = 0x01c8,
  kVSlot_InvokeSlot1CCVirtual = 0x01cc,
  kVSlot_CtrlSlot116 = 0x01d0,
  kVSlot_CtrlSlot117 = 0x01d4,
  kVSlot_CtrlSlot118 = 0x01d8,
  kVSlot_CtrlSlot119 = 0x01dc,
  kVSlot_CtrlSlot120 = 0x01e0,
  kVSlot_SetControlValueSlot1E4 = 0x01e4,
  kVSlot_QueryValueSlot1E8 = 0x01e8
};

// TControl primary method address/signature map (non-thunk).
// 0x00406429: int __thiscall DispatchUiMouseEventToChildrenOrSelf(TControl * this, int param3, int param4, int param5, int param_4)
// 0x00415d70: void __thiscall SetCityDialogValueDword10(TControl * this, int value)
// 0x00427290: void __thiscall BuildRectFromControlPositionAndSizeFields(TControl * this, int * pOutRect)
// 0x00485e90: void __thiscall HandleTurnEventVtableSlot08ConditionalDispatch(TControl * this, int arg1)
// 0x0048a260: void __thiscall SetCityDialogFlagByte4(TControl * this, char flagValue)
// 0x0048a2e0: void __thiscall DispatchUiCommandToHandler(TControl * this, int commandId, void * eventArg, int eventExtra)
// 0x0048a310: void __thiscall ForwardNotifyParamToPrimaryChildSlot44(TControl * this, int notifyValue)
// 0x0048a3b0: void __thiscall DispatchQueuedUiCommandAndRelease(TControl * this)
// 0x0048a3f0: void __thiscall DispatchUiSelectionToHandler(TControl * this)
// 0x0048a690: void __thiscall HandleCityDialogNoOpA(TControl * this, int activeFlag, int refreshNow)
// 0x0048a6b0: void __thiscall NoOpUiSetControlVisibleFlag(TControl * this, int visibleFlag)
// 0x0048a6d0: void __thiscall DispatchUiCommand19ToParent(TControl * this)
// 0x0048aaf0: void __thiscall DispatchControlEventToChildrenAndSelf(TControl * this, int eventArg)
// 0x0048ab90: void __thiscall ForwardMapViewVirtualC4IfPresent(TControl * this, int arg2)
// 0x0048abc0: void __thiscall NoOpUiCallback(TControl * this)
// 0x0048afd0: void * __thiscall FindUiChildControlByWindowHandleRecursive(TControl * this, int windowHandle)
// 0x0048b070: void __thiscall SetUiControlVisibleFlagAndMaybeRefreshWindow(TControl * this, int visibleFlag)
// 0x0048b1a0: int __thiscall QueryChildMapViewSlot58OrZero(TControl * this)
// 0x0048b1c0: void __thiscall SetControlActiveFlagAndRefreshIfChanged(TControl * this, int activeFlag, int refreshIfChanged)
// 0x0048b200: bool __thiscall CanProcessMapViewSlotECUnderWindowState(TControl * this)
// 0x0048b250: void __thiscall WrapperFor_InvalidateCityDialogRectRegion_At0048b250(TControl * this, int arg1, int arg2)
// 0x0048b3f0: void __thiscall UpdateControlPositionAndInvalidateUnionRect(TControl * this, int arg1, int arg2)
// 0x0048b4b0: void __thiscall InvalidateOffsetRegionUsingChildClipRect(TControl * this, int * clipState)
// 0x0048b690: void __thiscall ValidateControlRectIfWindowActive(TControl * this, int * pRect)
// 0x0048b770: bool __thiscall SetGlobalUiSelectionIfChangedAndNotify(TControl * this)
// 0x0048c000: bool __thiscall EvaluateControlInputGate(TControl * this)
// 0x0048c050: bool __thiscall HasRenderableParentAndContent(TControl * this)
// 0x0048c080: void __thiscall HandleCursorHoverSelectionByChildHitTestAndFallback(TControl * this, int arg1, int arg2)
// 0x0048c450: void __thiscall DispatchUiMouseMoveToChildren(TControl * this, int arg1, int arg2, int arg3, int arg4)
// 0x0048c590: int __thiscall DispatchUiMouseEventToChildrenOrSelf_Impl(TControl * this, int param3, int param4, int param5, int param_4)
// 0x0048e520: void __thiscall ConstructUiCommandTagResourceEntryBase(TControl * this)

// TradeControl primary method address/signature map (non-thunk).
// 0x00412bf0: void __cdecl NoOpTurnEventStateVtableSlot0C(void)
// 0x00412c10: void __cdecl NoOpTurnEventStateVtableSlot10(void)
// 0x00415ce0: void __cdecl HandleTurnEventVtableSlot24CopyPayloadBuffer(void)
// 0x00415d50: int __fastcall GetCityDialogValueDword10(CityDialogController * pDialog)
// 0x00427220: void __thiscall NoOpCommandHandler(TradeControl * this)
// 0x00427240: void __cdecl NoOpControlCallback_Impl(void)
// 0x00427260: void __thiscall BuildRectFromControlDimensions_Impl(TradeControl * this)
// 0x004272d0: void __thiscall DispatchVslot134WithRectAndRectPlus8_Impl(TradeControl * this)
// 0x00429450: void __cdecl GetCityProductionControllerField60(void)
// 0x00429470: void __cdecl AssertCityProductionGlobalStateInitialized(void)
// 0x004294a0: bool __cdecl LogUnhandledDialogMethodAndReturnFalse(void)
// 0x00485f70: void __cdecl HandleCityDialogNoOpSlot14(void)
// 0x00485f90: void __cdecl HandleCityDialogNoOpSlot18(void)
// 0x0048a240: byte __fastcall GetCityDialogFlagByte4(CityDialogController * pDialog)
// 0x0048a2c0: int __fastcall GetCityDialogValueDwordC(CityDialogController * pDialog)
// 0x0048a380: void __thiscall ForwardCityDialogParamToChildSlot48(TradeControl * this)
// 0x0048a480: void __cdecl CanHandleCityDialogActionFalse(void)
// 0x0048a4a0: void __thiscall DetachActiveCityProductionChildIfMatches(TradeControl * this)
// 0x0048a4d0: void __cdecl SetUiResourceOwner(void)
// 0x0048a500: void __cdecl IsCurrentActiveCityProductionView(void)
// 0x0048a530: void __cdecl CanStartCityProductionActionFalse(void)
// 0x0048a550: void __cdecl GetCityDialogZeroValue(void)
// 0x0048a570: void __cdecl ActivateCityProductionViewIfAllowed(void)
// 0x0048a650: void __cdecl HandleCityProductionNoOp(void)
// 0x0048a670: void __thiscall DispatchCityProductionAction1A(TradeControl * this)
// 0x0048a6f0: void __cdecl DispatchCityProductionAction1B(void)
// 0x0048abe0: void __thiscall RunNationInfoModalAndReturnNonCancel_Impl(TradeControl * this)
// 0x0048ae60: void __thiscall DetachUiElementFromOwnerListAndClearBackref(TradeControl * this, TradeControl * pUiElement)
// 0x0048b0b0: void __thiscall CloseCityDialogChildrenAndReleaseSelf(TradeControl * this)
// 0x0048b180: void __cdecl GetCityDialogValueViaChildSlot58(void)
// 0x0048b2d0: void __thiscall WrapperFor_thunk_PopSinglyLinkedListHeadPointer_At0048b2d0(TradeControl * this)
// 0x0048b6d0: void __thiscall WrapperFor_thunk_InvalidateCityDialogRectRegion_At0048b6d0(TradeControl * this)
// 0x0048b700: void __thiscall ResetUiInputCaptureState(TradeControl * this)
// 0x0048b7b0: bool __thiscall WrapperFor_GetOrCreateHandleMapObjectByHandle_At0048b7b0(TradeControl * this, void * pExistingHandleMap)
// 0x0048b810: void __thiscall WrapperFor_AllocateWithFallbackHandler_At0048b810(TradeControl * this)
// 0x0048b860: void __cdecl WrapperFor_InvalidateCityDialogRectRegion_At0048b860(void)
// 0x0048b8d0: void __thiscall PaintVisibleChildrenIntersectingClipRect(TradeControl * this)
// 0x0048ba40: void __thiscall OffsetRectByControlPositionAndDispatchVslot138_Impl(TradeControl * this)
// 0x0048ba80: void __cdecl OffsetRectByControlPositionAndDispatchVslot138_EcxBridge_Impl(void)
// 0x0048bb00: void __cdecl OffsetRectByControlPosition_Impl(void)
// 0x0048c1e0: void __thiscall RefreshCityProductionViewStateFromContext(TradeControl * this)
// 0x0048c250: void __cdecl UpdateMapCursorFromSelectionContext(void)
// 0x0048c380: void __thiscall UpdateRectCacheIfChangedAndInvalidateCityDialog(TradeControl * this, int arg1, int arg2)
// 0x0048c750: void __thiscall DrawRectangleInCurrentUiContext(TradeControl * this, int * pRect)
// 0x0048c7a0: void __thiscall AssertMcAppUILine1914(TradeControl * this)
// 0x0048c7d0: void __thiscall AssertMcAppUILine1922(TradeControl * this)
// 0x0048c890: void __thiscall DispatchVfuncA0ToLinkedChildListSlot44(TradeControl * this)
// 0x0048e640: void __thiscall BeginMouseCaptureAndStartRepeatTimer(TradeControl * this, int arg1, int arg2, int arg3, int arg4)
// 0x0048e7a0: void __thiscall SetControlPictureEntryAndMaybeRefresh(TradeControl * this, int * pPictureEntryRef, bool fRefreshNow)
// 0x0048e7d0: void __stdcall SetCityProductionDialogPictureRectAndMaybeRefresh(int arg1, int arg2)
// 0x0048e810: void __thiscall SetControlStateFlagAndMaybeRefresh(TradeControl * this, bool fEnabledState, bool fRefreshNow)
// 0x0048e850: void __thiscall DispatchPictureResourceCommand(TradeControl * this, int nEventType, void * pEventSender, void * pEventDataA, PanelEventPayload * pEventDataB)
// 0x0048e980: void __thiscall WrapperFor_ApplyRectMarginsInPlace_At0048e980(TradeControl * this)
// 0x0048e9c0: void __thiscall NoOpUiViewSlotHandler(TradeControl * this)
// 0x0048e9e0: void __cdecl NoOpCityProductionDialogPictureHook(void)
// 0x00583bd0: void __thiscall HandleTradeArrowAutoRepeatTickAndDispatch(TradeControl * this, int nEventType, void * pEventSender, void * pEventDataA, SplitArrowDispatchPayload * pHitPayload, void * pRepeatArg)
// 0x00588630: void __thiscall UpdateBarValuesAndRefresh(TradeControl * this, int valueAt60, int valueAt62)
// 0x00588670: void __thiscall InvokeSlot1A8NoArg(TradeControl * this)
// 0x00588690: void __thiscall RenderPrimarySurfaceOverlayPanelWithClipCache(TradeControl * this)
// 0x00589340: void __thiscall RenderQuickDrawControlWithHitRegionClipVariantA(TradeControl * this)
// 0x00589540: void __thiscall RenderQuickDrawOverlayWithHitRegionVariantA(TradeControl * this, int selectedValue)
// 0x0058a1b0: void __thiscall RenderQuickDrawControlWithHitRegionClipVariantB(TradeControl * this)
// 0x0058a3b0: void __thiscall RenderQuickDrawOverlayWithHitRegionVariantB(TradeControl * this, int selectedValue)
// 0x0058ac80: void __thiscall RenderQuickDrawControlWithHitRegionClipVariantC(TradeControl * this)
// 0x0058b0f0: void __thiscall RenderControlWithTemporaryRectClipRegionAndChildren(TradeControl * this)
// 0x0058b890: void __thiscall InvokeSlot1CCIfSlot28Enabled(TradeControl * this, int arg2, int arg3)

}  // namespace trade_contract

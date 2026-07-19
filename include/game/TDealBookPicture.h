#pragma once

#include "compat.h"
#include "game/TPicture.h"
#include "game/mfc.h"

class TTradePageBuyView;
class TTradePageSellView;

// VTABLE: IMPERIALISM 0x0066dfc0
class TDealBookPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TDealBookPicture)
  virtual ~TDealBookPicture() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x48b0b0)
  // slot 0x08 ShallowClone inherited unchanged (0x48f640)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a GetBoolSlot28 inherited unchanged (0x48a240)
  // slot 0x0b SetControlValue inherited unchanged (0x48a260)
  // slot 0x0c QueryStepValue inherited unchanged (0x48a2c0)
  // slot 0x0d DispatchQueuedUiCommandAndRelease inherited unchanged (0x48a3b0)
  // slot 0x0e DispatchUiSelectionToHandler inherited unchanged (0x48a3f0)
  virtual void HandleEvent(int commandId, TEventHandler* sourceHandler,
                           TEvent* event) override; // slot 0x0f 0x005bbc30
  // slot 0x10 DispatchEvent inherited unchanged (0x48a2e0)
  // slot 0x11 vmethod_0017 inherited unchanged (0x48a310)
  // slot 0x12 ForwardParam inherited unchanged (0x48a380)
  // slot 0x13 DoIdle inherited unchanged (0x48a480)
  // slot 0x14 GetCityDialogValueDword10 inherited unchanged (0x415d50)
  // slot 0x15 SetCityDialogValueDword10 inherited unchanged (0x415d70)
  // slot 0x16 OwnerPanel inherited unchanged (0x48b180)
  // slot 0x17 vmethod_0023 inherited unchanged (0x48a530)
  // slot 0x18 GetDeactivateVetoCode inherited unchanged (0x48a550)
  // slot 0x19 OnDeactivated inherited unchanged (0x48a690)
  // slot 0x1a OnDeactivateVetoed inherited unchanged (0x48a6b0)
  // slot 0x1b HandleCityProductionNoOp inherited unchanged (0x48a650)
  // slot 0x1c DispatchUiCommand19ToParent inherited unchanged (0x48a6d0)
  // slot 0x1d DispatchCityProductionAction1A inherited unchanged (0x48a670)
  // slot 0x1e DispatchCityProductionAction1B inherited unchanged (0x48a6f0)
  // slot 0x1f ActivateCityProductionViewIfAllowed inherited unchanged (0x48a570)
  // slot 0x20 TryDeactivateActiveView inherited unchanged (0x48a5e0)
  // slot 0x21 vmethod_0081 inherited unchanged (0x48a710)
  // slot 0x22 IsActiveView inherited unchanged (0x48a500)
  // slot 0x23 DetachUiResourceOwnerIfMatches inherited unchanged (0x48a4a0)
  // slot 0x24 SetUiResourceOwner inherited unchanged (0x48a4d0)
  // slot 0x25 ResolveControlByTag inherited unchanged (0x48afd0)
  // slot 0x26 SwitchActiveChildAndNotify inherited unchanged (0x48af80)
  // slot 0x27 DispatchSlot9CToLinkedChildren inherited unchanged (0x48c820)
  // slot 0x28 CallVoidSlotA0 inherited unchanged (0x48c890)
  // slot 0x29 SetEnabled inherited unchanged (0x48b1c0)
  // slot 0x2a SetState inherited unchanged (0x48b070)
  // slot 0x2b GetField4E inherited unchanged (0x427200)
  // slot 0x2c HandleCursorHoverFallback inherited unchanged (0x48c250)
  // slot 0x2d vmethod_0073 inherited unchanged (0x48c1c0)
  // slot 0x2e RefreshCityProductionViewStateFromContext inherited unchanged (0x48c1e0)
  // slot 0x2f QuerySelectedIndexSlotBC inherited unchanged (0x429450)
  // slot 0x30 InvalidateOffsetRegionUsingChildClipRect inherited unchanged (0x48b4b0)
  // slot 0x31 ForwardMapViewVirtualC4IfPresent inherited unchanged (0x48ab90)
  // slot 0x32 ValidateControlRectIfWindowActive inherited unchanged (0x48b690)
  // slot 0x33 EvaluateControlInputGate inherited unchanged (0x48c000)
  // slot 0x34 HasRenderableParentAndContent inherited unchanged (0x48c050)
  // slot 0x35 HandleCursorHoverSelectionByChildHitTestAndFallback inherited unchanged (0x48c080)
  // slot 0x36 DispatchControlEventToChildrenAndSelf inherited unchanged (0x48aaf0)
  // slot 0x37 NoOpUiLifecycleHook inherited unchanged (0x48ab70)
  // slot 0x38 NoOpUiCallback inherited unchanged (0x48abc0)
  // slot 0x39 RefreshControl inherited unchanged (0x48b6d0)
  // slot 0x3a QueryOwnerContextPanel inherited unchanged (0x48b1a0)
  // slot 0x3b IsActionable inherited unchanged (0x48b200)
  // slot 0x3c CaptureLayoutF0 inherited unchanged (0x48b250)
  // slot 0x3d CaptureLayout inherited unchanged (0x48b3f0)
  // slot 0x3e Refresh inherited unchanged (0x48b770)
  // slot 0x3f PostRenderSlotFC inherited unchanged (0x427220)
  // slot 0x40 BindMapQuickDrawDc inherited unchanged (0x48b7b0)
  // slot 0x41 ReleaseMapQuickDrawDc inherited unchanged (0x48b7e0)
  // slot 0x42 EnsureField48Buffer inherited unchanged (0x48b810)
  // slot 0x43 PaintVisibleChildrenIntersectingClipRect inherited unchanged (0x48b8d0)
  // slot 0x44 ApplyRectSlot110 inherited unchanged (0x48f3c0)
  // slot 0x45 vmethod_0048 inherited unchanged (0x48b860)
  // slot 0x46 DispatchUiMouseMoveToChildren inherited unchanged (0x48c450)
  // slot 0x47 BeginMouseCaptureAndStartRepeatTimer inherited unchanged (0x48e640)
  // slot 0x48 DispatchUiMouseEventToChildrenOrSelf_Impl inherited unchanged (0x48c590)
  // slot 0x49 vmethod_0071 inherited unchanged (0x427240)
  // slot 0x4a QueryContentBounds inherited unchanged (0x427260)
  // slot 0x4b QueryBounds inherited unchanged (0x427290)
  // slot 0x4c DispatchVslot134WithRectAndRectPlus8_Impl inherited unchanged (0x4272d0)
  // slot 0x4d vmethod_0076 inherited unchanged (0x48ba80)
  // slot 0x4e vmethod_0078 inherited unchanged (0x48ba40)
  // slot 0x4f InvokeSlot13C inherited unchanged (0x48b700)
  // slot 0x50 OffsetRectByControlPosition inherited unchanged (0x48bb00)
  // slot 0x51 UpdateAfterBitmapChange inherited unchanged (0x427330)
  // slot 0x52 CtrlSlot82_TransformPointViaSlot138_Impl_d6 inherited unchanged (0x48bb60)
  // slot 0x53 CtrlSlot83_TransformRectViaSlot148_Impl_d7 inherited unchanged (0x48bbb0)
  // slot 0x54 CtrlSlot84_AddControlPosToPoint_Impl_d8 inherited unchanged (0x48bc30)
  // slot 0x55 CtrlSlot85_OffsetRectByCachedPos_Impl_d9 inherited unchanged (0x48bc60)
  // slot 0x56 CtrlSlot86_GetCachedPosPoint_Impl_da inherited unchanged (0x48bb30)
  // slot 0x57 TransformPointViaSlot138 inherited unchanged (0x429410)
  // slot 0x58 CtrlSlot88_BuildRectFromSlot158AndCachedSize_Impl_dc inherited unchanged (0x48bce0)
  // slot 0x59 VTableSlot59 inherited unchanged (0x48b2d0)
  // slot 0x5a BuildRectFromSlot158 inherited unchanged (0x48c380)
  // slot 0x5b PointInBoundsAndActionable inherited unchanged (0x48e940)
  // slot 0x5c vmethod_0092 inherited unchanged (0x48abe0)
  // slot 0x5d DetachUiElementFromOwnerListAndClearBackref_e1 inherited unchanged (0x48ae60)
  // slot 0x5e CtrlSlot94_GetWordField54_Impl_e2 inherited unchanged (0x48c970)
  // slot 0x5f CtrlSlot95_TestPointInBoundsFromSlot128_Impl_e3 inherited unchanged (0x48c990)
  // slot 0x60 OrphanCallChain_C11_I88_004874b0 inherited unchanged (0x48c9e0)
  // slot 0x61 OrphanLeaf_NoCall_Ins07_004d8920 inherited unchanged (0x48ca00)
  // slot 0x62 OrphanCallChain_C11_I88_004874b0 inherited unchanged (0x48ca20)
  // slot 0x63 GetTEventHandlerClassNamePointer_e7 inherited unchanged (0x48ca40)
  // slot 0x64 DrawRectangleInCurrentUiContext_e8 inherited unchanged (0x48c750)
  // slot 0x65 AssertMcAppUILine1914_e9 inherited unchanged (0x48c7a0)
  // slot 0x66 AssertMcAppUILine1922_ea inherited unchanged (0x48c7d0)
  // slot 0x67 CtrlSlot103_SubtractPosAndDispatchSlot19C_Impl_eb inherited unchanged (0x48bac0)
  // slot 0x68 DispatchPictureResourceCommand inherited unchanged (0x48e850)
  // slot 0x69 BuildInsetContentRect inherited unchanged (0x48e980)
  // slot 0x6a AssertCityProductionGlobalStateInitialized inherited unchanged (0x429470)
  // slot 0x6b NoOpUiViewSlotHandler inherited unchanged (0x48e9c0)
  // slot 0x6c OrphanRetStub_00487a00 inherited unchanged (0x48e9e0)
  // slot 0x6d SetCityProductionDialogPictureRectAndMaybeRefresh inherited unchanged (0x48e7d0)
  // slot 0x6e SetControlPictureEntryAndMaybeRefresh inherited unchanged (0x48e7a0)
  // slot 0x6f LogUnhandledDialogMethodAndReturnFalse inherited unchanged (0x4294a0)
  // slot 0x70 SetControlStateFlagAndMaybeRefresh inherited unchanged (0x48e810)
  // slot 0x71 ResetPictureResourceEntry inherited unchanged (0x48f520)
  // slot 0x72 SetPictureResourceIdAndRefresh inherited unchanged (0x48f570)
  virtual void
  UpdateDealBookResourceSelectionAndToggleControls(int nResourceIndex,
                                                   short nSelectedRow); // slot 0x73 0x5baf70
  virtual undefined BuildSelectedNationOrderCapabilityRows();           // slot 0x74 0x5bb2e0
  // TPicture's slice ends at 0x90; RTTI oracle confirms sizeof(TDealBookPicture) == 0xb4.
  // The ctor (0x5babc0) writes field90 (= 8) and fieldB2 (= 0); the intervening region and
  // the 0xb3 byte are unconfirmed padding. Fields 0x92-0xb1 (formerly a pad92[0x20] blob)
  // recovered from RefreshTradeSelectionHeaderAndNationOfferBidLines (0x5bc0d0).
  short field90; // +0x90 initialized to 8
  // +0x92 -- computed as max(sellView->field_0x60, buyView->field_0x60) - 1 at the end of
  // RefreshTradeSelectionHeaderAndNationOfferBidLines; purpose beyond that not yet confirmed.
  short field92;
  short field94;          // +0x94 -- selected row index, written by
                          // UpdateDealBookResourceSelectionAndToggleControls (0x5baf70)
  unsigned char pad96[2]; // +0x96..0x97
  // +0x98 -- picture resource id, reapplied via this->SetPictureResourceIdAndRefresh(field98,
  // 1) at the end of RefreshTradeSelectionHeaderAndNationOfferBidLines (only when the byte at
  // +0xb1 was already set on entry).
  int field98;
  // +0x9c -- a TView-family pointer, target of one of the 4 CaptureLayoutF0 calls at the end
  // of RefreshTradeSelectionHeaderAndNationOfferBidLines; not yet confirmed which subview.
  TView* field9c;
  TTradePageBuyView* buyView;   // +0xa0
  TTradePageSellView* sellView; // +0xa4
  // +0xa8/+0xac -- re-cached copies of sellView/buyView, set at the end of
  // RefreshTradeSelectionHeaderAndNationOfferBidLines right after their CaptureLayoutF0
  // calls; field92 (the wider-page selection default) is then computed from these, not
  // directly from sellView/buyView.
  TTradePageSellView* fieldA8;
  TTradePageBuyView* fieldAC;
  unsigned char padB0; // +0xb0 -- no confirmed writer yet
  // +0xb1 -- "already initialized" flag; flipped (via `!=0`) at the end of
  // RefreshTradeSelectionHeaderAndNationOfferBidLines each time it runs.
  unsigned char initializedFlagB1;
  unsigned char fieldB2; // +0xb2 initialized to 0
  unsigned char padB3;   // +0xb3

  TDealBookPicture();
  // 0x5bc0d0 -- on first call (initializedFlagB1 == 0), sets the 'mark' state, builds the
  // "<season> <year>" header text for 'rtil' and loads the tab-strip's shared message.
  // On subsequent calls, resets both trade pages to their unselected state (-1), refreshes
  // 'titL'/'rtil"'s labels from the string table, resets 'mark', and reloads the tab strip.
  // Either way, ends by capturing 4 subviews' layouts, re-caching the sell view pointer,
  // recomputing field92 from the wider of the two trade pages' field_0x60, reapplying the
  // dialog's own picture resource, and flipping the "already initialized" flag.
  void RefreshTradeSelectionHeaderAndNationOfferBidLines();
  // 0x5bac50 -- re-caches the six commodity sub-controls (guob/dlos/uobt/lost) into
  // field98..fieldAC, resets the 'mark'/'tabs' labels and the initialized flag, refreshes
  // the nation title ('loot'), reapplies this dialog's slot-0x73 theme, plays the refresh
  // sfx, and rebuilds the 'titL'/'rtil' title/subtitle labels + 'rocl'/'rocr' buttons.
  // (Ghidra mis-attributed this to TControl; it is contiguous with this class's methods
  // and uses its exact field layout + slot 0x73.)
  void RefreshHudNationTitleControlsAndTheme(int themeCode);
};

ASSERT_SIZE(TDealBookPicture, 0xb4);

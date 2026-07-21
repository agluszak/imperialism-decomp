#pragma once

#include "compat.h"
#include "game/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e728
class TOfferDeskPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TOfferDeskPicture)
  virtual ~TOfferDeskPicture() override; // slot 0x01 (scalar deleting destructor)
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
                           TEvent* event) override; // slot 0x0f 0x005bf740
  // slot 0x10 DispatchUiCommandToHandler inherited unchanged (0x48a2e0)
  // slot 0x11 vmethod_0017 inherited unchanged (0x48a310)
  virtual void ForwardParam(int param) override; // slot 0x12 0x5bf860
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
  // slot 0x27 Open inherited unchanged (0x48c820)
  // slot 0x28 Close inherited unchanged (0x48c890)
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
  virtual void DoPostCreate(int arg) override; // slot 0x37 0x5be600
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
  virtual char HandleMouseUp(const CPoint& point, TToolboxEvent* event,
                             CPoint origin) override; // slot 0x48 0x5c0930
  // slot 0x49 vmethod_0071 inherited unchanged (0x427240)
  // slot 0x4a QueryContentBounds inherited unchanged (0x427260)
  // slot 0x4b QueryBounds inherited unchanged (0x427290)
  // slot 0x4c DispatchVslot134WithRectAndRectPlus8_Impl inherited unchanged (0x4272d0)
  // slot 0x4d vmethod_0076 inherited unchanged (0x48ba80)
  // slot 0x4e vmethod_0078 inherited unchanged (0x48ba40)
  // slot 0x4f InvokeSlot13C inherited unchanged (0x48b700)
  // slot 0x50 OffsetRectByControlPosition inherited unchanged (0x48bb00)
  // slot 0x51 UpdateAfterBitmapChange inherited unchanged (0x427330)
  // slot 0x52 CtrlSlot82_TransformPointViaSlot138_Impl inherited unchanged (0x48bb60)
  // slot 0x53 CtrlSlot83_TransformRectViaSlot148_Impl inherited unchanged (0x48bbb0)
  // slot 0x54 CtrlSlot84_AddControlPosToPoint_Impl inherited unchanged (0x48bc30)
  // slot 0x55 CtrlSlot85_OffsetRectByCachedPos_Impl inherited unchanged (0x48bc60)
  // slot 0x56 CtrlSlot86_GetCachedPosPoint_Impl inherited unchanged (0x48bb30)
  // slot 0x57 CopyRectFromBuildRectFromSlot158 inherited unchanged (0x429410)
  // slot 0x58 CtrlSlot88_BuildRectFromSlot158AndCachedSize_Impl inherited unchanged (0x48bce0)
  // slot 0x59 VTableSlot59 inherited unchanged (0x48b2d0)
  // slot 0x5a UpdateRectCacheIfChangedAndInvalidateCityDialog inherited unchanged (0x48c380)
  // slot 0x5b VTableSlot5B inherited unchanged (0x48e940)
  // slot 0x5c vmethod_0092 inherited unchanged (0x48abe0)
  // slot 0x5d DetachUiElementFromOwnerListAndClearBackref inherited unchanged (0x48ae60)
  // slot 0x5e CtrlSlot94_GetWordField54_Impl inherited unchanged (0x48c970)
  // slot 0x5f CtrlSlot95_TestPointInBoundsFromSlot128_Impl inherited unchanged (0x48c990)
  // slot 0x60 OrphanCallChain_C11_I88_004874b0 inherited unchanged (0x48c9e0)
  // slot 0x61 OrphanLeaf_NoCall_Ins07_004d8920 inherited unchanged (0x48ca00)
  // slot 0x62 OrphanCallChain_C11_I88_004874b0 inherited unchanged (0x48ca20)
  // slot 0x63 GetTEventHandlerClassNamePointer inherited unchanged (0x48ca40)
  // slot 0x64 DrawRectangleInCurrentUiContext inherited unchanged (0x48c750)
  // slot 0x65 AssertMcAppUILine1914 inherited unchanged (0x48c7a0)
  // slot 0x66 AssertMcAppUILine1922 inherited unchanged (0x48c7d0)
  // slot 0x67 CtrlSlot103_SubtractPosAndDispatchSlot19C_Impl inherited unchanged (0x48bac0)
  // slot 0x68 DispatchPictureResourceCommand inherited unchanged (0x48e850)
  // slot 0x69 BuildInsetContentRect inherited unchanged (0x48e980)
  // slot 0x6a AssertCityProductionGlobalStateInitialized inherited unchanged (0x429470)
  // slot 0x6b NoOpUiViewSlotHandler inherited unchanged (0x48e9c0)
  // slot 0x6c OrphanRetStub_00487a00 inherited unchanged (0x48e9e0)
  // slot 0x6d SetTextStyleAndMaybeRefresh inherited unchanged (0x48e7d0)
  // slot 0x6e SetTextColorAndMaybeRefresh inherited unchanged (0x48e7a0)
  // slot 0x6f LogUnhandledDialogMethodAndReturnFalse inherited unchanged (0x4294a0)
  // slot 0x70 HiliteState inherited unchanged (0x48e810)
  // slot 0x71 ResetPictureResourceEntry inherited unchanged (0x48f520)
  // slot 0x72 SetPictureResourceIdAndRefresh inherited unchanged (0x48f570)
  virtual void PoseOfferSheet(short sourceNation, short targetNation, short proposedAmount,
                              short maxAmount, short commodityType); // slot 0x73 0x5bea00
  // TPicture's own slice ends at 0x90 (ASSERT_SIZE); RTTI oracle confirms
  // sizeof(TOfferDeskPicture) == 0xa8. The ctor initializes the selection flag and
  // resolves the accept/reject controls during DoPostCreate().
  // 0x90/0x92/0x96 identified from RefreshSelectedNationOrderCompatibilityInfo (hedged
  // names); 0x94/0x98/0x9a/0x9d identified from CreateNextTradeCommandAndFormatPrompt
  // (0x5c04f0): all four feed TTradeMgr::DispatchProposalAmountSlot60's arguments or the
  // quantity-validation / error-detail branches there.
  short sourceNationSlot90; // +0x90 selected/source major nation slot (indexes g_apNationStates)
  short targetNationSlot92; // +0x92 trade-target nation slot (index into the 23-nation tables)
  short maxAmount94;     // +0x94 upper bound passed to DispatchProposalAmountSlot60's maxAmount arg
  short commodityType96; // +0x96 commodity/need-type index 0..0x16 (0/1 = Cotton+Wool pair)
  // +0x98 current proposed quantity, refreshed from the 'purc' TNumberText control's window
  // text each time CreateNextTradeCommandAndFormatPrompt runs; forced to 0 on a 'reje' action.
  short proposedAmount98;
  // +0x9a the 'clus'->'nomo' child control's IsTradeControlAtMinimum() result, forwarded as
  // DispatchProposalAmountSlot60's emitEventFlag arg (skip the diplomacy event when the
  // quantity control was never moved off its floor).
  short suppressEventFlag9a;
  unsigned char pad9c;
  // +0x9d gates the out-of-range quantity error message: concise (GetString group 0x2740
  // index 0x10) when set, else a detailed bracket-expanded "max is <N>" message.
  unsigned char detailedErrorFlag9d;
  bool selectionActive9e;
  unsigned char pad9f;
  TControl* acceptButtonA0;
  TControl* rejectButtonA4;

  TOfferDeskPicture();

  // Rebuilds the 'info' static-text control's trade-compatibility text for the selected
  // source nation / target nation / commodity, at the current help detail level.
  // 0x005bf930, __thiscall (non-virtual helper called by slot 0x73 and HandleEvent).
  void RefreshSelectedNationOrderCompatibilityInfo();

  // Reads the 'clus'/'nomo'/'purc' child controls, validates the proposed quantity against
  // the 'purc' TNumberText's own maximumValue -- showing an out-of-range error and
  // re-selecting the field's text on failure -- then on success dispatches the trade
  // proposal through TTradeMgr, resets the accept/reject buttons, notifies the toolbar of
  // the new source-nation move value, and (unless mid-turn-processing) queues a new
  // TNextTradeCommand onto the UI root controller. `actionCode` is the triggering button's
  // FourCC tag ('acce'/'reje'/etc.); 'reje' forces the proposed quantity to 0.
  void CreateNextTradeCommandAndFormatPrompt(int actionCode); // 0x5c04f0

  // Updates the trade-desk selection state (activating/deactivating) and refreshes the UI
  // to match. 0x5c09d0, __thiscall.
  void UpdateTradeSelectionStateAndRefreshUiIfChanged(int activate);
};

ASSERT_SIZE(TOfferDeskPicture, 0xa8);

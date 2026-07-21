#pragma once

#include "game/TTEView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006406d8
class TDeluxeText : public TTEView {
public:
  DECLARE_DYNCREATE(TDeluxeText)
  virtual ~TDeluxeText() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x48b0b0)
  // slot 0x08 ShallowClone inherited unchanged (0x48fc00)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a GetBoolSlot28 inherited unchanged (0x48a240)
  // slot 0x0b SetControlValue inherited unchanged (0x48a260)
  // slot 0x0c QueryStepValue inherited unchanged (0x48a2c0)
  // slot 0x0d DispatchQueuedUiCommandAndRelease inherited unchanged (0x48a3b0)
  // slot 0x0e DispatchUiSelectionToHandler inherited unchanged (0x48a3f0)
  // slot 0x0f HandleEvent inherited unchanged (0x48e710)
  // slot 0x10 DispatchUiCommandToHandler inherited unchanged (0x48a2e0)
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
  virtual void DoPostCreate(int arg) override; // slot 0x37 0x5b6060
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
  virtual void ApplyRectSlot110(RECT* rectBuffer) override; // slot 0x44 0x5b6170
  // slot 0x45 vmethod_0048 inherited unchanged (0x48b860)
  // slot 0x46 HandleMouseDown inherited unchanged (0x48c450)
  // slot 0x47 BeginMouseCaptureAndStartRepeatTimer inherited unchanged (0x48e640)
  // slot 0x48 HandleMouseUp inherited unchanged (0x48c590)
  // slot 0x49 vmethod_0071 inherited unchanged (0x427240)
  // slot 0x4a QueryContentBounds inherited unchanged (0x427260)
  // slot 0x4b QueryBounds inherited unchanged (0x427290)
  // slot 0x4c TranslateRectToWindow inherited unchanged (0x4272d0)
  // slot 0x4d vmethod_0076 inherited unchanged (0x48ba80)
  // slot 0x4e vmethod_0078 inherited unchanged (0x48ba40)
  // slot 0x4f InvokeSlot13C inherited unchanged (0x48b700)
  // slot 0x50 OffsetRectByControlPosition inherited unchanged (0x48bb00)
  // slot 0x51 UpdateAfterBitmapChange inherited unchanged (0x427330)
  // slot 0x52 CtrlSlot82_TransformPointViaSlot138_Impl inherited unchanged (0x48bb60)
  // slot 0x53 CtrlSlot83_TransformRectViaSlot148_Impl inherited unchanged (0x48bbb0)
  // slot 0x54 CtrlSlot84_AddControlPosToPoint_Impl inherited unchanged (0x48bc30)
  // slot 0x55 CtrlSlot85_OffsetRectByCachedPos_Impl inherited unchanged (0x48bc60)
  // slot 0x56 CtrlSlot86_GetAbsolutePosition_Impl inherited unchanged (0x48bb30)
  // slot 0x57 GetDrawableQDRect inherited unchanged (0x429410)
  // slot 0x58 GetQDExtent inherited unchanged (0x48bce0)
  // slot 0x59 VTableSlot59 inherited unchanged (0x48b2d0)
  // slot 0x5a UpdateRectCacheIfChangedAndInvalidateCityDialog inherited unchanged (0x48c380)
  // slot 0x5b VTableSlot5B inherited unchanged (0x48e940)
  // slot 0x5c vmethod_0092 inherited unchanged (0x48abe0)
  // slot 0x5d DetachUiElementFromOwnerListAndClearBackref inherited unchanged (0x48ae60)
  // slot 0x5e CtrlSlot94_GetWordField54_Impl inherited unchanged (0x48c970)
  // slot 0x5f ContainsMouse inherited unchanged (0x48c990)
  // slot 0x60 GoAwayByUser inherited unchanged (0x48c9e0)
  // slot 0x61 MoveByUser inherited unchanged (0x48ca00)
  // slot 0x62 ResizeByUser inherited unchanged (0x48ca20)
  // slot 0x63 ZoomByUser inherited unchanged (0x48ca40)
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
  // slot 0x71 SetTextAlignmentAndMaybeRefresh inherited unchanged (0x48ff70)
  // slot 0x72 SetTextAndMaybeRefresh inherited unchanged (0x48fe60)
  // slot 0x73 SetTextFromStringResource inherited unchanged (0x48fed0)
  // slot 0x74 CopyTextTo inherited unchanged (0x4294d0)
  // slot 0x75 DrawTextAligned inherited unchanged (0x4900a0)
  virtual void SetSelectedFlagAndState(char param_1); // slot 0x76 0x5b60a0
  // Loads the localized UI string `stringId` from the module cache and assigns it
  // via UpdateTextEntrySharedStringAndMaybeNotify (verified 1-arg thiscall, RET 4;
  // the old InitializeTechHistoryViewTitleAndMapKeyControls name was junk and the
  // declaration had dropped the argument).
  virtual void SetTextFromUiStringResourceId(short stringId); // slot 0x77 0x5b60d0
  virtual void BuildAndApplyTextStyleDescriptor(int unused, int pointSize,
                                                int themeCode); // slot 0x78 0x5b62e0
  // styleDescriptor points at the packed text-style record built by BuildUiTextStyleDescriptor;
  // its styleRef6 is also cached in the deluxe-text slice at +0x98.
  virtual void ApplyTextStyleDescriptorAndMaybeRefresh(TUiTextStyleDescriptor* styleDescriptor,
                                                       int refreshFlag); // slot 0x79 0x5b62a0
  virtual void BuildCityViewProductionControls_Impl(short codeGroup,
                                                    short stringIndex); // slot 0x7a 0x5b64e0
  virtual void UpdateTextEntrySharedStringAndMaybeNotify(CString* text,
                                                         char notifyFlag); // slot 0x7b 0x5b64a0
  virtual void UpdateTextEntrySharedString(CString* text);                 // slot 0x7c 0x5b6480
  // Assign the entry text from a raw char pointer; the length argument is accepted but
  // unused by the body (ret 8 proves the two-arg shape; renamed from the provisional
  // Helper_Uses_ConstructSharedStringFromCStrOrResourceId_At005b6360).
  virtual void SetTextEntryFromChars(const char* textChars,
                                     int textLength); // slot 0x7d 0x5b6360
  // Real return is undefined4 (packs two shorts via CONCAT22) with an
  // unresolved measure-width helper (func_0x004065e1) feeding it — kept as
  // `undefined` rather than guessing a real return type.
  virtual int
  RecenterTextFromMeasuredWidthAndMaybeInvalidate(char refreshNow); // slot 0x7e 0x5b63e0
  // field94/field95/padding96 moved to the base TTEView (its RTTI object size is
  // 0x98; TDeluxeText's own fields start at 0x98 — see TTEView.h).
  int textColor98;            // +0x98
  int shadowTextColor9C;      // +0x9c
  bool dropShadowEnabledA0;   // +0xa0
  unsigned char paddingA1[3]; // +0xa1

  TDeluxeText();

  // Mac-style second-phase init: forwards to TTEView::ConstructTTEViewBaseState with the
  // fixed (0, ..., 5, 5, ..., 0, 1) filler args, copies style->textColor into
  // textColor98, and clears the selected flag via the slot-0x76 virtual.
  // 0x5b5ff0, __thiscall, RET 0x18.
  void ConstructTDeluxeTextBaseState(TView* panel, int* offsetLayout, int* sizeLayout,
                                     RECT* insetRect, TUiTextStyleDescriptor* style,
                                     short styleWord90);
};

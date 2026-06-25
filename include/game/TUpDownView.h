#pragma once

#include "game/TControl.h"
#include "game/mfc.h"

// TODO(manifest): describe TUpDownView and its role. Base edge (TControl) recovered from RTTI CRuntimeClass chain: TUpDownView -> TControl -> TView -> TEventHandler -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00663770
class TUpDownView : public TControl {
public:
// === BEGIN GENERATED DECLS (TUpDownView) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x583d30
  virtual ~TUpDownView(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x48b0b0)
  // slot 0x08 ShallowClone inherited unchanged (0x435760)
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
  // slot 0x13 CanHandleCityDialogActionFalse inherited unchanged (0x48a480)
  // slot 0x14 GetCityDialogValueDword10 inherited unchanged (0x415d50)
  // slot 0x15 SetCityDialogValueDword10 inherited unchanged (0x415d70)
  // slot 0x16 OwnerPanel inherited unchanged (0x48b180)
  // slot 0x17 vmethod_0023 inherited unchanged (0x48a530)
  // slot 0x18 vmethod_0024 inherited unchanged (0x48a550)
  // slot 0x19 vmethod_0025 inherited unchanged (0x48a690)
  // slot 0x1a vmethod_0026 inherited unchanged (0x48a6b0)
  // slot 0x1b HandleCityProductionNoOp inherited unchanged (0x48a650)
  // slot 0x1c DispatchUiCommand19ToParent inherited unchanged (0x48a6d0)
  // slot 0x1d DispatchCityProductionAction1A inherited unchanged (0x48a670)
  // slot 0x1e DispatchCityProductionAction1B inherited unchanged (0x48a6f0)
  // slot 0x1f ActivateCityProductionViewIfAllowed inherited unchanged (0x48a570)
  // slot 0x20 vmethod_0080 inherited unchanged (0x48a5e0)
  // slot 0x21 vmethod_0081 inherited unchanged (0x48a710)
  // slot 0x22 vmethod_0032 inherited unchanged (0x48a500)
  // slot 0x23 vmethod_0033 inherited unchanged (0x48a4a0)
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
  // slot 0x44 ApplyRectSlot110 inherited unchanged (0x430bf0)
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
  virtual void DispatchPictureResourceCommand(int nEventType, void * pEventSender, void * pEventDataA, void * pEventDataB) override; // slot 0x68 0x583dd0
  // slot 0x69 DeserializeCityProductionQueueCommand inherited unchanged (0x48e980)
  // slot 0x6a AssertCityProductionGlobalStateInitialized inherited unchanged (0x429470)
  // slot 0x6b NoOpUiViewSlotHandler inherited unchanged (0x48e9c0)
  // slot 0x6c OrphanRetStub_00487a00 inherited unchanged (0x48e9e0)
  // slot 0x6d SetCityProductionDialogPictureRectAndMaybeRefresh inherited unchanged (0x48e7d0)
  // slot 0x6e SetControlPictureEntryAndMaybeRefresh inherited unchanged (0x48e7a0)
  // slot 0x6f LogUnhandledDialogMethodAndReturnFalse inherited unchanged (0x4294a0)
  // slot 0x70 SetControlStateFlagAndMaybeRefresh inherited unchanged (0x48e810)
// === END GENERATED DECLS (TUpDownView) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TUpDownView 0xCTOR`).

  TUpDownView();
};

// === BEGIN GENERATED (TUpDownView) — refreshed by `just gen-class TUpDownView`; do not hand-edit ===
// clang-format off
// vtable @ 0x00663770 (113 slots), object size 0x88, base TControl
//   slot 0x00  byte 0x00  0x00583d30  override  GetTEventHandlerClassNamePointer
//   slot 0x01  byte 0x04  0x00583d80  override  VTableSlot01
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x0048b0b0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x08  byte 0x20  0x00435760  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0048a240  inherited GetTEventHandlerClassNamePointer
//   slot 0x0b  byte 0x2c  0x0048a260  inherited ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x0c  byte 0x30  0x0048a2c0  inherited UpdateControlCachedIntFromWindowText
//   slot 0x0d  byte 0x34  0x0048a3b0  inherited OrphanRetStub_0059add0
//   slot 0x0e  byte 0x38  0x0048a3f0  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x0f  byte 0x3c  0x0048e710  inherited ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x10  byte 0x40  0x0048a2e0  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x11  byte 0x44  0x0048a310  inherited VTableSlot11
//   slot 0x12  byte 0x48  0x0048a380  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x13  byte 0x4c  0x0048a480  inherited VTableSlot13
//   slot 0x14  byte 0x50  0x00415d50  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x15  byte 0x54  0x00415d70  inherited VTableSlot15
//   slot 0x16  byte 0x58  0x0048b180  inherited SetForeignMinisterReadyFlag14
//   slot 0x17  byte 0x5c  0x0048a530  inherited VTableSlot17
//   slot 0x18  byte 0x60  0x0048a550  inherited SetForeignMinisterReadyFlag14
//   slot 0x19  byte 0x64  0x0048a690  inherited VTableSlot19
//   slot 0x1a  byte 0x68  0x0048a6b0  inherited GetTEventHandlerClassNamePointer
//   slot 0x1b  byte 0x6c  0x0048a650  inherited VTableSlot1B
//   slot 0x1c  byte 0x70  0x0048a6d0  inherited GetTEventHandlerClassNamePointer
//   slot 0x1d  byte 0x74  0x0048a670  inherited VTableSlot1D
//   slot 0x1e  byte 0x78  0x0048a6f0  inherited GetTEventHandlerClassNamePointer
//   slot 0x1f  byte 0x7c  0x0048a570  inherited VTableSlot1F
//   slot 0x20  byte 0x80  0x0048a5e0  inherited GetTEventHandlerClassNamePointer
//   slot 0x21  byte 0x84  0x0048a710  inherited VTableSlot21
//   slot 0x22  byte 0x88  0x0048a500  inherited GetTEventHandlerClassNamePointer
//   slot 0x23  byte 0x8c  0x0048a4a0  inherited VTableSlot23
//   slot 0x24  byte 0x90  0x0048a4d0  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x25  byte 0x94  0x0048afd0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x26  byte 0x98  0x0048af80  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x27  byte 0x9c  0x0048c820  inherited GetTEventHandlerClassNamePointer
//   slot 0x28  byte 0xa0  0x0048c890  inherited GetTEventHandlerClassNamePointer
//   slot 0x29  byte 0xa4  0x0048b1c0  inherited ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x2a  byte 0xa8  0x0048b070  inherited UpdateControlCachedIntFromWindowText
//   slot 0x2b  byte 0xac  0x00427200  inherited OrphanRetStub_0059add0
//   slot 0x2c  byte 0xb0  0x0048c250  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x2d  byte 0xb4  0x0048c1c0  inherited OrphanRetStub_0059add0
//   slot 0x2e  byte 0xb8  0x0048c1e0  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x2f  byte 0xbc  0x00429450  inherited VTableSlot2F
//   slot 0x30  byte 0xc0  0x0048b4b0  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x31  byte 0xc4  0x0048ab90  inherited VTableSlot31
//   slot 0x32  byte 0xc8  0x0048b690  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x33  byte 0xcc  0x0048c000  inherited VTableSlot33
//   slot 0x34  byte 0xd0  0x0048c050  inherited SetForeignMinisterReadyFlag14
//   slot 0x35  byte 0xd4  0x0048c080  inherited SetForeignMinisterReadyFlag14
//   slot 0x36  byte 0xd8  0x0048aaf0  inherited SetForeignMinisterReadyFlag14
//   slot 0x37  byte 0xdc  0x0048ab70  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x38  byte 0xe0  0x0048abc0  inherited GetTEventHandlerClassNamePointer
//   slot 0x39  byte 0xe4  0x0048b6d0  inherited VTableSlot39
//   slot 0x3a  byte 0xe8  0x0048b1a0  inherited GetTEventHandlerClassNamePointer
//   slot 0x3b  byte 0xec  0x0048b200  inherited VTableSlot3B
//   slot 0x3c  byte 0xf0  0x0048b250  inherited GetTEventHandlerClassNamePointer
//   slot 0x3d  byte 0xf4  0x0048b3f0  inherited VTableSlot3D
//   slot 0x3e  byte 0xf8  0x0048b770  inherited GetTEventHandlerClassNamePointer
//   slot 0x3f  byte 0xfc  0x00427220  inherited VTableSlot3F
//   slot 0x40  byte 0x100  0x0048b7b0  inherited GetTEventHandlerClassNamePointer
//   slot 0x41  byte 0x104  0x0048b7e0  inherited VTableSlot41
//   slot 0x42  byte 0x108  0x0048b810  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x43  byte 0x10c  0x0048b8d0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x44  byte 0x110  0x00430bf0  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x45  byte 0x114  0x0048b860  inherited GetTEventHandlerClassNamePointer
//   slot 0x46  byte 0x118  0x0048c450  inherited SetForeignMinisterReadyFlag14
//   slot 0x47  byte 0x11c  0x0048e640  inherited VTableSlot47
//   slot 0x48  byte 0x120  0x0048c590  inherited UpdateControlCachedIntFromWindowText
//   slot 0x49  byte 0x124  0x00427240  inherited OrphanRetStub_0059add0
//   slot 0x4a  byte 0x128  0x00427260  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x4b  byte 0x12c  0x00427290  inherited OrphanRetStub_0059add0
//   slot 0x4c  byte 0x130  0x004272d0  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x4d  byte 0x134  0x0048ba80  inherited VTableSlot4D
//   slot 0x4e  byte 0x138  0x0048ba40  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x4f  byte 0x13c  0x0048b700  inherited VTableSlot4F
//   slot 0x50  byte 0x140  0x0048bb00  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x51  byte 0x144  0x00427330  inherited VTableSlot51
//   slot 0x52  byte 0x148  0x0048bb60  inherited SetForeignMinisterReadyFlag14
//   slot 0x53  byte 0x14c  0x0048bbb0  inherited SetForeignMinisterReadyFlag14
//   slot 0x54  byte 0x150  0x0048bc30  inherited SetForeignMinisterReadyFlag14
//   slot 0x55  byte 0x154  0x0048bc60  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x56  byte 0x158  0x0048bb30  inherited GetTEventHandlerClassNamePointer
//   slot 0x57  byte 0x15c  0x00429410  inherited VTableSlot57
//   slot 0x58  byte 0x160  0x0048bce0  inherited GetTEventHandlerClassNamePointer
//   slot 0x59  byte 0x164  0x0048b2d0  inherited VTableSlot59
//   slot 0x5a  byte 0x168  0x0048c380  inherited GetTEventHandlerClassNamePointer
//   slot 0x5b  byte 0x16c  0x0048e940  inherited VTableSlot5B
//   slot 0x5c  byte 0x170  0x0048abe0  inherited GetTEventHandlerClassNamePointer
//   slot 0x5d  byte 0x174  0x0048ae60  inherited VTableSlot5D
//   slot 0x5e  byte 0x178  0x0048c970  inherited GetTEventHandlerClassNamePointer
//   slot 0x5f  byte 0x17c  0x0048c990  inherited VTableSlot5F
//   slot 0x60  byte 0x180  0x0048c9e0  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x61  byte 0x184  0x0048ca00  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x62  byte 0x188  0x0048ca20  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x63  byte 0x18c  0x0048ca40  inherited GetTEventHandlerClassNamePointer
//   slot 0x64  byte 0x190  0x0048c750  inherited SetForeignMinisterReadyFlag14
//   slot 0x65  byte 0x194  0x0048c7a0  inherited ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x66  byte 0x198  0x0048c7d0  inherited UpdateControlCachedIntFromWindowText
//   slot 0x67  byte 0x19c  0x0048bac0  inherited OrphanRetStub_0059add0
//   slot 0x68  byte 0x1a0  0x00583dd0  override  QueueCityRecruitmentSupportCommandsIfDeficit
//   slot 0x69  byte 0x1a4  0x0048e980  inherited DeserializeCityProductionQueueCommand
//   slot 0x6a  byte 0x1a8  0x00429470  inherited OrphanRetStub_0059add0
//   slot 0x6b  byte 0x1ac  0x0048e9c0  inherited NoOpUiViewSlotHandler
//   slot 0x6c  byte 0x1b0  0x0048e9e0  inherited OrphanRetStub_00487a00
//   slot 0x6d  byte 0x1b4  0x0048e7d0  inherited SetCityProductionDialogPictureRectAndMaybeRefresh
//   slot 0x6e  byte 0x1b8  0x0048e7a0  inherited SetControlPictureEntryAndMaybeRefresh
//   slot 0x6f  byte 0x1bc  0x004294a0  inherited LogUnhandledDialogMethodAndReturnFalse
//   slot 0x70  byte 0x1c0  0x0048e810  inherited SetControlStateFlagAndMaybeRefresh
// object size 0x88 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TUpDownView) ===

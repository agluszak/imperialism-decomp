#pragma once

#include "game/TControl.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x64b0c0
class TCluster : public TControl {
public:
// === BEGIN GENERATED DECLS (TCluster) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TCluster)
  virtual ~TCluster(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x48b0b0)
  virtual TObject* ShallowClone() override; // slot 0x08 0x4918a0
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a GetBoolSlot28 inherited unchanged (0x48a240)
  // slot 0x0b SetControlValue inherited unchanged (0x48a260)
  // slot 0x0c QueryStepValue inherited unchanged (0x48a2c0)
  // slot 0x0d DispatchQueuedUiCommandAndRelease inherited unchanged (0x48a3b0)
  // slot 0x0e DispatchUiSelectionToHandler inherited unchanged (0x48a3f0)
  virtual void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override; // slot 0x0f 0x00491650
  // slot 0x10 DispatchEvent inherited unchanged (0x48a2e0)
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
  // slot 0x69 DeserializeCityProductionQueueCommand inherited unchanged (0x48e980)
  // slot 0x6a AssertCityProductionGlobalStateInitialized inherited unchanged (0x429470)
  // slot 0x6b NoOpUiViewSlotHandler inherited unchanged (0x48e9c0)
  // slot 0x6c OrphanRetStub_00487a00 inherited unchanged (0x48e9e0)
  // slot 0x6d SetCityProductionDialogPictureRectAndMaybeRefresh inherited unchanged (0x48e7d0)
  // slot 0x6e SetControlPictureEntryAndMaybeRefresh inherited unchanged (0x48e7a0)
  // slot 0x6f LogUnhandledDialogMethodAndReturnFalse inherited unchanged (0x4294a0)
  // slot 0x70 SetControlStateFlagAndMaybeRefresh inherited unchanged (0x48e810)
  virtual int GetField84(); // slot 0x71 0x491770
  virtual void SetControlClassAndRefresh(int classState); // slot 0x72 0x491790 (1 arg; RET 4)
// === END GENERATED DECLS (TCluster) ===
  int field84;

  TCluster();
};

// === BEGIN GENERATED (TCluster) — refreshed by `just gen-class TCluster`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064b0c0 (309 slots), object size 0x88, base TControl
//   slot 0x00  byte 0x00  0x004913e0  override  GetTEventHandlerClassNamePointer
//   slot 0x01  byte 0x04  0x00491480  override  VTableSlot01
//   slot 0x02  byte 0x08  0x00485e90  inherited GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  inherited ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  inherited GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x00485f70  inherited OrphanRetStub_0059ad90
//   slot 0x06  byte 0x18  0x00485f90  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x07  byte 0x1c  0x0048b0b0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x08  byte 0x20  0x004918a0  override  OrphanCallChain_C11_I88_004874b0
//   slot 0x09  byte 0x24  0x00415ce0  inherited OrphanRetStub_0059add0
//   slot 0x0a  byte 0x28  0x0048a240  inherited GetTEventHandlerClassNamePointer
//   slot 0x0b  byte 0x2c  0x0048a260  inherited ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x0c  byte 0x30  0x0048a2c0  inherited UpdateControlCachedIntFromWindowText
//   slot 0x0d  byte 0x34  0x0048a3b0  inherited OrphanRetStub_0059add0
//   slot 0x0e  byte 0x38  0x0048a3f0  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x0f  byte 0x3c  0x00491650  override  OrphanRetStub_0059add0
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
//   slot 0x68  byte 0x1a0  0x0048e850  inherited QueueCityRecruitmentSupportCommandsIfDeficit
//   slot 0x69  byte 0x1a4  0x0048e980  inherited DeserializeCityProductionQueueCommand
//   slot 0x6a  byte 0x1a8  0x00429470  inherited OrphanRetStub_0059add0
//   slot 0x6b  byte 0x1ac  0x0048e9c0  inherited NoOpUiViewSlotHandler
//   slot 0x6c  byte 0x1b0  0x0048e9e0  inherited OrphanRetStub_00487a00
//   slot 0x6d  byte 0x1b4  0x0048e7d0  inherited SetCityProductionDialogPictureRectAndMaybeRefresh
//   slot 0x6e  byte 0x1b8  0x0048e7a0  inherited SetControlPictureEntryAndMaybeRefresh
//   slot 0x6f  byte 0x1bc  0x004294a0  inherited LogUnhandledDialogMethodAndReturnFalse
//   slot 0x70  byte 0x1c0  0x0048e810  inherited SetControlStateFlagAndMaybeRefresh
//   slot 0x71  byte 0x1c4  0x00491770  new       OrphanTiny_GetDwordEcxOffset_84_00491770
//   slot 0x72  byte 0x1c8  0x00491790  new       OrphanCallChain_C2_I51_00491790
//   slot 0x73  byte 0x1cc  0x00000000  null      (null)
//   slot 0x74  byte 0x1d0  0x00000000  null      (null)
//   slot 0x75  byte 0x1d4  0x00000000  null      (null)
//   slot 0x76  byte 0x1d8  0x00000000  null      (null)
//   slot 0x77  byte 0x1dc  0x00000000  null      (null)
//   slot 0x78  byte 0x1e0  0x00000000  null      (null)
//   slot 0x79  byte 0x1e4  0x00000000  null      (null)
//   slot 0x7a  byte 0x1e8  0x00000000  null      (null)
//   slot 0x7b  byte 0x1ec  0x00000000  null      (null)
//   slot 0x7c  byte 0x1f0  0x00000000  null      (null)
//   slot 0x7d  byte 0x1f4  0x00000000  null      (null)
//   slot 0x7e  byte 0x1f8  0x00000000  null      (null)
//   slot 0x7f  byte 0x1fc  0x00000000  null      (null)
//   slot 0x80  byte 0x200  0x00000000  null      (null)
//   slot 0x81  byte 0x204  0x00000000  null      (null)
//   slot 0x82  byte 0x208  0x00000000  null      (null)
//   slot 0x83  byte 0x20c  0x00000000  null      (null)
//   slot 0x84  byte 0x210  0x00000000  null      (null)
//   slot 0x85  byte 0x214  0x00000000  null      (null)
//   slot 0x86  byte 0x218  0x00000000  null      (null)
//   slot 0x87  byte 0x21c  0x00000000  null      (null)
//   slot 0x88  byte 0x220  0x00000000  null      (null)
//   slot 0x89  byte 0x224  0x00000000  null      (null)
//   slot 0x8a  byte 0x228  0x00485e20  new       GetRuntimeClass
//   slot 0x8b  byte 0x22c  0x00491b10  new       WrapperFor_FreeHeapBufferIfNotNull_At00491b10
//   slot 0x8c  byte 0x230  0x00485e90  new       GetTTaskClassNamePointer
//   slot 0x8d  byte 0x234  0x00412bf0  new       ConstructTTaskBaseState
//   slot 0x8e  byte 0x238  0x00412c10  new       GetTEventHandlerClassNamePointer
//   slot 0x8f  byte 0x23c  0x00485f70  new       OrphanRetStub_0059ad90
//   slot 0x90  byte 0x240  0x00485f90  new       OrphanCallChain_C11_I88_004874b0
//   slot 0x91  byte 0x244  0x004798b0  new       QueueCityRecruitmentSupportCommandsIfDeficit
//   slot 0x92  byte 0x248  0x004798d0  new       DeserializeCityProductionQueueCommand
//   slot 0x93  byte 0x24c  0x00415ce0  new       OrphanRetStub_0059add0
//   slot 0x94  byte 0x250  0x00491c80  new       OrphanCallChain_C1_I17_00491c80
//   slot 0x95  byte 0x254  0x00491d80  new       InvokeDialogFactoryFromPacket
//   slot 0x96  byte 0x258  0x00491cc0  new       RunRegisteredDialogFactoriesByEventCode
//   slot 0x97  byte 0x25c  0x00000000  null      (null)
//   slot 0x98  byte 0x260  0x00000000  null      (null)
//   slot 0x99  byte 0x264  0x00000000  null      (null)
//   slot 0x9a  byte 0x268  0x00606fba  new       SetForeignMinisterReadyFlag14
//   slot 0x9b  byte 0x26c  0x00492980  new       WrapperFor_FreeHeapBufferIfNotNull_At00492980
//   slot 0x9c  byte 0x270  0x004927e0  new       SerializeRecordList_0x0C_WithBlockPool_D
//   slot 0x9d  byte 0x274  0x00412bf0  new       ConstructTTaskBaseState
//   slot 0x9e  byte 0x278  0x00412c10  new       GetTEventHandlerClassNamePointer
//   slot 0x9f  byte 0x27c  0x00000000  null      (null)
//   slot 0xa0  byte 0x280  0x00491f90  new       GetTEventHandlerClassNamePointer
//   slot 0xa1  byte 0x284  0x00492110  new       VTableSlotA1
//   slot 0xa2  byte 0x288  0x00485e90  new       GetTTaskClassNamePointer
//   slot 0xa3  byte 0x28c  0x00412bf0  new       ConstructTTaskBaseState
//   slot 0xa4  byte 0x290  0x00412c10  new       GetTEventHandlerClassNamePointer
//   slot 0xa5  byte 0x294  0x00485f70  new       OrphanRetStub_0059ad90
//   slot 0xa6  byte 0x298  0x00485f90  new       OrphanCallChain_C11_I88_004874b0
//   slot 0xa7  byte 0x29c  0x0048e2a0  new       VTableSlotA7
//   slot 0xa8  byte 0x2a0  0x00492d80  new       OrphanCallChain_C11_I88_004874b0
//   slot 0xa9  byte 0x2a4  0x00415ce0  new       OrphanRetStub_0059add0
//   slot 0xaa  byte 0x2a8  0x0048a240  new       GetTEventHandlerClassNamePointer
//   slot 0xab  byte 0x2ac  0x0048a260  new       ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0xac  byte 0x2b0  0x0048a2c0  new       UpdateControlCachedIntFromWindowText
//   slot 0xad  byte 0x2b4  0x0048a3b0  new       OrphanRetStub_0059add0
//   slot 0xae  byte 0x2b8  0x0048a3f0  new       OrphanCallChain_C11_I88_004874b0
//   slot 0xaf  byte 0x2bc  0x0048dd50  new       OrphanRetStub_0059add0
//   slot 0xb0  byte 0x2c0  0x0048dd10  new       OrphanCallChain_C11_I88_004874b0
//   slot 0xb1  byte 0x2c4  0x0048a310  new       VTableSlotB1
//   slot 0xb2  byte 0x2c8  0x0048a380  new       OrphanTiny_ReturnZero_0048a730
//   slot 0xb3  byte 0x2cc  0x0048a480  new       VTableSlotB3
//   slot 0xb4  byte 0x2d0  0x00415d50  new       OrphanTiny_ReturnZero_0048a730
//   slot 0xb5  byte 0x2d4  0x00415d70  new       VTableSlotB5
//   slot 0xb6  byte 0x2d8  0x00492cc0  new       OrphanTiny_ReturnZero_0048a730
//   slot 0xb7  byte 0x2dc  0x0048a530  new       VTableSlotB7
//   slot 0xb8  byte 0x2e0  0x0048a550  new       SetForeignMinisterReadyFlag14
//   slot 0xb9  byte 0x2e4  0x0048a690  new       VTableSlotB9
//   slot 0xba  byte 0x2e8  0x0048a6b0  new       GetTEventHandlerClassNamePointer
//   slot 0xbb  byte 0x2ec  0x0048a650  new       VTableSlotBB
//   slot 0xbc  byte 0x2f0  0x0048a6d0  new       GetTEventHandlerClassNamePointer
//   slot 0xbd  byte 0x2f4  0x0048a670  new       VTableSlotBD
//   slot 0xbe  byte 0x2f8  0x0048a6f0  new       GetTEventHandlerClassNamePointer
//   slot 0xbf  byte 0x2fc  0x0048a570  new       VTableSlotBF
//   slot 0xc0  byte 0x300  0x0048a5e0  new       GetTEventHandlerClassNamePointer
//   slot 0xc1  byte 0x304  0x0048a710  new       VTableSlotC1
//   slot 0xc2  byte 0x308  0x0048a500  new       GetTEventHandlerClassNamePointer
//   slot 0xc3  byte 0x30c  0x0048a4a0  new       VTableSlotC3
//   slot 0xc4  byte 0x310  0x0048a4d0  new       OrphanCallChain_C11_I88_004874b0
//   slot 0xc5  byte 0x314  0x0048afd0  new       OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0xc6  byte 0x318  0x0048af80  new       OrphanCallChain_C11_I88_004874b0
//   slot 0xc7  byte 0x31c  0x0048de00  new       OrphanCallChain_C11_I88_004874b0
//   slot 0xc8  byte 0x320  0x00492330  new       GetTEventHandlerClassNamePointer
//   slot 0xc9  byte 0x324  0x0048b1c0  new       ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0xca  byte 0x328  0x0048b070  new       UpdateControlCachedIntFromWindowText
//   slot 0xcb  byte 0x32c  0x00427200  new       OrphanRetStub_0059add0
//   slot 0xcc  byte 0x330  0x0048c250  new       OrphanCallChain_C11_I88_004874b0
//   slot 0xcd  byte 0x334  0x0048c1c0  new       OrphanRetStub_0059add0
//   slot 0xce  byte 0x338  0x0048c1e0  new       OrphanTiny_ReturnZero_0048a730
//   slot 0xcf  byte 0x33c  0x00430bd0  new       VTableSlotCF
//   slot 0xd0  byte 0x340  0x0048b4b0  new       OrphanTiny_ReturnZero_0048a730
//   slot 0xd1  byte 0x344  0x0048ab90  new       VTableSlotD1
//   slot 0xd2  byte 0x348  0x0048b690  new       OrphanTiny_ReturnZero_0048a730
//   slot 0xd3  byte 0x34c  0x0048c000  new       VTableSlotD3
//   slot 0xd4  byte 0x350  0x0048c050  new       SetForeignMinisterReadyFlag14
//   slot 0xd5  byte 0x354  0x0048c080  new       SetForeignMinisterReadyFlag14
//   slot 0xd6  byte 0x358  0x0048aaf0  new       SetForeignMinisterReadyFlag14
//   slot 0xd7  byte 0x35c  0x0048ab70  new       OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0xd8  byte 0x360  0x0048abc0  new       GetTEventHandlerClassNamePointer
//   slot 0xd9  byte 0x364  0x0048b6d0  new       VTableSlotD9
//   slot 0xda  byte 0x368  0x00492ce0  new       GetTEventHandlerClassNamePointer
//   slot 0xdb  byte 0x36c  0x0048d980  new       ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0xdc  byte 0x370  0x0048b250  new       GetTEventHandlerClassNamePointer
//   slot 0xdd  byte 0x374  0x0048b3f0  new       VTableSlotDD
//   slot 0xde  byte 0x378  0x0048b770  new       GetTEventHandlerClassNamePointer
//   slot 0xdf  byte 0x37c  0x00427220  new       VTableSlotDF
//   slot 0xe0  byte 0x380  0x0048b7b0  new       GetTEventHandlerClassNamePointer
//   slot 0xe1  byte 0x384  0x0048b7e0  new       VTableSlotE1
//   slot 0xe2  byte 0x388  0x0048b810  new       OrphanCallChain_C11_I88_004874b0
//   slot 0xe3  byte 0x38c  0x0048b8d0  new       OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0xe4  byte 0x390  0x00430bf0  new       OrphanCallChain_C11_I88_004874b0
//   slot 0xe5  byte 0x394  0x0048b860  new       GetTEventHandlerClassNamePointer
//   slot 0xe6  byte 0x398  0x0048c450  new       SetForeignMinisterReadyFlag14
//   slot 0xe7  byte 0x39c  0x00430c10  new       ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0xe8  byte 0x3a0  0x0048c590  new       UpdateControlCachedIntFromWindowText
//   slot 0xe9  byte 0x3a4  0x00427240  new       OrphanRetStub_0059add0
//   slot 0xea  byte 0x3a8  0x00427260  new       OrphanCallChain_C11_I88_004874b0
//   slot 0xeb  byte 0x3ac  0x00427290  new       OrphanRetStub_0059add0
//   slot 0xec  byte 0x3b0  0x00492d40  new       GetTEventHandlerClassNamePointer
//   slot 0xed  byte 0x3b4  0x00492d20  new       VTableSlotED
//   slot 0xee  byte 0x3b8  0x00492d00  new       OrphanCallChain_C11_I88_004874b0
//   slot 0xef  byte 0x3bc  0x0048b700  new       VTableSlotEF
//   slot 0xf0  byte 0x3c0  0x0048bb00  new       OrphanTiny_ReturnZero_0048a730
//   slot 0xf1  byte 0x3c4  0x00427330  new       VTableSlotF1
//   slot 0xf2  byte 0x3c8  0x0048bb60  new       SetForeignMinisterReadyFlag14
//   slot 0xf3  byte 0x3cc  0x0048bbb0  new       SetForeignMinisterReadyFlag14
//   slot 0xf4  byte 0x3d0  0x0048bc30  new       SetForeignMinisterReadyFlag14
//   slot 0xf5  byte 0x3d4  0x0048bc60  new       OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0xf6  byte 0x3d8  0x0048bb30  new       GetTEventHandlerClassNamePointer
//   slot 0xf7  byte 0x3dc  0x00429410  new       VTableSlotF7
//   slot 0xf8  byte 0x3e0  0x0048bce0  new       GetTEventHandlerClassNamePointer
//   slot 0xf9  byte 0x3e4  0x0048b2d0  new       VTableSlotF9
//   slot 0xfa  byte 0x3e8  0x0048c380  new       GetTEventHandlerClassNamePointer
//   slot 0xfb  byte 0x3ec  0x0048c6d0  new       VTableSlotFB
//   slot 0xfc  byte 0x3f0  0x0048abe0  new       GetTEventHandlerClassNamePointer
//   slot 0xfd  byte 0x3f4  0x0048ae60  new       VTableSlotFD
//   slot 0xfe  byte 0x3f8  0x0048c970  new       GetTEventHandlerClassNamePointer
//   slot 0xff  byte 0x3fc  0x0048e1c0  new       VTableSlotFF
//   slot 0x100  byte 0x400  0x0048e1e0  new       GetTEventHandlerClassNamePointer
//   slot 0x101  byte 0x404  0x0048e210  new       VTableSlot101
//   slot 0x102  byte 0x408  0x0048e240  new       GetTEventHandlerClassNamePointer
//   slot 0x103  byte 0x40c  0x0048e270  new       VTableSlot103
//   slot 0x104  byte 0x410  0x0048c750  new       SetForeignMinisterReadyFlag14
//   slot 0x105  byte 0x414  0x0048c7a0  new       ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x106  byte 0x418  0x0048c7d0  new       UpdateControlCachedIntFromWindowText
//   slot 0x107  byte 0x41c  0x00492d60  new       OrphanRetStub_0059ad90
//   slot 0x108  byte 0x420  0x0048da40  new       OrphanLeaf_NoCall_Ins03_0048da40
//   slot 0x109  byte 0x424  0x0048d8a0  new       OrphanLeaf_NoCall_Ins05_0048d8a0
//   slot 0x10a  byte 0x428  0x0048da10  new       OrphanCallChain_C1_I08_0048da10
//   slot 0x10b  byte 0x42c  0x0048da60  new       ExecuteViewModalStateWithPushPopChain
//   slot 0x10c  byte 0x430  0x0048dc60  new       OrphanCallChain_C1_I08_0048dc60
//   slot 0x10d  byte 0x434  0x0048dc90  new       OrphanCallChain_C2_I12_0048dc90
//   slot 0x10e  byte 0x438  0x0048dcc0  new       OrphanLeaf_NoCall_Ins02_0048dcc0
//   slot 0x10f  byte 0x43c  0x0048dce0  new       AssertMcAppUILine2554
//   slot 0x110  byte 0x440  0x0048ddc0  new       OrphanCallChain_C2_I19_0048ddc0
//   slot 0x111  byte 0x444  0x0048e150  new       WrapperFor_CenterWindowWithinOwnerOrWorkArea_At0048e150
//   slot 0x112  byte 0x448  0x0048d8d0  new       AssertMcAppUILine2358
//   slot 0x113  byte 0x44c  0x0048d900  new       OrphanCallChain_C2_I39_0048d900
//   slot 0x114  byte 0x450  0x0048e120  new       OrphanCallChain_C2_I10_0048e120
//   slot 0x115  byte 0x454  0x0048d9c0  new       WrapperFor_SetWindowTextOrDelegateToOwner_At0048d9c0
//   slot 0x116  byte 0x458  0x0048d9f0  new       WrapperFor_FID_conflict_GetWindowTextA_At0048d9f0
//   slot 0x117  byte 0x45c  0x00492310  new       OrphanVtableAssignStub_00492310
//   slot 0x118  byte 0x460  0x00000000  null      (null)
//   slot 0x119  byte 0x464  0x00000000  null      (null)
//   slot 0x11a  byte 0x468  0x00000000  null      (null)
//   slot 0x11b  byte 0x46c  0x00000000  null      (null)
//   slot 0x11c  byte 0x470  0x00000000  null      (null)
//   slot 0x11d  byte 0x474  0x00000000  null      (null)
//   slot 0x11e  byte 0x478  0x00000000  null      (null)
//   slot 0x11f  byte 0x47c  0x00000000  null      (null)
//   slot 0x120  byte 0x480  0x00000000  null      (null)
//   slot 0x121  byte 0x484  0x00000000  null      (null)
//   slot 0x122  byte 0x488  0x00000000  null      (null)
//   slot 0x123  byte 0x48c  0x00000000  null      (null)
//   slot 0x124  byte 0x490  0x00000000  null      (null)
//   slot 0x125  byte 0x494  0x00000000  null      (null)
//   slot 0x126  byte 0x498  0x00000000  null      (null)
//   slot 0x127  byte 0x49c  0x00000000  null      (null)
//   slot 0x128  byte 0x4a0  0x00000000  null      (null)
//   slot 0x129  byte 0x4a4  0x00000000  null      (null)
//   slot 0x12a  byte 0x4a8  0x00000000  null      (null)
//   slot 0x12b  byte 0x4ac  0x00000000  null      (null)
//   slot 0x12c  byte 0x4b0  0x00000000  null      (null)
//   slot 0x12d  byte 0x4b4  0x00000000  null      (null)
//   slot 0x12e  byte 0x4b8  0x00000000  null      (null)
//   slot 0x12f  byte 0x4bc  0x00000000  null      (null)
//   slot 0x130  byte 0x4c0  0x00606fba  new       SetForeignMinisterReadyFlag14
//   slot 0x131  byte 0x4c4  0x00492950  new       WrapperFor_FreeHeapBufferIfNotNull_At00492950
//   slot 0x132  byte 0x4c8  0x00492670  new       SerializeRecordList_0x0C_WithBlockPool_C
//   slot 0x133  byte 0x4cc  0x00412bf0  new       ConstructTTaskBaseState
//   slot 0x134  byte 0x4d0  0x00412c10  new       GetTEventHandlerClassNamePointer
// object size 0x88 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TCluster) ===

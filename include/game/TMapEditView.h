#pragma once

#include "game/TMapDialog.h"
#include "game/mfc.h"

// TODO(manifest): describe TMapEditView and its role. Base edge (TMapDialog) recovered from RTTI CRuntimeClass chain: TMapEditView -> TMapDialog -> TWorldView -> TView -> TEventHandler -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x006594e8
class TMapEditView : public TMapDialog {
public:
// === BEGIN GENERATED DECLS (TMapEditView) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x51cc40
  virtual ~TMapEditView(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x519c90)
  // slot 0x08 ShallowClone inherited unchanged (0x48bfd0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a GetBoolSlot28 inherited unchanged (0x48a240)
  // slot 0x0b SetControlValue inherited unchanged (0x48a260)
  // slot 0x0c QueryStepValue inherited unchanged (0x48a2c0)
  // slot 0x0d vmethod_0013 inherited unchanged (0x48a3b0)
  // slot 0x0e vmethod_0014 inherited unchanged (0x48a3f0)
  // slot 0x0f ForwardEngineerDialogCommandToChildSlot40 inherited unchanged (0x5950b0)
  // slot 0x10 DispatchUiCommandToHandler inherited unchanged (0x48a2e0)
  // slot 0x11 vmethod_0017 inherited unchanged (0x48a310)
  virtual void ForwardParam(int param) override; // slot 0x12 0x51deb0
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
  // slot 0x2c HandleCursorHoverFallback inherited unchanged (0x595810)
  // slot 0x2d vmethod_0073 inherited unchanged (0x48c1c0)
  // slot 0x2e RefreshCityProductionViewStateFromContext inherited unchanged (0x48c1e0)
  // slot 0x2f QuerySelectedIndexSlotBC inherited unchanged (0x430bd0)
  // slot 0x30 InvalidateOffsetRegionUsingChildClipRect inherited unchanged (0x48b4b0)
  // slot 0x31 ForwardMapViewVirtualC4IfPresent inherited unchanged (0x48ab90)
  // slot 0x32 ValidateControlRectIfWindowActive inherited unchanged (0x48b690)
  // slot 0x33 EvaluateControlInputGate inherited unchanged (0x48c000)
  // slot 0x34 HasRenderableParentAndContent inherited unchanged (0x48c050)
  // slot 0x35 HandleCursorHoverSelectionByChildHitTestAndFallback inherited unchanged (0x5958b0)
  // slot 0x36 DispatchControlEventToChildrenAndSelf inherited unchanged (0x48aaf0)
  virtual void NoOpUiLifecycleHook(int arg) override; // slot 0x37 0x51cc60
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
  // slot 0x44 ApplyRectSlot110 inherited unchanged (0x51e260)
  // slot 0x45 vmethod_0048 inherited unchanged (0x48b860)
  // slot 0x46 DispatchUiMouseMoveToChildren inherited unchanged (0x596100)
  // slot 0x47 BeginMouseCaptureAndStartRepeatTimer inherited unchanged (0x430c10)
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
  // slot 0x5b VTableSlot5B inherited unchanged (0x48c6d0)
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
  // slot 0x68 SetFlagByteAndInvokeVslot1A4 inherited unchanged (0x595c40)
  // slot 0x69 RenderMapContextOverlayWithScopedClipAndSurface inherited unchanged (0x595c70)
  // slot 0x6a OrphanTiny_ReturnZero_0048a730 inherited unchanged (0x523640)
  // slot 0x6b VTableSlot6B inherited unchanged (0x523b70)
  // slot 0x6c OrphanRetStub_00596060 inherited unchanged (0x523ff0)
  // slot 0x6d OrphanRetStub_00596080 inherited unchanged (0x519e00)
  // slot 0x6e OrphanRetStub_005960e0 inherited unchanged (0x525730)
  // slot 0x6f OrphanTiny_ReturnMinusOneWord_005960a0 inherited unchanged (0x5960a0)
  // slot 0x70 OrphanRetStub_005960c0 inherited unchanged (0x51a990)
  virtual void InvokeDialogHooks1D8ThenE4() override; // slot 0x71 0x51cfa0
  virtual void HandleMapTileClickSetOrderContextAndDispatchEvent79() override; // slot 0x72 0x51d210
  virtual undefined WrapperFor_AllocateWithFallbackHandler_At005963d0() override; // slot 0x73 0x51d060
  // slot 0x74 WrapperFor_AllocateWithFallbackHandler_At00596440 inherited unchanged (0x596440)
  virtual void HandleMapClickByInteractionMode(short nTileIndex, int nInputFlags) override; // slot 0x75 0x51ce60
  // slot 0x76 OrphanRetStub_00594fc0 inherited unchanged (0x51ac40)
  // slot 0x77 OrphanTiny_ReturnMinusOneWord_00519af0 inherited unchanged (0x519af0)
  // slot 0x78 OrphanRetStub_005966a0 inherited unchanged (0x51ad70)
  // slot 0x79 OrphanRetStub_00596680 inherited unchanged (0x51adc0)
  // slot 0x7a OrphanRetStub_005966c0 inherited unchanged (0x51aad0)
  // slot 0x7b OrphanLeaf_NoCall_Ins02_005966e0 inherited unchanged (0x51ab60)
  // slot 0x7c OrphanCallChain_C6_I29_00596700 inherited unchanged (0x596700)
  // slot 0x7d DrawHexNeighborOutlineFromTileArray inherited unchanged (0x51a2a0)
  // slot 0x7e OrphanCallChain_C1_I20_0051e1a0 inherited unchanged (0x51e1a0)
  // slot 0x7f OrphanLeaf_NoCall_Ins21_0051e1f0 inherited unchanged (0x51e1f0)
  // slot 0x80 UpdateMapDialogProjectedTileMarkerAndInvalidate inherited unchanged (0x51a900)
  // slot 0x81 RenderStrategicMapTileCell inherited unchanged (0x51eb40)
  // slot 0x82 EmitHexAdjacencyTransitionEventsByBitmask inherited unchanged (0x521a40)
  // slot 0x83 DrawHexEdgeConnectionGlyphsByMask inherited unchanged (0x521680)
  // slot 0x84 RenderMapDialogBilateralRelationMarkers inherited unchanged (0x520670)
  // slot 0x85 DrawMapDialogGuidePatternSetA_00520970 inherited unchanged (0x520970)
  // slot 0x86 DrawMapDialogGuidePatternSetB_00520a90 inherited unchanged (0x520a90)
  // slot 0x87 DrawMapDialogGuidePatternSetC_00520c10 inherited unchanged (0x520c10)
  // slot 0x88 DrawMapDialogGuidePatternSetD_00520d20 inherited unchanged (0x520d20)
  // slot 0x89 DrawMapDialogTileGuidePatternByVariant inherited unchanged (0x520de0)
  // slot 0x8a DrawMapDialogGuidePatternSetE_00520fc0 inherited unchanged (0x520fc0)
  // slot 0x8b DrawMapDialogGuidePatternSetF_00521090 inherited unchanged (0x521090)
  // slot 0x8c DrawMapDialogGuidePatternSetG_005211c0 inherited unchanged (0x5211c0)
  // slot 0x8d DrawMapDialogGuidePatternSetH_00521340 inherited unchanged (0x521340)
  // slot 0x8e DrawMapDialogGuidePatternSetI_00521540 inherited unchanged (0x521540)
  // slot 0x8f DrawMapDialogOwnershipMarkerForNation_00522000 inherited unchanged (0x522000)
  // slot 0x90 RenderMapDialogDiplomacyNeighborRelationHints inherited unchanged (0x5220f0)
  // slot 0x91 DrawMapDialogWrappedTileConnectionMarker_00522c10 inherited unchanged (0x522c10)
  // slot 0x92 DrawHexNeighborConnectionMask inherited unchanged (0x522cf0)
  // slot 0x93 WrapperFor_SetQuickDrawFillColor_At00523060 inherited unchanged (0x523060)
  // slot 0x94 UpdateMapOrderEntryTilePreviewSlot inherited unchanged (0x523170)
  // slot 0x95 OrphanLeaf_NoCall_Ins100_005241b0 inherited unchanged (0x5241b0)
  // slot 0x96 GetTEventHandlerClassNamePointer inherited unchanged (0x5242f0)
  // slot 0x97 VTableSlot97 inherited unchanged (0x524540)
  // slot 0x98 InitializeForeignMinisterStateFlags inherited unchanged (0x524670)
  // slot 0x99 AddToForeignMinisterCounterAtIndex inherited unchanged (0x5247a0)
  // slot 0x9a SetForeignMinisterReadyFlag14 inherited unchanged (0x5249f0)
  // slot 0x9b SelectCandidateTilesWithLowGroundUnitCount inherited unchanged (0x524b30)
  // slot 0x9c OrphanLeaf_NoCall_Ins07_004d8920 inherited unchanged (0x524c60)
  // slot 0x9d OrphanLeaf_NoCall_Ins07_004d8920 inherited unchanged (0x524e70)
  // slot 0x9e CopyDiamondMaskBlockKernel inherited unchanged (0x5250a0)
  // slot 0x9f CopyDiagonalMaskNarrowingBlockKernel inherited unchanged (0x5252d0)
  // slot 0xa0 CopyDiagonalMaskWideningBlockKernel inherited unchanged (0x5254a0)
  // slot 0xa1 Copy64x64TileBlockWithStrideAdjustment inherited unchanged (0x525670)
  // slot 0xa2 HasRenderableParentAndContent inherited unchanged (0x51ace0)
  // slot 0xa3 SetMapDialogCellCoordinatesAndRefresh inherited unchanged (0x51adf0)
  // slot 0xa4 UpdateMapInteractionPreviewParityAndRenderTransientSprites inherited unchanged (0x51af60)
// === END GENERATED DECLS (TMapEditView) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TMapEditView 0xCTOR`).

  TMapEditView();
};

// === BEGIN GENERATED (TMapEditView) — refreshed by `just gen-class TMapEditView`; do not hand-edit ===
// clang-format off
// vtable @ 0x006594e8 (165 slots), object size 0x370, base TMapDialog
//   slot 0x00  byte 0x00  0x0051cc40  override  GetTEventHandlerClassNamePointer
//   slot 0x01  byte 0x04  0x0051cbf0  override  VTableSlot01
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x00519c90  inherited VTableSlot07
//   slot 0x08  byte 0x20  0x0048bfd0  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0048a240  inherited GetTEventHandlerClassNamePointer
//   slot 0x0b  byte 0x2c  0x0048a260  inherited ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x0c  byte 0x30  0x0048a2c0  inherited UpdateControlCachedIntFromWindowText
//   slot 0x0d  byte 0x34  0x0048a3b0  inherited OrphanRetStub_0059add0
//   slot 0x0e  byte 0x38  0x0048a3f0  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x0f  byte 0x3c  0x005950b0  inherited OrphanRetStub_0059add0
//   slot 0x10  byte 0x40  0x0048a2e0  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x11  byte 0x44  0x0048a310  inherited VTableSlot11
//   slot 0x12  byte 0x48  0x0051deb0  override  OrphanTiny_ReturnZero_0048a730
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
//   slot 0x2c  byte 0xb0  0x00595810  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x2d  byte 0xb4  0x0048c1c0  inherited OrphanRetStub_0059add0
//   slot 0x2e  byte 0xb8  0x0048c1e0  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x2f  byte 0xbc  0x00430bd0  inherited VTableSlot2F
//   slot 0x30  byte 0xc0  0x0048b4b0  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x31  byte 0xc4  0x0048ab90  inherited VTableSlot31
//   slot 0x32  byte 0xc8  0x0048b690  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x33  byte 0xcc  0x0048c000  inherited VTableSlot33
//   slot 0x34  byte 0xd0  0x0048c050  inherited SetForeignMinisterReadyFlag14
//   slot 0x35  byte 0xd4  0x005958b0  inherited SetForeignMinisterReadyFlag14
//   slot 0x36  byte 0xd8  0x0048aaf0  inherited SetForeignMinisterReadyFlag14
//   slot 0x37  byte 0xdc  0x0051cc60  override  OrphanLeaf_NoCall_Ins07_004d8920
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
//   slot 0x44  byte 0x110  0x0051e260  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x45  byte 0x114  0x0048b860  inherited GetTEventHandlerClassNamePointer
//   slot 0x46  byte 0x118  0x00596100  inherited SetForeignMinisterReadyFlag14
//   slot 0x47  byte 0x11c  0x00430c10  inherited ReleaseRuntimeSelectionOwnerAndDestroyObject
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
//   slot 0x5b  byte 0x16c  0x0048c6d0  inherited VTableSlot5B
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
//   slot 0x68  byte 0x1a0  0x00595c40  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x69  byte 0x1a4  0x00595c70  inherited OrphanRetStub_0059add0
//   slot 0x6a  byte 0x1a8  0x00523640  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x6b  byte 0x1ac  0x00523b70  inherited DispatchReflectedControlMessageOrFallback
//   slot 0x6c  byte 0x1b0  0x00523ff0  inherited OrphanRetStub_00596060
//   slot 0x6d  byte 0x1b4  0x00519e00  inherited OrphanRetStub_00596080
//   slot 0x6e  byte 0x1b8  0x00525730  inherited OrphanRetStub_005960e0
//   slot 0x6f  byte 0x1bc  0x005960a0  inherited OrphanTiny_ReturnMinusOneWord_005960a0
//   slot 0x70  byte 0x1c0  0x0051a990  inherited OrphanRetStub_005960c0
//   slot 0x71  byte 0x1c4  0x0051cfa0  override  InvokeDialogHooks1D8ThenE4
//   slot 0x72  byte 0x1c8  0x0051d210  override  HandleMapTileClickSetOrderContextAndDispatchEvent79
//   slot 0x73  byte 0x1cc  0x0051d060  override  ApplyCityInfluenceTierAndInvalidateTileCaches
//   slot 0x74  byte 0x1d0  0x00596440  inherited WrapperFor_AllocateWithFallbackHandler_At00596440
//   slot 0x75  byte 0x1d4  0x0051ce60  override  HandleMapClickByInteractionMode
//   slot 0x76  byte 0x1d8  0x0051ac40  inherited OrphanRetStub_00594fc0
//   slot 0x77  byte 0x1dc  0x00519af0  inherited OrphanTiny_ReturnMinusOneWord_00519af0
//   slot 0x78  byte 0x1e0  0x0051ad70  inherited OrphanRetStub_005966a0
//   slot 0x79  byte 0x1e4  0x0051adc0  inherited OrphanRetStub_00596680
//   slot 0x7a  byte 0x1e8  0x0051aad0  inherited OrphanRetStub_005966c0
//   slot 0x7b  byte 0x1ec  0x0051ab60  inherited OrphanLeaf_NoCall_Ins02_005966e0
//   slot 0x7c  byte 0x1f0  0x00596700  inherited OrphanCallChain_C6_I29_00596700
//   slot 0x7d  byte 0x1f4  0x0051a2a0  inherited DrawHexNeighborOutlineFromTileArray
//   slot 0x7e  byte 0x1f8  0x0051e1a0  inherited OrphanCallChain_C1_I20_0051e1a0
//   slot 0x7f  byte 0x1fc  0x0051e1f0  inherited OrphanLeaf_NoCall_Ins21_0051e1f0
//   slot 0x80  byte 0x200  0x0051a900  inherited UpdateMapDialogProjectedTileMarkerAndInvalidate
//   slot 0x81  byte 0x204  0x0051eb40  inherited RenderStrategicMapTileCell
//   slot 0x82  byte 0x208  0x00521a40  inherited EmitHexAdjacencyTransitionEventsByBitmask
//   slot 0x83  byte 0x20c  0x00521680  inherited DrawHexEdgeConnectionGlyphsByMask
//   slot 0x84  byte 0x210  0x00520670  inherited RenderMapDialogBilateralRelationMarkers
//   slot 0x85  byte 0x214  0x00520970  inherited DrawMapDialogGuidePatternSetA_00520970
//   slot 0x86  byte 0x218  0x00520a90  inherited DrawMapDialogGuidePatternSetB_00520a90
//   slot 0x87  byte 0x21c  0x00520c10  inherited DrawMapDialogGuidePatternSetC_00520c10
//   slot 0x88  byte 0x220  0x00520d20  inherited DrawMapDialogGuidePatternSetD_00520d20
//   slot 0x89  byte 0x224  0x00520de0  inherited DrawMapDialogTileGuidePatternByVariant
//   slot 0x8a  byte 0x228  0x00520fc0  inherited DrawMapDialogGuidePatternSetE_00520fc0
//   slot 0x8b  byte 0x22c  0x00521090  inherited DrawMapDialogGuidePatternSetF_00521090
//   slot 0x8c  byte 0x230  0x005211c0  inherited DrawMapDialogGuidePatternSetG_005211c0
//   slot 0x8d  byte 0x234  0x00521340  inherited DrawMapDialogGuidePatternSetH_00521340
//   slot 0x8e  byte 0x238  0x00521540  inherited DrawMapDialogGuidePatternSetI_00521540
//   slot 0x8f  byte 0x23c  0x00522000  inherited DrawMapDialogOwnershipMarkerForNation_00522000
//   slot 0x90  byte 0x240  0x005220f0  inherited RenderMapDialogDiplomacyNeighborRelationHints
//   slot 0x91  byte 0x244  0x00522c10  inherited DrawMapDialogWrappedTileConnectionMarker_00522c10
//   slot 0x92  byte 0x248  0x00522cf0  inherited DrawHexNeighborConnectionMask
//   slot 0x93  byte 0x24c  0x00523060  inherited WrapperFor_SetQuickDrawFillColor_At00523060
//   slot 0x94  byte 0x250  0x00523170  inherited UpdateMapOrderEntryTilePreviewSlot
//   slot 0x95  byte 0x254  0x005241b0  inherited OrphanLeaf_NoCall_Ins100_005241b0
//   slot 0x96  byte 0x258  0x005242f0  inherited GetTEventHandlerClassNamePointer
//   slot 0x97  byte 0x25c  0x00524540  inherited VTableSlot97
//   slot 0x98  byte 0x260  0x00524670  inherited InitializeForeignMinisterStateFlags
//   slot 0x99  byte 0x264  0x005247a0  inherited AddToForeignMinisterCounterAtIndex
//   slot 0x9a  byte 0x268  0x005249f0  inherited SetForeignMinisterReadyFlag14
//   slot 0x9b  byte 0x26c  0x00524b30  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x9c  byte 0x270  0x00524c60  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x9d  byte 0x274  0x00524e70  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x9e  byte 0x278  0x005250a0  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x9f  byte 0x27c  0x005252d0  inherited OrphanRetStub_0059add0
//   slot 0xa0  byte 0x280  0x005254a0  inherited GetTBehaviorClassNamePointer
//   slot 0xa1  byte 0x284  0x00525670  inherited EvaluateControlInputGate
//   slot 0xa2  byte 0x288  0x0051ace0  inherited HasRenderableParentAndContent
//   slot 0xa3  byte 0x28c  0x0051adf0  inherited ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0xa4  byte 0x290  0x0051af60  inherited HandleTurnEvent7DE_RefreshTradeDiplomacyCityTransportSummary
// object size 0x370 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TMapEditView) ===

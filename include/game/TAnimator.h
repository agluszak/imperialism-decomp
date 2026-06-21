#pragma once

#include "game/TEventHandler.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// TODO(manifest): describe TAnimator and its role. Base edge (TEventHandler) recovered from RTTI CRuntimeClass chain: TAnimator -> TEventHandler -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064c4e8
class TAnimator : public TEventHandler {
public:
// === BEGIN GENERATED DECLS (TAnimator) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x4a0a80
  virtual ~TAnimator(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x4a0e50
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4a0e10
  virtual void Free() override; // slot 0x07 0x4a0dc0
  // slot 0x08 ShallowClone inherited unchanged (0x48a7c0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a GetBoolSlot28 inherited unchanged (0x48a240)
  // slot 0x0b SetControlValue inherited unchanged (0x48a260)
  // slot 0x0c QueryStepValue inherited unchanged (0x48a2c0)
  // slot 0x0d vmethod_0013 inherited unchanged (0x48a3b0)
  // slot 0x0e vmethod_0014 inherited unchanged (0x48a3f0)
  // slot 0x0f ForwardEngineerDialogCommandToChildSlot40 inherited unchanged (0x48a280)
  // slot 0x10 DispatchUiCommandToHandler inherited unchanged (0x48a2e0)
  // slot 0x11 vmethod_0017 inherited unchanged (0x48a310)
  // slot 0x12 ForwardParam inherited unchanged (0x48a380)
  virtual char CanHandleCityDialogActionFalse(int action) override; // slot 0x13 0x4a0c30
  // slot 0x14 GetCityDialogValueDword10 inherited unchanged (0x415d50)
  // slot 0x15 SetCityDialogValueDword10 inherited unchanged (0x415d70)
  // slot 0x16 OwnerPanel inherited unchanged (0x48a730)
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
  virtual undefined OrphanCallChain_C2_I13_004a0c00() override; // slot 0x25 0x4a0c00
// === END GENERATED DECLS (TAnimator) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TAnimator 0xCTOR`).

  TAnimator();
};

// === BEGIN GENERATED (TAnimator) — refreshed by `just gen-class TAnimator`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064c4e8 (38 slots), object size 0x30, base TEventHandler
//   slot 0x00  byte 0x00  0x004a0a80  override  GetTEventHandlerClassNamePointer
//   slot 0x01  byte 0x04  0x004a0ad0  override  VTableSlot01
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x004a0e50  override  VTableSlot05
//   slot 0x06  byte 0x18  0x004a0e10  override  GetTEventHandlerClassNamePointer
//   slot 0x07  byte 0x1c  0x004a0dc0  override  ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x08  byte 0x20  0x0048a7c0  inherited UpdateControlCachedIntFromWindowText
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0048a240  inherited GetTEventHandlerClassNamePointer
//   slot 0x0b  byte 0x2c  0x0048a260  inherited ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x0c  byte 0x30  0x0048a2c0  inherited UpdateControlCachedIntFromWindowText
//   slot 0x0d  byte 0x34  0x0048a3b0  inherited OrphanRetStub_0059add0
//   slot 0x0e  byte 0x38  0x0048a3f0  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x0f  byte 0x3c  0x0048a280  inherited OrphanRetStub_0059add0
//   slot 0x10  byte 0x40  0x0048a2e0  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x11  byte 0x44  0x0048a310  inherited VTableSlot11
//   slot 0x12  byte 0x48  0x0048a380  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x13  byte 0x4c  0x004a0c30  override  VTableSlot13
//   slot 0x14  byte 0x50  0x00415d50  inherited OrphanTiny_ReturnZero_0048a730
//   slot 0x15  byte 0x54  0x00415d70  inherited VTableSlot15
//   slot 0x16  byte 0x58  0x0048a730  inherited OrphanTiny_ReturnZero_0048a730
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
//   slot 0x25  byte 0x94  0x004a0c00  override  OrphanCallChain_C2_I13_004a0c00
// object size 0x30 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TAnimator) ===

#pragma once

#include "game/TControl.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class CityDialogController;
class TObject;

// TODO(manifest): describe TMapMaker and its role. Base edge (TControl) recovered from RTTI CRuntimeClass chain: TMapMaker -> TControl -> TView -> TEventHandler -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x006598f8
class TMapMaker : public TControl {
public:
// === BEGIN GENERATED DECLS (TMapMaker) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x525950
  virtual ~TMapMaker(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  virtual void Free() override; // slot 0x07 0x4798b0
  virtual TObject* ShallowClone() override; // slot 0x08 0x4798d0
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual char GetBoolSlot28() override; // slot 0x0a 0x526ba0
  virtual void SetControlValue(int value) override; // slot 0x0b 0x526c20
  virtual int QueryStepValue() override; // slot 0x0c 0x527040
  virtual void vmethod_0013(int* cmd) override; // slot 0x0d 0x527300
  virtual void vmethod_0014(int command) override; // slot 0x0e 0x5275a0
  virtual undefined ForwardEngineerDialogCommandToChildSlot40() override; // slot 0x0f 0x527730
  virtual undefined DispatchUiCommandToHandler() override; // slot 0x10 0x5274d0
  virtual void vmethod_0017(int param) override; // slot 0x11 0x528e50
  virtual void ForwardParam(int param) override; // slot 0x12 0x5283c0
  virtual char CanHandleCityDialogActionFalse(int action) override; // slot 0x13 0x528670
  virtual int GetCityDialogValueDword10() override; // slot 0x14 0x528780
  virtual void SetCityDialogValueDword10(int value) override; // slot 0x15 0x5288a0
  virtual class TView* OwnerPanel() override; // slot 0x16 0x528140
  virtual char vmethod_0023() override; // slot 0x17 0x527d00
  virtual char vmethod_0024() override; // slot 0x18 0x527ed0
  virtual void vmethod_0025() override; // slot 0x19 0x529f60
  virtual void vmethod_0026(int gate) override; // slot 0x1a 0x52e840
  virtual void HandleCityProductionNoOp() override; // slot 0x1b 0x52e900
  virtual void DispatchUiCommand19ToParent() override; // slot 0x1c 0x52e890
  virtual void DispatchCityProductionAction1A() override; // slot 0x1d 0x528ce0
  virtual void DispatchCityProductionAction1B() override; // slot 0x1e 0x5292f0
  virtual char ActivateCityProductionViewIfAllowed() override; // slot 0x1f 0x5296a0
  virtual char vmethod_0080() override; // slot 0x20 0x5297e0
  virtual void vmethod_0081() override; // slot 0x21 0x5298a0
  virtual void SetEnabled(int enabledState, int refreshFlag) override; // slot 0x29 0x52a760
  virtual void SetState(int state, int refreshFlag) override; // slot 0x2a 0x52c0a0
// === END GENERATED DECLS (TMapMaker) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TMapMaker 0xCTOR`).

  TMapMaker();
};

// === BEGIN GENERATED (TMapMaker) — refreshed by `just gen-class TMapMaker`; do not hand-edit ===
// clang-format off
// vtable @ 0x006598f8 (43 slots), object size 0x2a8, base TControl
//   slot 0x00  byte 0x00  0x00525950  override  GetTEventHandlerClassNamePointer
//   slot 0x01  byte 0x04  0x00525990  override  VTableSlot01
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x004798b0  override  Free
//   slot 0x08  byte 0x20  0x004798d0  override  ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x00526ba0  override  GetTEventHandlerClassNamePointer
//   slot 0x0b  byte 0x2c  0x00526c20  override  ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x0c  byte 0x30  0x00527040  override  UpdateControlCachedIntFromWindowText
//   slot 0x0d  byte 0x34  0x00527300  override  OrphanRetStub_0059add0
//   slot 0x0e  byte 0x38  0x005275a0  override  OrphanCallChain_C11_I88_004874b0
//   slot 0x0f  byte 0x3c  0x00527730  override  ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x10  byte 0x40  0x005274d0  override  OrphanTiny_ReturnZero_0048a730
//   slot 0x11  byte 0x44  0x00528e50  override  VTableSlot11
//   slot 0x12  byte 0x48  0x005283c0  override  OrphanTiny_ReturnZero_0048a730
//   slot 0x13  byte 0x4c  0x00528670  override  VTableSlot13
//   slot 0x14  byte 0x50  0x00528780  override  OrphanTiny_ReturnZero_0048a730
//   slot 0x15  byte 0x54  0x005288a0  override  VTableSlot15
//   slot 0x16  byte 0x58  0x00528140  override  SetForeignMinisterReadyFlag14
//   slot 0x17  byte 0x5c  0x00527d00  override  VTableSlot17
//   slot 0x18  byte 0x60  0x00527ed0  override  InvalidateWindowRectFromHandleField1C
//   slot 0x19  byte 0x64  0x00529f60  override  OrphanRetStub_0059add0
//   slot 0x1a  byte 0x68  0x0052e840  override  GetTEventHandlerClassNamePointer
//   slot 0x1b  byte 0x6c  0x0052e900  override  VTableSlot1B
//   slot 0x1c  byte 0x70  0x0052e890  override  GetTEventHandlerClassNamePointer
//   slot 0x1d  byte 0x74  0x00528ce0  override  VTableSlot1D
//   slot 0x1e  byte 0x78  0x005292f0  override  OrphanCallChain_C11_I88_004874b0
//   slot 0x1f  byte 0x7c  0x005296a0  override  OrphanRetStub_0059add0
//   slot 0x20  byte 0x80  0x005297e0  override  GetTEventHandlerClassNamePointer
//   slot 0x21  byte 0x84  0x005298a0  override  VTableSlot21
//   slot 0x22  byte 0x88  0x00000000  null      (null)
//   slot 0x23  byte 0x8c  0x00000000  null      (null)
//   slot 0x24  byte 0x90  0x00000000  null      (null)
//   slot 0x25  byte 0x94  0x00000000  null      (null)
//   slot 0x26  byte 0x98  0x00000000  null      (null)
//   slot 0x27  byte 0x9c  0x00000000  null      (null)
//   slot 0x28  byte 0xa0  0x00000000  null      (null)
//   slot 0x29  byte 0xa4  0x0052a760  override  VTableSlot29
//   slot 0x2a  byte 0xa8  0x0052c0a0  override  GetTEventHandlerClassNamePointer
// object size 0x2a8 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TMapMaker) ===

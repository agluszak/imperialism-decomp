#pragma once

#include "game/TObject.h"
#include "game/TEventHandler.h"
#include "game/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006598f8
class TMapMaker : public TObject {
  DECLARE_DYNAMIC(TMapMaker)
public:
  TMapMaker();
  virtual ~TMapMaker() override;

  virtual char GetBoolSlot28(); // slot 10 / 0x28
  virtual void SetControlValue(int value); // slot 11 / 0x2c
  virtual TEventHandler* QueryStepValue(); // slot 12 / 0x30
  virtual void DispatchQueuedUiCommandAndRelease(void* payload); // slot 13 / 0x34
  virtual void DispatchUiSelectionToHandler(void* payload); // slot 14 / 0x38
  virtual void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event); // slot 15 / 0x3c
  virtual void DispatchEvent(int commandId, TEventHandler* sourceHandler, TEvent* event); // slot 16 / 0x40
  virtual void vmethod_0017(int param); // slot 17 / 0x44
  virtual void ForwardParam(int param); // slot 18 / 0x48
  virtual char CanHandleCityDialogActionFalse(int action); // slot 19 / 0x4c
  virtual int GetCityDialogValueDword10(); // slot 20 / 0x50
  virtual void SetCityDialogValueDword10(int value); // slot 21 / 0x54
  virtual TView* OwnerPanel(); // slot 22 / 0x58
  virtual char vmethod_0023(); // slot 23 / 0x5c
  virtual char vmethod_0024(); // slot 24 / 0x60
  virtual void vmethod_0025(); // slot 25 / 0x64
  virtual void vmethod_0026(int gate); // slot 26 / 0x68
  virtual void HandleCityProductionNoOp(); // slot 27 / 0x6c
  virtual void DispatchUiCommand19ToParent(); // slot 28 / 0x70
  virtual void DispatchCityProductionAction1A(); // slot 29 / 0x74
  virtual void DispatchCityProductionAction1B(); // slot 30 / 0x78
  virtual char ActivateCityProductionViewIfAllowed(); // slot 31 / 0x7c
  virtual char vmethod_0080(); // slot 32 / 0x80
  virtual void vmethod_0081(int param); // slot 33 / 0x84

  // Slots 34 to 40 are NULL (pure virtual dummy methods)
  virtual void TMapMakerDummy34() = 0;
  virtual void TMapMakerDummy35() = 0;
  virtual void TMapMakerDummy36() = 0;
  virtual void TMapMakerDummy37() = 0;
  virtual void TMapMakerDummy38() = 0;
  virtual void TMapMakerDummy39() = 0;
  virtual void TMapMakerDummy40() = 0;

  // Slots 41 and 42 (offset 0xa4 and 0xa8)
  virtual void SetEnabled(int enabledState, int refreshFlag); // slot 41 / 0xa4
  virtual void SetState(int state, int refreshFlag); // slot 42 / 0xa8

  char pad_04_2a8[0x2a8 - 0x04];
};

ASSERT_SIZE(TMapMaker, 0x2a8);

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

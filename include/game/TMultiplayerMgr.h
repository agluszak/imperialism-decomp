#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class CityDialogController;
class TStream;

// TODO(manifest): describe TMultiplayerMgr and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TMultiplayerMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0065c030
class TMultiplayerMgr : public TObject {
public:
// === BEGIN GENERATED DECLS (TMultiplayerMgr) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x542650
  virtual ~TMultiplayerMgr(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x542ff0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x542be0
  virtual void Free() override; // slot 0x07 0x542b10
  virtual TObject* ShallowClone() override; // slot 0x08 0x48a7c0
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual byte GetTEventHandlerClassNamePointer_0a(CityDialogController * pDialog); // slot 0x0a 0x48a240
  virtual void ReleaseRuntimeSelectionOwnerAndDestroyObject(char flagValue); // slot 0x0b 0x48a260
  virtual int UpdateControlCachedIntFromWindowText(CityDialogController * pDialog); // slot 0x0c 0x48a2c0
  virtual undefined OrphanRetStub_0059add0_0d(int * param_1); // slot 0x0d 0x48a3b0
  virtual undefined OrphanCallChain_C11_I88_004874b0_0e(); // slot 0x0e 0x48a3f0
  virtual undefined OrphanRetStub_0059add0_0f(undefined4 param_1, undefined4 param_2, undefined4 param_3); // slot 0x0f 0x48a280
  virtual undefined OrphanTiny_ReturnZero_0048a730_10(); // slot 0x10 0x48a2e0
  virtual undefined VTableSlot11(undefined4 param_1); // slot 0x11 0x48a310
  virtual undefined OrphanTiny_ReturnZero_0048a730_12(undefined4 param_1); // slot 0x12 0x48a380
  virtual undefined DispatchOptionalChildEventAndProcessDiplomacyTurnQueue(); // slot 0x13 0x544e30
  virtual int OrphanTiny_ReturnZero_0048a730_14(CityDialogController * pDialog); // slot 0x14 0x415d50
  virtual void VTableSlot15(int value); // slot 0x15 0x415d70
  virtual undefined OrphanTiny_ReturnZero_0048a730_16(); // slot 0x16 0x48a730
  virtual undefined VTableSlot17(); // slot 0x17 0x48a530
  virtual undefined SetForeignMinisterReadyFlag14(); // slot 0x18 0x48a550
  virtual undefined VTableSlot19(); // slot 0x19 0x48a690
  virtual undefined GetTEventHandlerClassNamePointer_1a(); // slot 0x1a 0x48a6b0
  virtual undefined VTableSlot1B(); // slot 0x1b 0x48a650
  virtual undefined GetTEventHandlerClassNamePointer_1c(); // slot 0x1c 0x48a6d0
  virtual undefined VTableSlot1D(); // slot 0x1d 0x48a670
  virtual undefined GetTEventHandlerClassNamePointer_1e(); // slot 0x1e 0x48a6f0
  virtual undefined VTableSlot1F(); // slot 0x1f 0x48a570
  virtual undefined GetTEventHandlerClassNamePointer_20(); // slot 0x20 0x48a5e0
  virtual undefined VTableSlot21(); // slot 0x21 0x48a710
  virtual undefined GetTEventHandlerClassNamePointer_22(); // slot 0x22 0x48a500
  virtual undefined VTableSlot23(int param_1); // slot 0x23 0x48a4a0
  virtual undefined OrphanCallChain_C11_I88_004874b0_24(int param_1); // slot 0x24 0x48a4d0
  virtual undefined InitializeMultiplayerManagerForSessionContext(CString param_1); // slot 0x25 0x542900
// === END GENERATED DECLS (TMultiplayerMgr) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TMultiplayerMgr 0xCTOR`).

  TMultiplayerMgr();
};

// === BEGIN GENERATED (TMultiplayerMgr) — refreshed by `just gen-class TMultiplayerMgr`; do not hand-edit ===
// clang-format off
// vtable @ 0x0065c030 (38 slots), object size 0xf8, base TObject
//   slot 0x00  byte 0x00  0x00542650  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x005427e0  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00542ff0  override  WriteTo
//   slot 0x06  byte 0x18  0x00542be0  override  ReadFrom
//   slot 0x07  byte 0x1c  0x00542b10  override  Free
//   slot 0x08  byte 0x20  0x0048a7c0  override  ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0048a240  override  GetTEventHandlerClassNamePointer
//   slot 0x0b  byte 0x2c  0x0048a260  override  ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x0c  byte 0x30  0x0048a2c0  override  UpdateControlCachedIntFromWindowText
//   slot 0x0d  byte 0x34  0x0048a3b0  override  OrphanRetStub_0059add0
//   slot 0x0e  byte 0x38  0x0048a3f0  override  OrphanCallChain_C11_I88_004874b0
//   slot 0x0f  byte 0x3c  0x0048a280  override  OrphanRetStub_0059add0
//   slot 0x10  byte 0x40  0x0048a2e0  override  OrphanTiny_ReturnZero_0048a730
//   slot 0x11  byte 0x44  0x0048a310  override  VTableSlot11
//   slot 0x12  byte 0x48  0x0048a380  override  OrphanTiny_ReturnZero_0048a730
//   slot 0x13  byte 0x4c  0x00544e30  override  DispatchOptionalChildEventAndProcessDiplomacyTurnQueue
//   slot 0x14  byte 0x50  0x00415d50  override  OrphanTiny_ReturnZero_0048a730
//   slot 0x15  byte 0x54  0x00415d70  override  VTableSlot15
//   slot 0x16  byte 0x58  0x0048a730  override  OrphanTiny_ReturnZero_0048a730
//   slot 0x17  byte 0x5c  0x0048a530  override  VTableSlot17
//   slot 0x18  byte 0x60  0x0048a550  override  SetForeignMinisterReadyFlag14
//   slot 0x19  byte 0x64  0x0048a690  override  VTableSlot19
//   slot 0x1a  byte 0x68  0x0048a6b0  override  GetTEventHandlerClassNamePointer
//   slot 0x1b  byte 0x6c  0x0048a650  override  VTableSlot1B
//   slot 0x1c  byte 0x70  0x0048a6d0  override  GetTEventHandlerClassNamePointer
//   slot 0x1d  byte 0x74  0x0048a670  override  VTableSlot1D
//   slot 0x1e  byte 0x78  0x0048a6f0  override  GetTEventHandlerClassNamePointer
//   slot 0x1f  byte 0x7c  0x0048a570  override  VTableSlot1F
//   slot 0x20  byte 0x80  0x0048a5e0  override  GetTEventHandlerClassNamePointer
//   slot 0x21  byte 0x84  0x0048a710  override  VTableSlot21
//   slot 0x22  byte 0x88  0x0048a500  override  GetTEventHandlerClassNamePointer
//   slot 0x23  byte 0x8c  0x0048a4a0  override  VTableSlot23
//   slot 0x24  byte 0x90  0x0048a4d0  override  OrphanCallChain_C11_I88_004874b0
//   slot 0x25  byte 0x94  0x00542900  override  InitializeMultiplayerManagerForSessionContext
// object size 0xf8 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TMultiplayerMgr) ===

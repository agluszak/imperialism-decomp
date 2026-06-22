#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// TODO(manifest): describe TNetMgr and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TNetMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066fa20
class TNetMgr : public TObject {
public:
// === BEGIN GENERATED DECLS (TNetMgr) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x5e33c0
  virtual ~TNetMgr(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  virtual void Free() override; // slot 0x07 0x5e3470
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual CRuntimeClass * GetRuntimeClass_0c() override; // slot 0x0c 0x606fba
  virtual undefined WrapperFor_FreeHeapBufferIfNotNull_At005e4a30(byte param_1) override; // slot 0x0d 0x5e4a30
  virtual undefined SerializeLinkedRecordListWithFreeNodePool(CArchive * param_1) override; // slot 0x0e 0x5e4610
  virtual void AssertValid_0f() override; // slot 0x0f 0x412bf0
  virtual void Dump_10(undefined4 dc) override; // slot 0x10 0x412c10
  virtual CRuntimeClass * GetRuntimeClass_12() override; // slot 0x12 0x606fba
  virtual undefined WrapperFor_FreeHeapBufferIfNotNull_At005e4a60(byte param_1) override; // slot 0x13 0x5e4a60
  virtual undefined SerializeDynamicDwordPointerArrayState(CArchive * param_1) override; // slot 0x14 0x5e4830
  virtual void AssertValid_15() override; // slot 0x15 0x412bf0
  virtual void Dump_16(undefined4 dc) override; // slot 0x16 0x412c10
// === END GENERATED DECLS (TNetMgr) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TNetMgr 0xCTOR`).

  TNetMgr();
};

// === BEGIN GENERATED (TNetMgr) — refreshed by `just gen-class TNetMgr`; do not hand-edit ===
// clang-format off
// vtable @ 0x0066fa20 (23 slots), object size 0x04, base TObject
//   slot 0x00  byte 0x00  0x005e33c0  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x005e3400  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x005e3470  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x00000000  null      (null)
//   slot 0x0b  byte 0x2c  0x00000000  null      (null)
//   slot 0x0c  byte 0x30  0x00606fba  override  GetRuntimeClass
//   slot 0x0d  byte 0x34  0x005e4a30  override  WrapperFor_FreeHeapBufferIfNotNull_At005e4a30
//   slot 0x0e  byte 0x38  0x005e4610  override  SerializeLinkedRecordListWithFreeNodePool
//   slot 0x0f  byte 0x3c  0x00412bf0  override  AssertValid
//   slot 0x10  byte 0x40  0x00412c10  override  Dump
//   slot 0x11  byte 0x44  0x00000000  null      (null)
//   slot 0x12  byte 0x48  0x00606fba  override  GetRuntimeClass
//   slot 0x13  byte 0x4c  0x005e4a60  override  WrapperFor_FreeHeapBufferIfNotNull_At005e4a60
//   slot 0x14  byte 0x50  0x005e4830  override  SerializeDynamicDwordPointerArrayState
//   slot 0x15  byte 0x54  0x00412bf0  override  AssertValid
//   slot 0x16  byte 0x58  0x00412c10  override  Dump
// object size 0x04 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TNetMgr) ===

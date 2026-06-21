#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// TODO(manifest): describe THelpMgr and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: THelpMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00657040
class THelpMgr : public TObject {
public:
// === BEGIN GENERATED DECLS (THelpMgr) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x5005c0
  virtual ~THelpMgr(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x500fe0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x500f50
  virtual void Free() override; // slot 0x07 0x501070
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined InitializeHelpManagerIndexArrayAndState() override; // slot 0x0a 0x500680
  virtual undefined OrphanCallChain_C1_I22_00500f10() override; // slot 0x0b 0x500f10
// === END GENERATED DECLS (THelpMgr) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery THelpMgr 0xCTOR`).

  THelpMgr();
};

// === BEGIN GENERATED (THelpMgr) — refreshed by `just gen-class THelpMgr`; do not hand-edit ===
// clang-format off
// vtable @ 0x00657040 (12 slots), object size 0x30, base TObject
//   slot 0x00  byte 0x00  0x005005c0  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x00500630  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00500fe0  override  WriteTo
//   slot 0x06  byte 0x18  0x00500f50  override  ReadFrom
//   slot 0x07  byte 0x1c  0x00501070  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x00500680  override  InitializeHelpManagerIndexArrayAndState
//   slot 0x0b  byte 0x2c  0x00500f10  override  OrphanCallChain_C1_I22_00500f10
// object size 0x30 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (THelpMgr) ===

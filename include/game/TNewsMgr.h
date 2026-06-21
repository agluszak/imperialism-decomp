#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// TODO(manifest): describe TNewsMgr and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TNewsMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0065c598
class TNewsMgr : public TObject {
public:
// === BEGIN GENERATED DECLS (TNewsMgr) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x55b6f0
  virtual ~TNewsMgr(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x55b8c0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x55b8a0
  virtual void Free() override; // slot 0x07 0x55b820
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
// === END GENERATED DECLS (TNewsMgr) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TNewsMgr 0xCTOR`).

  TNewsMgr();
};

// === BEGIN GENERATED (TNewsMgr) — refreshed by `just gen-class TNewsMgr`; do not hand-edit ===
// clang-format off
// vtable @ 0x0065c598 (10 slots), object size 0xf10, base TObject
//   slot 0x00  byte 0x00  0x0055b6f0  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x0055b6a0  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x0055b8c0  override  WriteTo
//   slot 0x06  byte 0x18  0x0055b8a0  override  ReadFrom
//   slot 0x07  byte 0x1c  0x0055b820  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
// object size 0xf10 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TNewsMgr) ===

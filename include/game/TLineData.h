#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// TODO(manifest): describe TLineData and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TLineData -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0065e230
class TLineData : public TObject {
public:
// === BEGIN GENERATED DECLS (TLineData) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TLineData)
  virtual ~TLineData(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanRetStub_0056f460(); // slot 0x0a 0x56f460
  virtual undefined OrphanRetStub_0056f480(); // slot 0x0b 0x56f480
// === END GENERATED DECLS (TLineData) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TLineData 0xCTOR`).

  TLineData();
};

// === BEGIN GENERATED (TLineData) — refreshed by `just gen-class TLineData`; do not hand-edit ===
// clang-format off
// vtable @ 0x0065e230 (12 slots), object size 0x10, base TObject
//   slot 0x00  byte 0x00  0x0056f390  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x0056f3d0  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0056f460  override  OrphanRetStub_0056f460
//   slot 0x0b  byte 0x2c  0x0056f480  override  OrphanRetStub_0056f480
// object size 0x10 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TLineData) ===

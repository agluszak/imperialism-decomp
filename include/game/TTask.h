#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// TODO(manifest): describe TTask and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TTask -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066a970
class TTask : public TObject {
public:
// === BEGIN GENERATED DECLS (TTask) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TTask)
  virtual ~TTask(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x5adc50
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5adc90
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanLeaf_NoCall_Ins04_005adc30(); // slot 0x0a 0x5adc30
// === END GENERATED DECLS (TTask) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TTask 0xCTOR`).

  TTask();
};

// === BEGIN GENERATED (TTask) — refreshed by `just gen-class TTask`; do not hand-edit ===
// clang-format off
// vtable @ 0x0066a970 (11 slots), object size 0x08, base TObject
//   slot 0x00  byte 0x00  0x005adb70  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x005adbb0  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x005adc50  override  WriteTo
//   slot 0x06  byte 0x18  0x005adc90  override  ReadFrom
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x005adc30  override  OrphanLeaf_NoCall_Ins04_005adc30
// object size 0x08 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TTask) ===

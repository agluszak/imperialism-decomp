#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Fuzzy-logic set (collection of up to 10 TObject-derived members, each
// released via its own virtual Free()) used by the AI minister decision code
// alongside TFuzzyVar. Base edge (TObject) recovered from RTTI CRuntimeClass
// chain: TFuzzySet -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x006569c8
class TFuzzySet : public TObject {
public:
// === BEGIN GENERATED DECLS (TFuzzySet) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TFuzzySet)
  virtual ~TFuzzySet(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  virtual void Free() override; // slot 0x07 0x4ff780
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
// === END GENERATED DECLS (TFuzzySet) ===

  TFuzzySet();

private:
  int m_memberCount;         // field_0x4 — not zeroed by the ctor; caller-managed
  TObject* m_members[10];    // field_0x8..field_0x2c
};

ASSERT_SIZE(TFuzzySet, 0x30);

// === BEGIN GENERATED (TFuzzySet) — refreshed by `just gen-class TFuzzySet`; do not hand-edit ===
// clang-format off
// vtable @ 0x006569c8 (10 slots), object size 0x30, base TObject
//   slot 0x00  byte 0x00  0x004ff6c0  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x004ff700  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x004ff780  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
// object size 0x30 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TFuzzySet) ===

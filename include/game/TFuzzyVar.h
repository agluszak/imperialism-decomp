#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Fuzzy-logic variable used by the AI minister decision code (constructed by
// InitializeCityInteriorMinister @0x4be8d0). Base edge (TObject) recovered from
// RTTI CRuntimeClass chain: TFuzzyVar -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00656998
class TFuzzyVar : public TObject {
public:
// === BEGIN GENERATED DECLS (TFuzzyVar) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TFuzzyVar)
  virtual ~TFuzzyVar(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
// === END GENERATED DECLS (TFuzzyVar) ===

  TFuzzyVar();

  // Allocates a leaf TFuzzyVar record holding the 4 raw params and appends it
  // to this instance's record array (0x4ff7d0, called 4x from
  // InitializeCityInteriorMinister). Only ever observed called on a
  // "container" instance; the allocated record itself is never seen appended
  // to further, i.e. it is always used as a leaf.
  void AllocateAndAppendRecord(int param1, int param2, int param3, int param4);

private:
  // Dual-purpose layout (see AGENTS.md dual-purpose-offset guardrail): on a
  // "container" instance these are a record count (field_0x4) plus up to 3
  // TFuzzyVar* record slots (field_0x8/0xc/0x10); on a "leaf" record allocated
  // by AllocateAndAppendRecord they instead hold 4 raw caller-supplied values.
  // Same memory, different role depending on how the instance is used, so the
  // slots stay raw ints rather than forcing pointer typing onto leaf use.
  int field_0x4;
  int field_0x8;
  int field_0xc;
  int field_0x10;
};

ASSERT_SIZE(TFuzzyVar, 0x14);

// === BEGIN GENERATED (TFuzzyVar) — refreshed by `just gen-class TFuzzyVar`; do not hand-edit ===
// clang-format off
// vtable @ 0x00656998 (10 slots), object size 0x14, base TObject
//   slot 0x00  byte 0x00  0x004ff490  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x004ff4d0  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
// object size 0x14 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TFuzzyVar) ===

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
  virtual ~TFuzzySet() override; // slot 0x01 (scalar deleting destructor)
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


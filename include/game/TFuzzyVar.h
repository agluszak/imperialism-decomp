#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Fuzzy-logic variable used by the AI minister decision code (constructed by
// InitializeCityInteriorMinister @0x4be8d0). Base edge (TObject) recovered from
// RTTI CRuntimeClass chain: TFuzzyVar -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00656998
class TFuzzyVar : public TObject {
public:
  DECLARE_DYNCREATE(TFuzzyVar)
  virtual ~TFuzzyVar() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)

  // In-class inline: the original has no out-of-line TFuzzyVar::TFuzzyVar — the ctor is
  // absorbed into each allocation site as a single vptr store (e.g. inside
  // TFuzzySet::AllocateAndAppendRecord 0x4ff7d0), so an out-of-line body would pessimize
  // those sites into a call with an EH frame.
  // NOOP: verified empty in original 0x004ff7e1 (no standalone body exists; the ctor is
  // absorbed at each allocation site as a single vptr store)
  TFuzzyVar() {}

  // Leaf record: four raw fuzzy-logic values. TFuzzyVar is purely the record; the container
  // that counts and holds these records is TFuzzySet (m_memberCount + m_members[10]).
  // TFuzzySet::AllocateAndAppendRecord (0x4ff7d0) news a TFuzzyVar and fills these, then
  // appends it to the set -- the earlier "container role of TFuzzyVar" was a wrong-class
  // attribution: that method's receiver is a 0x30-byte TFuzzySet, not a 0x14 TFuzzyVar.
  int values[4]; // +0x4..+0x10
};

ASSERT_SIZE(TFuzzyVar, 0x14);

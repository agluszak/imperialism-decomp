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

  TFuzzyVar();

  // Allocates a leaf TFuzzyVar record holding the 4 raw params and appends it
  // to this instance's record array (0x4ff7d0, called 4x from
  // InitializeCityInteriorMinister). Only ever observed called on a
  // "container" instance; the allocated record itself is never seen appended
  // to further, i.e. it is always used as a leaf.
  void AllocateAndAppendRecord(int param1, int param2, int param3, int param4);

private:
  // UNRESOLVED_FIELD_ATTRIBUTION: +0x4..+0x10 read as {count, TFuzzyVar* slots[3]} on the
  // "container" instance but as four raw scalars on instances allocated by
  // AllocateAndAppendRecord. This is EITHER a role-polymorphic object OR two distinct record
  // classes mistakenly merged as one TFuzzyVar -- unresolved until the two allocation sites
  // are proven to share (or not) the TFuzzyVar vtable/ctor. Resolve to a role/union model or a
  // separate leaf-record type then; the slots stay raw until proven (not "dual-purpose").
  int field_0x4;
  int field_0x8;
  int field_0xc;
  int field_0x10;
};

ASSERT_SIZE(TFuzzyVar, 0x14);

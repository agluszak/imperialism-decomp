#pragma once

#include "game/app/TObject.h"
#include "game/mfc.h"

// Fuzzy-logic set (collection of up to 10 TObject-derived members, each
// released via its own virtual Free()) used by the AI minister decision code
// alongside TFuzzyVar. Base edge (TObject) recovered from RTTI CRuntimeClass
// chain: TFuzzySet -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x006569c8
class TFuzzySet : public TObject {
public:
  DECLARE_DYNCREATE(TFuzzySet)
  virtual ~TFuzzySet() override; // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;  // slot 0x07 0x4ff780

  TFuzzySet();

  // Resets the set to empty: zeroes the member count and nulls all 10 member slots. 0x4ff750
  void Clear();

  // Allocates a 4-value TFuzzyVar leaf, fills its values, and appends it to m_members. 0x4ff7d0
  void AllocateAndAppendRecord(int value0, int value1, int value2, int value3);

  // Evaluates each trapezoidal membership record at `input`, normalizes the weights,
  // and randomly selects one member index from the resulting distribution.
  int SelectWeightedMemberIndex(float input); // 0x004ff840

private:
  int m_memberCount;      // field_0x4 — not zeroed by the ctor; caller-managed
  TObject* m_members[10]; // field_0x8..field_0x2c
};

ASSERT_SIZE(TFuzzySet, 0x30);

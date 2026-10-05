#pragma once

#include "game/app/TObject.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006569c8
class TFuzzySet : public TObject {
public:
  DECLARE_DYNCREATE(TFuzzySet)
  virtual ~TFuzzySet() override; // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;  // slot 0x07 0x4ff780

  TFuzzySet();

  // Resets the set to empty: zeroes the member count and nulls all 10 member slots. 0x4ff750
  void IFuzzySet();

  // Allocates a 4-value TFuzzyVar leaf, fills its values, and appends it to m_members. 0x4ff7d0
  void AddFuzzyVar(float value0, float value1, float value2, float value3);

  int GetCrispOutput(float input); // 0x004ff840

private:
  int m_memberCount;      // field_0x4 — not zeroed by the ctor; caller-managed
  TObject* m_members[10]; // field_0x8..field_0x2c
};

ASSERT_SIZE(TFuzzySet, 0x30);

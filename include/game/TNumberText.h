#pragma once

#include "game/TEditText.h"

class CMcWindow;

// VTABLE: IMPERIALISM 0x0063e8b0
class TNumberText : public TEditText {
public:
  int value;           // 0xa0
  int field_a4;        // 0xa4
  int field_a8;        // 0xa8

  CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 (0x491040)
  ~TNumberText() override;                         // slot 0x01 (0x429530)
  TObject* ShallowClone() override;                // slot 0x08 (0x4912b0)

  using TEditText::SetControlValue;

  // New virtual methods
  virtual void SetControlValue(int val, int refresh); // slot 0x79 (0x4910e0)
  virtual int UpdateControlCachedIntFromWindowText(); // slot 0x7a (0x4911c0)

  TNumberText(); // constructor (0x429500)
  void ConstructTNumberTextBaseState(TControl* panel, int* offsetLayout, int* sizeLayout, int val, int field_a4_val, int field_a8_val);
};

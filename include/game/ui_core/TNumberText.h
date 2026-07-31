#pragma once

#include "compat.h"

#include "game/ui_core/TEditText.h"

class CMcWindow;

// VTABLE: IMPERIALISM 0x0063e8b0
class TNumberText : public TEditText {
public:
  int value;        // 0xa0
  int minimumValue; // 0xa4
  int maximumValue; // 0xa8

  DECLARE_DYNCREATE(TNumberText)
  ~TNumberText() override;          // slot 0x01 (0x429530)
  TObject* ShallowClone() override; // slot 0x08 (0x4912b0)

  using TEditText::SetEnable;

  // New virtual methods
  virtual void SetControlValue(int val, int refresh); // slot 0x79 (0x4910e0)
  virtual int UpdateControlCachedIntFromWindowText(); // slot 0x7a (0x4911c0)

  // FUNCTION: IMPERIALISM 0x00429500
  TNumberText() : TEditText() {
    value = 0;
  }
  void INumberText(TView* panel, int* offsetLayout, int* sizeLayout, int value, int minimumValue,
                   int maximumValue);
};
ASSERT_SIZE(TNumberText, 0xac);

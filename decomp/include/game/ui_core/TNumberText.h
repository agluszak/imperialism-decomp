#pragma once

#include "compat.h"

#include "game/ui_core/TEditText.h"

class CMcWindow;

// VTABLE: IMPERIALISM 0x0063e8b0
class TNumberText : public TEditText {
public:
  int value;
  int minimumValue;
  int maximumValue;

  DECLARE_DYNCREATE(TNumberText)
  ~TNumberText() override;
  TObject* ShallowClone() override;

  // New virtual methods
  virtual void SetControlValue(int val, int refresh);
  virtual int UpdateControlCachedIntFromWindowText();

  // FUNCTION: IMPERIALISM 0x00429500
  TNumberText() {
    value = 0;
  }
  void INumberText(TView* panel, int* offsetLayout, int* sizeLayout, int value, int minimumValue,
                   int maximumValue);
};
ASSERT_SIZE(TNumberText, 0xac);

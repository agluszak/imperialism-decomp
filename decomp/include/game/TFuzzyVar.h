#pragma once

#include "game/app/TObject.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00656998
class TFuzzyVar : public TObject {
public:
  DECLARE_DYNCREATE(TFuzzyVar)
  virtual ~TFuzzyVar() override;

  TFuzzyVar() {}

  void IFuzzyVar(float v0, float v1, float v2, float v3);

  float Membership(int input);
  float Membership(float input);

  float values[4];
};

ASSERT_SIZE(TFuzzyVar, 0x14);

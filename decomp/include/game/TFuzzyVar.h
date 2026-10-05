#pragma once

#include "game/app/TObject.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00656998
class TFuzzyVar : public TObject {
public:
  DECLARE_DYNCREATE(TFuzzyVar)
  virtual ~TFuzzyVar() override; // slot 0x01 (scalar deleting destructor)

  TFuzzyVar() {}

  void IFuzzyVar(float v0, float v1, float v2, float v3);

  float Membership(int input);   // 0x004ff550
  float Membership(float input); // 0x004ff5f0

  float values[4]; // +0x4..+0x10
};

ASSERT_SIZE(TFuzzyVar, 0x14);

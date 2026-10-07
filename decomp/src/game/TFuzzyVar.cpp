#include "game/TFuzzyVar.h"

IMPLEMENT_DYNCREATE(TFuzzyVar, TObject)

TFuzzyVar::~TFuzzyVar() {}

// FUNCTION: IMPERIALISM 0x004ff520
void TFuzzyVar::IFuzzyVar(float v0, float v1, float v2, float v3) {
  values[0] = v0;
  values[1] = v1;
  values[2] = v2;
  values[3] = v3;
}

// FUNCTION: IMPERIALISM 0x004ff550
float TFuzzyVar::Membership(int input) {
  float x = static_cast<float>(input);
  if (x > values[0]) {
    if (x < values[1]) {
      return (x - values[0]) / (values[1] - values[0]);
    }
    if (x <= values[2]) {
      return 1.0f;
    }
    if (x < values[3]) {
      return (values[3] - x) / (values[3] - values[2]);
    }
  }
  return 0.0f;
}

// FUNCTION: IMPERIALISM 0x004ff5f0
float TFuzzyVar::Membership(float input) {
  if (input > values[0]) {
    if (input < values[1]) {
      return (input - values[0]) / (values[1] - values[0]);
    }
    if (input <= values[2]) {
      return 1.0f;
    }
    if (input < values[3]) {
      return (values[3] - input) / (values[3] - values[2]);
    }
  }
  return 0.0f;
}

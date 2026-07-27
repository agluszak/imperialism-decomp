#include "game/TFuzzyVar.h"
// SYNTHETIC: IMPERIALISM 0x004ff460
// TFuzzyVar::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ff490
// TFuzzyVar::GetRuntimeClass

IMPLEMENT_DYNCREATE(TFuzzyVar, TObject)

// Complete-object destructor tail, called from the scalar deleting destructor
// at 0x4ff4d0; Ghidra had mis-bucketed this as TFuzzySet::CreateTFuzzySetInstance.
// SYNTHETIC: IMPERIALISM 0x004ff500
// TFuzzyVar::~TFuzzyVar
TFuzzyVar::~TFuzzyVar() {}

// SYNTHETIC: IMPERIALISM 0x004ff4d0
// TFuzzyVar::`scalar deleting destructor'

// Mac oracle: IFuzzyVar.
// FUNCTION: IMPERIALISM 0x004ff520
void TFuzzyVar::IFuzzyVar(float v0, float v1, float v2, float v3) {
  values[0] = v0;
  values[1] = v1;
  values[2] = v2;
  values[3] = v3;
}

#include "game/TFuzzyVar.h"
// SYNTHETIC: IMPERIALISM 0x004ff460
// TFuzzyVar::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ff490
// TFuzzyVar::GetRuntimeClass

IMPLEMENT_DYNCREATE(TFuzzyVar, TObject)

TFuzzyVar::TFuzzyVar() {}

// Complete-object destructor tail, called from the scalar deleting destructor
// at 0x4ff4d0; Ghidra had mis-bucketed this as TFuzzySet::CreateTFuzzySetInstance.
// SYNTHETIC: IMPERIALISM 0x004ff500
// TFuzzyVar::~TFuzzyVar
TFuzzyVar::~TFuzzyVar() {}

// FUNCTION: IMPERIALISM 0x004ff7d0
void TFuzzyVar::AllocateAndAppendRecord(int param1, int param2, int param3, int param4) {
  TFuzzyVar* record = new TFuzzyVar();
  record->field_0x4 = param1;
  record->field_0x8 = param2;
  record->field_0xc = param3;
  record->field_0x10 = param4;
  *reinterpret_cast<TFuzzyVar**>(&field_0x8 + field_0x4) = record;
  ++field_0x4;
}

// SYNTHETIC: IMPERIALISM 0x004ff4d0
// TFuzzyVar::`scalar deleting destructor'

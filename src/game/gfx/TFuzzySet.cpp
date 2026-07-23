#include "game/gfx/TFuzzySet.h"

#include <stdlib.h>

#include "game/TFuzzyVar.h"
// SYNTHETIC: IMPERIALISM 0x004ff690
// TFuzzySet::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ff6c0
// TFuzzySet::GetRuntimeClass

IMPLEMENT_DYNCREATE(TFuzzySet, TObject)

// Own-vtable-set ctor body, called out-of-line from InitializeCityInteriorMinister;
// inlined directly within CreateObject. Ghidra had named this ConstructTFuzzySetBaseState.
// SYNTHETIC: IMPERIALISM 0x004ff6e0
// TFuzzySet::TFuzzySet
TFuzzySet::TFuzzySet() {}

// SYNTHETIC: IMPERIALISM 0x004ff700
// TFuzzySet::`scalar deleting destructor'

// Complete-object destructor tail, called from the scalar deleting destructor
// at 0x4ff700. Ghidra had named this DestructTFuzzySetAndMaybeFree_Impl.
// SYNTHETIC: IMPERIALISM 0x004ff730
// TFuzzySet::~TFuzzySet
TFuzzySet::~TFuzzySet() {}

// FUNCTION: IMPERIALISM 0x004ff750
void TFuzzySet::Clear() {
  m_memberCount = 0;
  for (int i = 0; i < 10; ++i) {
    m_members[i] = nullptr;
  }
}

// FUNCTION: IMPERIALISM 0x004ff780
void TFuzzySet::Free() {
  for (int i = 0; i < m_memberCount; ++i) {
    m_members[i]->Free();
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x004ff840
int TFuzzySet::SelectWeightedMemberIndex(float input) {
  float weights[10];
  float totalWeight = 0.0f;
  int index;
  for (index = 0; index < m_memberCount; ++index) {
    TFuzzyVar* member = static_cast<TFuzzyVar*>(m_members[index]);
    float weight = 0.0f;
    if (input > member->values[0]) {
      if (input < member->values[1]) {
        weight = (input - member->values[0]) / (member->values[1] - member->values[0]);
      } else if (input <= member->values[2]) {
        weight = 1.0f;
      } else if (input < member->values[3]) {
        weight = (member->values[3] - input) / (member->values[3] - member->values[2]);
      }
    }
    weights[index] = weight;
    totalWeight += weight;
  }

  if (totalWeight == 0.0f) {
    return -1;
  }
  for (index = 0; index < m_memberCount; ++index) {
    weights[index] /= totalWeight;
  }

  float selection = static_cast<float>(rand() & 0x3fff) * 0.00006103515625f;
  index = 0;
  while (index < 10 && selection > weights[index]) {
    selection -= weights[index];
    ++index;
  }
  return index < 10 ? index : -1;
}

// AllocateAndAppendRecord (0x4ff7d0) is defined in its own TU
// (TFuzzySet_AllocateAndAppendRecord.cpp) to keep it out of this file's PDB line
// table, which otherwise crosses its symbol with the adjacent Free() and makes reccmp
// mis-pair both.

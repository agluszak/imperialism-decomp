#include "game/gfx/TFuzzySet.h"

#include <stdlib.h>

#include "game/TFuzzyVar.h"

IMPLEMENT_DYNCREATE(TFuzzySet, TObject)

TFuzzySet::TFuzzySet() {}

TFuzzySet::~TFuzzySet() {}

// FUNCTION: IMPERIALISM 0x004ff750
void TFuzzySet::IFuzzySet() {
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

// FUNCTION: IMPERIALISM 0x004ff7d0
void TFuzzySet::AddFuzzyVar(float value0, float value1, float value2, float value3) {
  TFuzzyVar* record = new TFuzzyVar();
  record->values[0] = value0;
  record->values[1] = value1;
  record->values[2] = value2;
  record->values[3] = value3;
  m_members[m_memberCount] = record;
  ++m_memberCount;
}

// FUNCTION: IMPERIALISM 0x004ff840
int TFuzzySet::GetCrispOutput(float input) {
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

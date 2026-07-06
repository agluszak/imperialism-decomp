#include "game/TFuzzySet.h"
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

// Complete-object destructor tail, called from the scalar deleting destructor
// at 0x4ff700. Ghidra had named this DestructTFuzzySetAndMaybeFree_Impl.
// SYNTHETIC: IMPERIALISM 0x004ff730
// TFuzzySet::~TFuzzySet
TFuzzySet::~TFuzzySet() {}

// FUNCTION: IMPERIALISM 0x004ff780
void TFuzzySet::Free() {
  for (int i = 0; i < m_memberCount; ++i) {
    m_members[i]->Free();
  }
  delete this;
}

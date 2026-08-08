#include "game/gfx/TFuzzySet.h"

#include "game/TFuzzyVar.h"

// Isolated in its own TU: when this method sits next to TFuzzySet::Free() in
// TFuzzySet.cpp, reccmp crosses the two functions' PDB line/symbol resolution and
// mis-pairs both (each drops to ~11%). The binary is identical either way; the split
// only keeps the two adjacent bodies in separate line tables so reccmp resolves each
// unambiguously.

// Allocates a fresh TFuzzyVar leaf, stores the four fuzzy values into it, and appends
// it to m_members (indexed by the current count). Ghidra had attributed this to
// TFuzzyVar; its receiver is a 0x30-byte TFuzzySet (count@0x4 + m_members[10]@0x8),
// not the 0x14-byte TFuzzyVar leaf it allocates.
// FUNCTION: IMPERIALISM 0x004ff7d0
void TFuzzySet::AllocateAndAppendRecord(float value0, float value1, float value2, float value3) {
  TFuzzyVar* record = new TFuzzyVar();
  record->values[0] = value0;
  record->values[1] = value1;
  record->values[2] = value2;
  record->values[3] = value3;
  m_members[m_memberCount] = record;
  ++m_memberCount;
}

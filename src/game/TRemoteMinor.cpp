#include "game/TRemoteMinor.h"

#include <new>

// SYNTHETIC: IMPERIALISM 0x00541c10
// TRemoteMinor::CreateObject

// SYNTHETIC: IMPERIALISM 0x00541d70
// TRemoteMinor::GetRuntimeClass

// Binary descriptor base points at itself (0x65b020), not TMinor — reproducing the
// original IMPLEMENT_DYNCREATE(TRemoteMinor, TRemoteMinor) copy-paste bug byte-for-byte.
IMPLEMENT_DYNCREATE(TRemoteMinor, TRemoteMinor)

// FUNCTION: IMPERIALISM 0x00541c90
char TRemoteMinor::ShouldDispatchImmediatelySlot28(void) {
  return 1;
}

// FUNCTION: IMPERIALISM 0x00541cb0
void TRemoteMinor::ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                                  int multiplier) {
  (void)resourceIndex;
  (void)delta;
  (void)multiplier;
}

// SYNTHETIC: IMPERIALISM 0x00541cd0
// TRemoteMinor::`scalar deleting destructor'
TRemoteMinor::~TRemoteMinor() {}

TRemoteMinor::TRemoteMinor() : TMinor() {}

// FUNCTION: IMPERIALISM 0x00541d90
void TRemoteMinor::NoOpNationSelectedRegionAndMapCellLabelHook(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
}

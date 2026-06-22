#include "game/TRemoteMinor.h"

#include <new>

static const unsigned int kAddrClassDescTRemoteMinor = 0x0065b020;

// FUNCTION: IMPERIALISM 0x00541c10
void* TRemoteMinor::AllocateAndConstructTRemoteMinor() {
  return new TRemoteMinor();
}

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

// FUNCTION: IMPERIALISM 0x00541d70
CRuntimeClass* TRemoteMinor::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(kAddrClassDescTRemoteMinor);
}

void* TRemoteMinor::GetTRemoteMinorClassNamePointer() {
  return reinterpret_cast<void*>(kAddrClassDescTRemoteMinor);
}

// FUNCTION: IMPERIALISM 0x00541d90
void TRemoteMinor::NoOpNationSelectedRegionAndMapCellLabelHook(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
}

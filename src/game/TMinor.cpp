#include "game/TMinor.h"

#include <new>

static const unsigned int kAddrClassDescTMinor = 0x006536a0;

// FUNCTION: IMPERIALISM 0x00406ee7
void* TMinor::thunk_GetTMinorClassNamePointer_At00406ee7(void) {
  return GetTMinorClassNamePointer();
}

// FUNCTION: IMPERIALISM 0x004e3660
void* TMinor::CreateTMinorInstance() {
  return new TMinor();
}

// FUNCTION: IMPERIALISM 0x004e36f0
void* TMinor::GetTMinorClassNamePointer() {
  return reinterpret_cast<void*>(kAddrClassDescTMinor);
}

void* TMinor::GetClassDescPointerSlot00(void) {
  return GetTMinorClassNamePointer();
}

// FUNCTION: IMPERIALISM 0x004e3710
TMinor::TMinor() : identitySharedString0(), identitySharedString1(), ownerNationSlot0e(0) {}

// Destructor is compiler-generated (implicit) from CString members + vtable.
// SYNTHETIC: IMPERIALISM 0x004e3790
// TMinor::`scalar deleting destructor'

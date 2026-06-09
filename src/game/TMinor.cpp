#include "game/TMinor.h"

#include <new>

static const unsigned int kAddrClassDescTMinor = 0x006536a0;
static const unsigned int kMinorObjectSizeBytes = 0x2dc;

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);

// FUNCTION: IMPERIALISM 0x00406ee7
void* TMinor::thunk_GetTMinorClassNamePointer_At00406ee7(void) {
  return GetTMinorClassNamePointer();
}

// FUNCTION: IMPERIALISM 0x00406988
void* TMinor::thunk_DestructTMinorAndMaybeFree_At00406988(unsigned char freeSelfFlag) {
  return DestructTMinorAndMaybeFree(freeSelfFlag);
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

// FUNCTION: IMPERIALISM 0x004e3660
void* TMinor::CreateTMinorInstance() {
  TMinor* instance = reinterpret_cast<TMinor*>(AllocateWithFallbackHandler(kMinorObjectSizeBytes));
  if (instance == 0) {
    return 0;
  }
  new (instance) TMinor();
  return instance;
}

// FUNCTION: IMPERIALISM 0x004e3790
void* TMinor::DestructTMinorAndMaybeFree(unsigned char freeSelfFlag) {
  this->~TMinor();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(reinterpret_cast<undefined4>(this));
  }
  return this;
}

#include "game/TCountingStream.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

void FreeHeapBufferIfNotNull(undefined4 ptrValue);
undefined4 thunk_DestructTObjectAndMaybeFree(void);

extern "C" {
char g_pClassDescTCountingStream = 0;
}

// FUNCTION: IMPERIALISM 0x004893f0
void* TCountingStream::GetRuntimeClass() {
  return &g_pClassDescTCountingStream;
}

// FUNCTION: IMPERIALISM 0x00489410
TCountingStream::TCountingStream() {
  this->maxExtentOrLimit = 0;
  this->positionOrByteCount = 0;
}

// FUNCTION: IMPERIALISM 0x00489470
void TCountingStream::DestructTCountingStreamBaseState() {
  ::thunk_DestructTObjectAndMaybeFree();
}

// FUNCTION: IMPERIALISM 0x00489440
void* TCountingStream::DestructTCountingStreamAndMaybeFree(byte freeSelfFlag) {
  this->DestructTCountingStreamBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(this)));
  }
  return this;
}

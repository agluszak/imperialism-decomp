#include "game/stream.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

void FreeHeapBufferIfNotNull(undefined4 ptrValue);
undefined4 thunk_DestructTObjectAndMaybeFree(void);

// Shared CObject runtime-class vtable (defined in TCapacityOrder.cpp).
extern char PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;

extern "C" {
char g_pClassDescTFileStream = 0;
char g_pClassDescTCountingStream = 0;
char g_pClassDescTHandleStream = 0;
}

// ---- TFileStream ----------------------------------------------------------

// FUNCTION: IMPERIALISM 0x004890f0
void* TFileStream::GetRuntimeClass() {
  return &g_pClassDescTFileStream;
}

// FUNCTION: IMPERIALISM 0x00489110
TFileStream::TFileStream() {
  backingArchiveOrStream = 0;
}

// SYNTHETIC: IMPERIALISM 0x00489130
void* TFileStream::DestructTFileStreamAndMaybeFree(unsigned int flags) {
  ::thunk_DestructTObjectAndMaybeFree(); // or whatever the real complete teardown is
  if ((flags & 1) != 0) {
    FreeHeapBufferIfNotNull(reinterpret_cast<undefined4>(this));
  }
  return this;
}

// ---- TCountingStream ------------------------------------------------------

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

// ---- THandleStream --------------------------------------------------------

// FUNCTION: IMPERIALISM 0x004895c0
void* THandleStream::GetRuntimeClass() {
  return &g_pClassDescTHandleStream;
}

// FUNCTION: IMPERIALISM 0x004895e0
THandleStream::THandleStream() {
  this->position = 1;
  this->directionOrMode = 0;
  this->highWatermark = 0;
  this->ownsHandleOrDirty = 0;
  this->handleOrBuffer = 0;
}

// FUNCTION: IMPERIALISM 0x00489640
void THandleStream::DestructTHandleStreamBaseState() {
  *reinterpret_cast<void**>(this) =
      reinterpret_cast<void*>(&PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4);
}

// FUNCTION: IMPERIALISM 0x00489610
void* THandleStream::DestructTHandleStreamAndMaybeFree(byte freeSelfFlag) {
  this->DestructTHandleStreamBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(this)));
  }
  return this;
}

#include "game/THandleStream.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

void FreeHeapBufferIfNotNull(undefined4 ptrValue);

// Shared CObject runtime-class vtable (defined in TCapacityOrder.cpp).
extern char PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;

extern "C" {
char g_pClassDescTHandleStream = 0;
}

// FUNCTION: IMPERIALISM 0x004895c0
void* THandleStream::GetRuntimeClass() {
  return &g_pClassDescTHandleStream;
}

// FUNCTION: IMPERIALISM 0x004895e0
THandleStream::THandleStream() {
  this->position = 1;
  this->currentExtent = 0;
  this->highWatermark = 0;
  this->ownsHandleOrDirty = 0;
  this->handleOrBuffer = 0;
}

// FUNCTION: IMPERIALISM 0x00489550
void THandleStream::AdvanceExtent(int handle, int delta) {
  (void)handle;
  this->currentExtent += delta;
  if (this->currentExtent > this->highWatermark) {
    this->highWatermark = this->currentExtent;
  }
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

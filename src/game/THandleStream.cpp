#include "game/THandleStream.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTHandleStream = 0;
}

// FUNCTION: IMPERIALISM 0x004895c0
CRuntimeClass* THandleStream::GetRuntimeClass() {
  return reinterpret_cast<CRuntimeClass*>(&g_pClassDescTHandleStream);
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

// Destructors are compiler-generated (implicit) from real TStream inheritance.
// SYNTHETIC: IMPERIALISM 0x00489640
// THandleStream::~THandleStream

// SYNTHETIC: IMPERIALISM 0x00489610
// THandleStream::`scalar deleting destructor'

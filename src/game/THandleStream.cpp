#include "game/THandleStream.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTHandleStream = 0;
}

// FUNCTION: IMPERIALISM 0x00489550
void THandleStream::AdvanceExtent(int handle, int delta) {
  (void)handle;
  this->currentExtent += delta;
  if (this->currentExtent > this->highWatermark) {
    this->highWatermark = this->currentExtent;
  }
}

// FUNCTION: IMPERIALISM 0x004895c0
CRuntimeClass* THandleStream::GetRuntimeClass() const {
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

// SYNTHETIC: IMPERIALISM 0x00489610
// THandleStream::`scalar deleting destructor'

// Destructors are compiler-generated (implicit) from real TStream inheritance.
// SYNTHETIC: IMPERIALISM 0x00489640
// THandleStream::~THandleStream

// FUNCTION: IMPERIALISM 0x004896a0
void THandleStream::streamSlot1c() {}

// FUNCTION: IMPERIALISM 0x004896e0
int THandleStream::streamSlot28() {
  return highWatermark;
}

// FUNCTION: IMPERIALISM 0x00489700
int THandleStream::streamSlot30() {
  return handleOrBuffer;
}

// FUNCTION: IMPERIALISM 0x00489740
void THandleStream::streamSlot2c() {}

// FUNCTION: IMPERIALISM 0x00489760
void THandleStream::streamSlot34() {}

// FUNCTION: IMPERIALISM 0x004897a0
void THandleStream::ReadBytes(void* buffer, int sizeBytes) {
  (void)buffer;
  (void)sizeBytes;
}

// FUNCTION: IMPERIALISM 0x00489810
void THandleStream::WriteBytesSlot78(void* data, int length) {
  (void)data;
  (void)length;
}

#include "game/core/THandleStream.h"

#include <string.h>

IMPLEMENT_DYNCREATE(THandleStream, TStream)

// FUNCTION: IMPERIALISM 0x004895e0
THandleStream::THandleStream() {
  this->growthSize = 1;
  this->attachedGlobalHandle = 0;
  this->streamPosition = 0;
  this->unclassifiedByte14 = 0;
  this->attachedSizeBytes = 0;
}

// FUNCTION: IMPERIALISM 0x00489660
void THandleStream::IHandleStream(HGLOBAL memoryHandle, int growthSize) {
  this->growthSize = growthSize;
  this->streamPosition = 0;
  if (memoryHandle != 0) {
    this->attachedSizeBytes = GlobalSize(memoryHandle);
    this->attachedGlobalHandle = memoryHandle;
  }
}

// FUNCTION: IMPERIALISM 0x004896a0
void THandleStream::Free() {
  if (attachedGlobalHandle != 0) {
    SetLength(GetPosition());
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x004896e0
int THandleStream::GetPosition() {
  return streamPosition;
}

// FUNCTION: IMPERIALISM 0x00489700
int THandleStream::GetLength() {
  return attachedSizeBytes;
}

// FUNCTION: IMPERIALISM 0x00489720
int THandleStream::GrowthSize(int requestedSize) {
  if (growthSize <= requestedSize) {
    return requestedSize;
  }
  return growthSize;
}

// Seek: store the requested position directly (no clamp for the handle stream).
// FUNCTION: IMPERIALISM 0x00489740
void THandleStream::SetPosition(int position) {
  streamPosition = position;
}

// FUNCTION: IMPERIALISM 0x00489760
void THandleStream::SetLength(int length) {
  GlobalReAlloc(attachedGlobalHandle, length, 0);
  if (length < streamPosition) {
    streamPosition = length;
  }
  attachedSizeBytes = length;
}

// FUNCTION: IMPERIALISM 0x004897a0
void THandleStream::ReadBytes(void* buffer, int sizeBytes) {
  int available = attachedSizeBytes - streamPosition;
  if (available < sizeBytes) {
    sizeBytes = available;
  }
  if (sizeBytes > 0) {
    char* bytes = static_cast<char*>(GlobalLock(attachedGlobalHandle));
    memmove(buffer, bytes + streamPosition, sizeBytes);
    GlobalUnlock(attachedGlobalHandle);
    streamPosition += sizeBytes;
  }
}

// FUNCTION: IMPERIALISM 0x00489810
void THandleStream::WriteBytes(const void* data, int length) {
  int available = attachedSizeBytes - streamPosition;
  if (available < length) {
    SetLength(attachedSizeBytes + GrowthSize(length - available));
  }
  char* bytes = static_cast<char*>(GlobalLock(attachedGlobalHandle));
  memmove(bytes + streamPosition, data, length);
  GlobalUnlock(attachedGlobalHandle);
  streamPosition += length;
  if (streamPosition > attachedSizeBytes) {
    attachedSizeBytes = streamPosition;
  }
}

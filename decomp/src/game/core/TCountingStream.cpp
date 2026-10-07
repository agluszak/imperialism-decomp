#include "game/core/TCountingStream.h"

IMPLEMENT_DYNCREATE(TCountingStream, TStream)

// FUNCTION: IMPERIALISM 0x00489410
TCountingStream::TCountingStream() {
  this->maxExtentOrLimit = 0;
  this->positionOrByteCount = 0;
}

// FUNCTION: IMPERIALISM 0x00489490
void TCountingStream::ICountingStream() {}

// FUNCTION: IMPERIALISM 0x004894b0
int TCountingStream::GetPosition() {
  return positionOrByteCount;
}

// Seek: clamp the requested position to the tracked extent, store as current.
// FUNCTION: IMPERIALISM 0x004894d0
void TCountingStream::SetPosition(int position) {
  if (position > maxExtentOrLimit) {
    position = maxExtentOrLimit;
  }
  positionOrByteCount = position;
}

// FUNCTION: IMPERIALISM 0x00489500
int TCountingStream::GetLength() {
  return maxExtentOrLimit;
}

// Mark: lower the current position if the mark precedes it, then record the mark.
// FUNCTION: IMPERIALISM 0x00489520
void TCountingStream::SetLength(int position) {
  if (position < positionOrByteCount) {
    positionOrByteCount = position;
  }
  maxExtentOrLimit = position;
}

// FUNCTION: IMPERIALISM 0x00489550
void TCountingStream::WriteBytes(const void* data, int length) {
  this->positionOrByteCount += length;
  if (this->positionOrByteCount > this->maxExtentOrLimit) {
    this->maxExtentOrLimit = this->positionOrByteCount;
  }
}

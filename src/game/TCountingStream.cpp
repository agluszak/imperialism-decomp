#include "game/TCountingStream.h"

extern "C" {
char g_pClassDescTCountingStream = 0;
}

// SYNTHETIC: IMPERIALISM 0x004893c0
// TCountingStream::CreateObject

// SYNTHETIC: IMPERIALISM 0x004893f0
// TCountingStream::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCountingStream, TStream)

// ReadBytes (slot 0x3c, 0x00488b40) is inherited unchanged from TStream;
// TCountingStream only overrides the byte-counting write path (WriteBytesSlot78).

// FUNCTION: IMPERIALISM 0x00489410
TCountingStream::TCountingStream() {
  this->maxExtentOrLimit = 0;
  this->positionOrByteCount = 0;
}

// SYNTHETIC: IMPERIALISM 0x00489440
// TCountingStream::`scalar deleting destructor'
TCountingStream::~TCountingStream() {}

// SYNTHETIC: IMPERIALISM 0x00489470
// TCountingStream::~TCountingStream

// FUNCTION: IMPERIALISM 0x004894b0
int TCountingStream::streamSlot28() {
  return positionOrByteCount;
}

// FUNCTION: IMPERIALISM 0x004894d0
void TCountingStream::streamSlot2c(void*) {}

// FUNCTION: IMPERIALISM 0x00489500
int TCountingStream::streamSlot30() {
  return maxExtentOrLimit;
}

// FUNCTION: IMPERIALISM 0x00489520
void TCountingStream::streamSlot34(void*) {}

// FUNCTION: IMPERIALISM 0x00489550
void TCountingStream::WriteBytesSlot78(void* data, int length) {
  (void)data;
  this->positionOrByteCount += length;
  if (this->positionOrByteCount > this->maxExtentOrLimit) {
    this->maxExtentOrLimit = this->positionOrByteCount;
  }
}

#include "game/TCountingStream.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTCountingStream = 0;
}

// FUNCTION: IMPERIALISM 0x00488b40
void TCountingStream::ReadBytes(void* buffer, int sizeBytes) {
  (void)buffer;
  (void)sizeBytes;
}

// FUNCTION: IMPERIALISM 0x004893f0
CRuntimeClass* TCountingStream::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(&g_pClassDescTCountingStream);
}

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
void TCountingStream::streamSlot2c() {}

// FUNCTION: IMPERIALISM 0x00489500
int TCountingStream::streamSlot30() {
  return maxExtentOrLimit;
}

// FUNCTION: IMPERIALISM 0x00489520
void TCountingStream::streamSlot34() {}

undefined TCountingStream::OrphanRetStub_00488e70() { return 0; }
undefined TCountingStream::OrphanRetStub_00488e30(void) { return 0; }
undefined TCountingStream::OrphanRetStub_00488e50(void) { return 0; }
undefined TCountingStream::OrphanTiny_ReturnZero_00488ad0(void) { return 0; }
undefined TCountingStream::OrphanTiny_ReturnZero_00488af0(void) { return 0; }

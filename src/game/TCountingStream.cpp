#include "game/TCountingStream.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTCountingStream = 0;
}

// FUNCTION: IMPERIALISM 0x004893f0
CRuntimeClass* TCountingStream::GetRuntimeClass() {
  return reinterpret_cast<CRuntimeClass*>(&g_pClassDescTCountingStream);
}

// FUNCTION: IMPERIALISM 0x00489410
TCountingStream::TCountingStream() {
  this->maxExtentOrLimit = 0;
  this->positionOrByteCount = 0;
}

// SYNTHETIC: IMPERIALISM 0x00489440
// TCountingStream::`scalar deleting destructor'

// Destructors are compiler-generated (implicit) from real TStream inheritance.
// SYNTHETIC: IMPERIALISM 0x00489470
// TCountingStream::~TCountingStream

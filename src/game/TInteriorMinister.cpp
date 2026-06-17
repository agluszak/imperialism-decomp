#include "game/TInteriorMinister.h"

#include "game/TStream.h"

extern "C" {
CRuntimeClass g_pClassDescTInteriorMinister = {nullptr, 0, 0, nullptr, nullptr};
}

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x004be1b0
CRuntimeClass* TInteriorMinister::GetRuntimeClass() const {
  return &g_pClassDescTInteriorMinister;
}

// FUNCTION: IMPERIALISM 0x004be1d0
TInteriorMinister::TInteriorMinister() : TMinister() {}

// SYNTHETIC: IMPERIALISM 0x004be200
// TInteriorMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004be290
void TInteriorMinister::ReadFrom(TStream* stream) {
  TMinister::ReadFrom(stream);
  stream->ReadBytes(reinterpret_cast<char*>(this) + 0x10, 2);
  stream->ReadBytes(reinterpret_cast<char*>(this) + 0x12, 2);
  stream->ReadBytes(reinterpret_cast<char*>(this) + 0x14, 2);
  stream->ReadBytes(reinterpret_cast<char*>(this) + 0x16, 2);
  stream->ReadBytes(reinterpret_cast<char*>(this) + 0x18, 0x2c);
}

// FUNCTION: IMPERIALISM 0x004be320
void TInteriorMinister::WriteTo(TStream* stream) {
  SerializeTMinisterBaseOrderArrayHeader(stream);
}

// FUNCTION: IMPERIALISM 0x004be3c0
void TInteriorMinister::MinisterSlot0A() {}

// FUNCTION: IMPERIALISM 0x004be450
void TInteriorMinister::MinisterSlot12() {}

// FUNCTION: IMPERIALISM 0x004be4f0
void TInteriorMinister::Call4C() {}

// FUNCTION: IMPERIALISM 0x004be520
void TInteriorMinister::MinisterSlot14() {}

// FUNCTION: IMPERIALISM 0x004be5b0
void TInteriorMinister::Call54() {}

// FUNCTION: IMPERIALISM 0x004be6d0
void TInteriorMinister::NotifySlot44(void* receiver) {
  (void)receiver;
}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

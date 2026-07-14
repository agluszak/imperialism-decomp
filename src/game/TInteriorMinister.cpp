#include "game/TInteriorMinister.h"

#include "game/TStream.h"

// Slots 0x16-0x1f own bodies (honest stubs; slot ownership drives vtable matching).
// FUNCTION: IMPERIALISM 0x004be150
short TInteriorMinister::InteriorSlot1D(int arg) {
  return static_cast<short>(arg);
}

// FUNCTION: IMPERIALISM 0x004be170
short TInteriorMinister::InteriorSlot1E(int arg) {
  return static_cast<short>(arg);
}

// FUNCTION: IMPERIALISM 0x004be190
void TInteriorMinister::InteriorSlot1F(int) {}
// SYNTHETIC: IMPERIALISM 0x004be0d0
// TInteriorMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x004be1b0
// TInteriorMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TInteriorMinister, TMinister)

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
short TInteriorMinister::DispatchNationStateEventCode10(short nationSlot) {
  (void)nationSlot;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004be3f0
void TInteriorMinister::InteriorSlot1A() {}

// FUNCTION: IMPERIALISM 0x004be410
void TInteriorMinister::InteriorSlot1B() {}

// FUNCTION: IMPERIALISM 0x004be430
void TInteriorMinister::InteriorSlot1C() {}

// FUNCTION: IMPERIALISM 0x004be450
void TInteriorMinister::MinisterSlot12() {}

// FUNCTION: IMPERIALISM 0x004be480
void TInteriorMinister::InteriorSlot16() {}

// FUNCTION: IMPERIALISM 0x004be4c0
void TInteriorMinister::InteriorSlot17() {}

// FUNCTION: IMPERIALISM 0x004be4f0
void TInteriorMinister::Call4C() {}

// FUNCTION: IMPERIALISM 0x004be520
void TInteriorMinister::MinisterSlot14() {}

// FUNCTION: IMPERIALISM 0x004be5b0
void TInteriorMinister::Call54() {}

// FUNCTION: IMPERIALISM 0x004be650
void TInteriorMinister::InteriorSlot18() {}

// FUNCTION: IMPERIALISM 0x004be690
void TInteriorMinister::InteriorSlot19() {}

// FUNCTION: IMPERIALISM 0x004be6d0
void TInteriorMinister::NoOpForeignMinisterUtilityStub(void* receiver) {
  (void)receiver;
}

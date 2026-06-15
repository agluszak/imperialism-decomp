#include "game/TMinister.h"

#include "game/CRuntimeClass.h"
#include "game/TMinisterBaseOrderArray.h"
#include "game/TStream.h"

#include <new>

void __stdcall NoOpForeignMinisterUtilityStub(int);

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
CRuntimeClass g_pClassDescTMinister = {nullptr, 0, 0, nullptr, nullptr};
}

int AllocateWithFallbackHandler(undefined4 size_bytes);

// FUNCTION: IMPERIALISM 0x0052eb60
CRuntimeClass* TMinister::GetRuntimeClass() const {
  return &g_pClassDescTMinister;
}

// FUNCTION: IMPERIALISM 0x0052eb80
#pragma optimize("y", on)
TMinister::TMinister() : ownerContextAt04(0), field_8(0), skillIndexC(0) {}
#pragma optimize("", on)

// Destructors are compiler-generated (implicit) from real CObject inheritance.
// SYNTHETIC: IMPERIALISM 0x0052eba0
// TMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0052ebf0
void TMinister::InitializeBaseOrderArray(undefined4 ownerContext) {
  this->ownerContextAt04 = ownerContext;
  void* storage = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x18));
  if (storage == 0) {
    this->field_8 = 0;
    return;
  }
  this->field_8 = new (storage) TMinisterBaseOrderArray();
}

// Slot 7 (0x1c): release the order array then delete self. This is the real base
// virtual body at 0x52ec80 (was a __fastcall free wrapper); inherited by every minister.
// FUNCTION: IMPERIALISM 0x0052ec80
void TMinister::Call1C() {
  if (this->field_8 != 0) {
    this->field_8->ReleaseSlot24();
  }
  this->field_8 = 0;
  delete this;
}

void TMinister::Serialize(CArchive* ar) {
  (void)ar;
}
void TMinister::AssertValidOrSlot0c() {}
void TMinister::DumpOrSlot10(int unused) {
  (void)unused;
}
void TMinister::InvokeObjectSlot20() {}
void TMinister::CopyPayloadSlot24() {}
void TMinister::NotifySlot44(void* receiver) {
  NoOpForeignMinisterUtilityStub(reinterpret_cast<int>(receiver));
}
void TMinister::MinisterSlot12() {}
void TMinister::Call4C() {}
void TMinister::MinisterSlot14() {}
void TMinister::Call54() {}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// FUNCTION: IMPERIALISM 0x0052ecc0
void TMinister::Call18(int arg1) {
  TStream* archive = reinterpret_cast<TStream*>(arg1);
  TMinister::Serialize(reinterpret_cast<CArchive*>(archive));
  archive->ReadBytes(&this->skillIndexC, 2);
}

// FUNCTION: IMPERIALISM 0x0052ecf0
void TMinister::SerializeTMinisterBaseOrderArrayHeader(TStream* archive) {
  TMinister::Serialize(reinterpret_cast<CArchive*>(archive));
  archive->WriteBytesSlot78(&this->skillIndexC, 2);
}

// Base-vtable slots 0x28-0x40. These were autogen stubs (slots left empty); the orig
// TMinister vtable points at these addresses, so they belong to the base class' own
// virtual methods. Bodies are honest placeholders pending full reconstruction.
// FUNCTION: IMPERIALISM 0x0052ed20
void TMinister::MinisterSlot0A() {}

// FUNCTION: IMPERIALISM 0x0052ed50
void TMinister::MinisterSlot0B() {}

// FUNCTION: IMPERIALISM 0x0052ee20
void TMinister::MinisterSlot0C() {}

// FUNCTION: IMPERIALISM 0x0052eea0
void TMinister::MinisterSlot0D() {}

// FUNCTION: IMPERIALISM 0x0052ef20
void TMinister::MinisterSlot0F() {}

// FUNCTION: IMPERIALISM 0x0052ef50
void TMinister::MinisterSlot10() {}

// FUNCTION: IMPERIALISM 0x0052ef80
void TMinister::MinisterSlot0E() {}

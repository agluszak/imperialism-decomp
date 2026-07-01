#include "game/TBehavior.h"

#include "game/mfc.h"

extern "C" char g_pClassDescTBehavior;
// SYNTHETIC: IMPERIALISM 0x00487180
// TBehavior::CreateObject

// SYNTHETIC: IMPERIALISM 0x004871c0
// TBehavior::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBehavior, TObject)

// FUNCTION: IMPERIALISM 0x004871e0
TBehavior::TBehavior() : TObject() {
  field_0x4 = 0x20202020;
  field_0x8 = 0;
  field_0xc = 1;
}

// SYNTHETIC: IMPERIALISM 0x00487210
// TBehavior::`scalar deleting destructor'
TBehavior::~TBehavior() {}

// FUNCTION: IMPERIALISM 0x00487280
void TBehavior::SetDword08(undefined4 value) {
  field_0x8 = value;
}

// FUNCTION: IMPERIALISM 0x004872a0
unsigned char TBehavior::GetFlag0C() {
  return field_0xc;
}

// FUNCTION: IMPERIALISM 0x004872c0
void TBehavior::SetFlag0C(unsigned char value) {
  field_0xc = value;
}

// FUNCTION: IMPERIALISM 0x004872e0
void TBehavior::NoOpSlot34(undefined4 value) {
  (void)value;
  return;
}

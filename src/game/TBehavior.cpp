#include "game/TBehavior.h"

#include "game/mfc.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" char g_pClassDescTBehavior;

// FUNCTION: IMPERIALISM 0x004871c0
CRuntimeClass* TBehavior::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(&g_pClassDescTBehavior);
}

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
undefined TBehavior::CreateTDialogBehaviorInstance(void) { return 0; }
undefined TBehavior::OrphanLeaf_NoCall_Ins02_004872a0(void) { return 0; }
undefined TBehavior::OrphanRetStub_004872e0(void) { return 0; }
undefined TBehavior::OrphanTiny_SetDwordEcxOffset_8_00487280(void) { return 0; }

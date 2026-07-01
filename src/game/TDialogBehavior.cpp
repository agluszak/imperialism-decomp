#include "game/TDialogBehavior.h"

extern "C" char g_pClassDescTDialogBehavior;
// SYNTHETIC: IMPERIALISM 0x00487300
// TDialogBehavior::CreateObject

IMPLEMENT_DYNCREATE(TDialogBehavior, TBehavior)

// FUNCTION: IMPERIALISM 0x00487370
TDialogBehavior::TDialogBehavior()
    : TBehavior(), field10(0), defaultCommandCode(0x20202020), cancelCommandCode(0x20202020),
      armedCommandCode(0x20202020), field20(1) {}

// SYNTHETIC: IMPERIALISM 0x004873b0
// TDialogBehavior::`scalar deleting destructor'
TDialogBehavior::~TDialogBehavior() {}

// FUNCTION: IMPERIALISM 0x00487400
void TDialogBehavior::SetUiColorDescriptorGoldTriplet(unsigned char flag, int colorA, int colorB) {
  field_0x4 = 0x646c6f67; // 'gold'
  field10 = flag;
  defaultCommandCode = colorA;
  cancelCommandCode = colorB;
}

// FUNCTION: IMPERIALISM 0x00487430
undefined TDialogBehavior::OrphanCallChain_C1_I13_00487430(undefined4 param_1, undefined4 param_2) {
  (void)param_2;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487470
undefined TDialogBehavior::OrphanCallChain_C1_I17_00487470(int param_1, int param_2) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004874b0
undefined TDialogBehavior::OrphanCallChain_C11_I88_004874b0(int param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004875d0
undefined TDialogBehavior::OrphanCallChain_C6_I49_004875d0(int param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487660
undefined TDialogBehavior::CreateTCommandInstance() {
  return 0;
}

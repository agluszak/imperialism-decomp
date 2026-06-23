#include "game/TDialogBehavior.h"

extern "C" char g_pClassDescTDialogBehavior;

// FUNCTION: IMPERIALISM 0x00487350
CRuntimeClass* TDialogBehavior::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(&g_pClassDescTDialogBehavior);
}

// SYNTHETIC: IMPERIALISM 0x004873b0
// TDialogBehavior::`scalar deleting destructor'
TDialogBehavior::~TDialogBehavior() {}

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

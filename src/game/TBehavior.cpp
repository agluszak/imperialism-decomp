#include "game/TBehavior.h"

// RTTI class descriptor placeholder (see GetRuntimeClass).
extern "C" char g_pClassDescTBehavior = 0;


// FUNCTION: IMPERIALISM 0x4871c0
CRuntimeClass* TBehavior::GetRuntimeClass() const {
  // TODO(manifest): port the body from Ghidra, then run the decomp loop.
  return 0; // TODO(manifest): real return value
}


// SYNTHETIC: IMPERIALISM 0x487210
// TBehavior::`scalar deleting destructor'

// TODO(manifest): emit the real ~TBehavior() with its own
// function marker at the real destructor address (find the destructor body in
// Ghidra; it is usually adjacent to the scalar deleting destructor).

// FUNCTION: IMPERIALISM 0x00487280
undefined TBehavior::OrphanTiny_SetDwordEcxOffset_8_00487280() {
  *(undefined4 *)&this->field_0x8 = param_1;
  return;
}

// FUNCTION: IMPERIALISM 0x004872a0
undefined TBehavior::OrphanLeaf_NoCall_Ins02_004872a0() {
  return this->field_0xc;
}

// FUNCTION: IMPERIALISM 0x004872c0
undefined TBehavior::CreateTDialogBehaviorInstance() {
  this->field_0xc = param_1;
  return;
}


// FUNCTION: IMPERIALISM 0x4872e0
undefined TBehavior::OrphanRetStub_004872e0() {
  // TODO(manifest): port the body from Ghidra, then run the decomp loop.
  return 0; // TODO(manifest): real return value
}


#include "game/TCommand.h"

// The compiler emits the 0x648e28 vtable write from the // VTABLE: annotation.

// FUNCTION: IMPERIALISM 0x00487800
CRuntimeClass* TCommand::GetRuntimeClass() const {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487820
TCommand::TCommand() : field04(0), field08(0), field0c(0), field10(0), field14(0) {}

// Vtable-shape placeholder bodies (the real slot implementations live elsewhere;
// these exist so the class emits its native vtable and derived classes can
// override individual slots through real C++ inheritance).

// SYNTHETIC: IMPERIALISM 0x00487850
// TCommand::`scalar deleting destructor'
TCommand::~TCommand() {}

// FUNCTION: IMPERIALISM 0x004878a0
void TCommand::InitializeRangePair(int arg1, int arg2, int arg3, int arg4, int arg5) {
  (void)arg3;
  (void)arg4;
  (void)arg5;
  int resolvedSecond = arg2;
  if (resolvedSecond == 0) {
    resolvedSecond = *reinterpret_cast<int*>(0x006a18e0);
  }
  field0c = 0;
  field08 = arg1;
  field10 = resolvedSecond;
  field04 = arg1;
  field14 = resolvedSecond;
}

// FUNCTION: IMPERIALISM 0x004878e0
void TCommand::Free() {
}

// FUNCTION: IMPERIALISM 0x00487900
undefined TCommand::NextDiplomacyCommandVtableSlotE8_NotifyOwnerSlot94() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487a00
undefined TCommand::OrphanRetStub_00487a00() {
  return 0;
}

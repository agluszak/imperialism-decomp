#include "game/TCivUnit.h"
#include "game/TUnit.h"
#include "game/TStream.h"

// SYNTHETIC: IMPERIALISM 0x005c2860
// TCivUnit::CreateObject

// SYNTHETIC: IMPERIALISM 0x005c28a0
// TCivUnit::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCivUnit, TUnit)

// FUNCTION: IMPERIALISM 0x005c28c0
TCivUnit::TCivUnit() {}

// SYNTHETIC: IMPERIALISM 0x005c28f0
// TCivUnit::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005c2920
TCivUnit::~TCivUnit() {}

// FUNCTION: IMPERIALISM 0x005c2940
void TCivUnit::InitializeCivWorkOrderState(int nOrderType, int pOwnerContext,
                                           int nOrderOwnerNationId) {
  this->RegisterUnitOrderWithOwnerManager(static_cast<short>(nOrderType), pOwnerContext,
                                          static_cast<short>(nOrderOwnerNationId), 0);
  this->remainingTurns24 = 0;
  this->completionMarker26 = static_cast<short>(-1);
}

// FUNCTION: IMPERIALISM 0x005c2980
int TCivUnit::IsInIdleSelectionState() {
  if (this->field_8 != 0 && (this->field_8 < 2 || this->field_8 > 3)) {
    return 0;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x005c29f0
void TCivUnit::SetOrderModeSlot34(int mode, int payload) {
  (void)mode;
  (void)payload;
}

// FUNCTION: IMPERIALISM 0x005c2a90
void TCivUnit::DispatchSlot2C() {}

// FUNCTION: IMPERIALISM 0x005c2b10
void TCivUnit::ReadFrom(TStream* stream) {
  TUnit::ReadFrom(stream);
  stream->ReadBytes(&remainingTurns24, 2);
}

// FUNCTION: IMPERIALISM 0x005c2b40
void TCivUnit::WriteTo(TStream* stream) {
  TUnit::WriteTo(stream);
  stream->WriteBytesSlot78(&remainingTurns24, 2);
}

// FUNCTION: IMPERIALISM 0x005c2b70
void TCivUnit::VTableSlot10(int pOwnerContext) {
  (void)pOwnerContext;
}

// FUNCTION: IMPERIALISM 0x005c2c40
void TCivUnit::DetachUnitOrderFromOwnerAndReset() {}

// FUNCTION: IMPERIALISM 0x005c2c60
void TCivUnit::ResetCivWorkOrderAndRefreshCounters() {}

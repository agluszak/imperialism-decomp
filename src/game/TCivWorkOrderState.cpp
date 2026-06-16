#include "game/TCivWorkOrderState.h"
#include "game/TUnitOrderState.h"
#include "game/TStream.h"

extern "C" char g_pClassDescTCivWorkOrderState = 0;

// FUNCTION: IMPERIALISM 0x005c28a0
CRuntimeClass* TCivWorkOrderState::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(&g_pClassDescTCivWorkOrderState);
}

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif
// FUNCTION: IMPERIALISM 0x005c28c0
TCivWorkOrderState::TCivWorkOrderState() {}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// SYNTHETIC: IMPERIALISM 0x005c28f0
// TCivWorkOrderState::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005c2920
TCivWorkOrderState::~TCivWorkOrderState() {}

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif
// FUNCTION: IMPERIALISM 0x005c2940
void TCivWorkOrderState::InitializeCivWorkOrderState(int nOrderType, int pOwnerContext,
                                                     int nOrderOwnerNationId) {
  this->RegisterUnitOrderWithOwnerManager(static_cast<short>(nOrderType), pOwnerContext,
                                          static_cast<short>(nOrderOwnerNationId), 0);
  this->remainingTurns24 = 0;
  this->completionMarker26 = static_cast<short>(-1);
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// FUNCTION: IMPERIALISM 0x005c29f0
void TCivWorkOrderState::SetOrderModeSlot34(int mode, int payload) {
  (void)mode;
  (void)payload;
}

// FUNCTION: IMPERIALISM 0x005c2a90
void TCivWorkOrderState::DispatchSlot2C() {}

// FUNCTION: IMPERIALISM 0x005c2b10
void TCivWorkOrderState::ReadFrom(TStream* stream) {
  TUnitOrderState::ReadFrom(stream);
  stream->ReadBytes(&remainingTurns24, 2);
}

// FUNCTION: IMPERIALISM 0x005c2b40
void TCivWorkOrderState::WriteTo(TStream* stream) {
  TUnitOrderState::WriteTo(stream);
  stream->WriteBytesSlot78(&remainingTurns24, 2);
}

// FUNCTION: IMPERIALISM 0x005c2b70
void TCivWorkOrderState::VTableSlot10(int pOwnerContext) {
  (void)pOwnerContext;
}

// FUNCTION: IMPERIALISM 0x005c2c40
void TCivWorkOrderState::DetachUnitOrderFromOwnerAndReset() {}

// FUNCTION: IMPERIALISM 0x005c2c60
void TCivWorkOrderState::ResetCivWorkOrderAndRefreshCounters() {}

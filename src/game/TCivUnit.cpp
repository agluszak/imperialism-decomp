#include "game/TCivUnit.h"
#include "game/TUnit.h"
#include "game/TStream.h"

extern "C" char g_pClassDescTCivUnit = 0;

// FUNCTION: IMPERIALISM 0x005c28a0
CRuntimeClass* TCivUnit::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(&g_pClassDescTCivUnit);
}

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x005c28c0
TCivUnit::TCivUnit() {}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// SYNTHETIC: IMPERIALISM 0x005c28f0
// TCivUnit::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005c2920
TCivUnit::~TCivUnit() {}

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x005c2940
void TCivUnit::InitializeCivWorkOrderState(int nOrderType, int pOwnerContext,
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

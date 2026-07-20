#include "game/THostGreatPower.h"

#include "game/global_data_tables.h"
#include "game/TMultiplayerMgr.h"
#include "game/TSimMgr.h"
#include "game/TStream.h"
#include "game/TViewMgr.h"

// FUNCTION: IMPERIALISM 0x00540f20
char THostGreatPower::ReturnFalseNationStateCapabilityFlag9C(void) {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x00540f40
// THostGreatPower::`scalar deleting destructor'
THostGreatPower::~THostGreatPower() {}
// SYNTHETIC: IMPERIALISM 0x00540e90
// THostGreatPower::CreateObject

// SYNTHETIC: IMPERIALISM 0x00540fe0
// THostGreatPower::GetRuntimeClass

IMPLEMENT_DYNCREATE(THostGreatPower, TGreatPower)

THostGreatPower::THostGreatPower() : nationLostEventDispatched(0) {}

// FUNCTION: IMPERIALISM 0x00541000
void THostGreatPower::ReadFrom(TStream* stream) {
  TGreatPower::ReadFrom(stream);
  if (g_nSaveFormatVersion >= 0x3d) {
    stream->ReadBytes(&nationLostEventDispatched, 1);
  }
}

// FUNCTION: IMPERIALISM 0x00541040
void THostGreatPower::WriteTo(TStream* stream) {
  TGreatPower::WriteTo(stream);
  stream->WriteBytesSlot78(&nationLostEventDispatched, 1);
}

// FUNCTION: IMPERIALISM 0x00541080
char THostGreatPower::TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                                    int arg4) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005410f0
void THostGreatPower::ProcessPendingDiplomacyProposalQueue(void) {}

// FUNCTION: IMPERIALISM 0x00541170
void THostGreatPower::HandleNationLost(void) {
  if (nationLostEventDispatched == 0) {
    g_pGameFlowState->DispatchTaggedGameStateEvent1F20(0x6c6f7374, nationSlot | 0xff00, -3);
    nationLostEventDispatched = 1;
  }

  short eligibleOtherNationCount = 0;
  int nationIndex = 0;
  TGreatPower** nation = g_apNationStates;
  do {
    if (nationIndex != nationSlot &&
        g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(nationIndex)) != 0 &&
        (*nation)->diplomacyEligibilityA0 != 0) {
      ++eligibleOtherNationCount;
    }
    ++nation;
    ++nationIndex;
  } while (reinterpret_cast<int>(nation) < reinterpret_cast<int>(&g_apNationStates_End));

  if (eligibleOtherNationCount == 0) {
    TGreatPower::HandleNationLost();
    return;
  }
  g_pSimMgr->PostMainWindowCommand100ForTurnFlow();
}

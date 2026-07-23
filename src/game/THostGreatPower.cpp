#include "game/THostGreatPower.h"

#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/TMultiplayerMgr.h"
#include "game/TSimMgr.h"
#include "game/TStream.h"
#include "game/TViewMgr.h"

// FUNCTION: IMPERIALISM 0x00540f20
bool THostGreatPower::IsHost(void) {
  return true;
}

// SYNTHETIC: IMPERIALISM 0x00540f40
// THostGreatPower::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00540f70
THostGreatPower::~THostGreatPower() {}
// SYNTHETIC: IMPERIALISM 0x00540e90
// THostGreatPower::CreateObject

// SYNTHETIC: IMPERIALISM 0x00540fe0
// THostGreatPower::GetRuntimeClass

IMPLEMENT_DYNCREATE(THostGreatPower, TGreatPower)

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
void THostGreatPower::ReplyToDiplomacyOffers(void) {
  TGreatPower::ReplyToDiplomacyOffers();

  int nationSlot = 0;
  TGreatPower** nation = g_apNationStates;
  do {
    if (*nation != 0 && (*nation)->IsRemote() == 0) {
      g_pGameFlowState->ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry(nationSlot);
    }
    ++nation;
    ++nationSlot;
  } while (reinterpret_cast<int>(nation) < reinterpret_cast<int>(&g_apNationStates_End));

  TViewMgr* uiRuntimeContext = g_pUiRuntimeContext;
  short ownerNationSlot = this->nationSlot;
  uiRuntimeContext->MakeDiplomacyOfferDialog(ownerNationSlot, ownerNationSlot, 0x29a);
}

// FUNCTION: IMPERIALISM 0x00541170
void THostGreatPower::SorryYouLose(void) {
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
  } while (nation < &g_apNationStates_End);

  if (eligibleOtherNationCount == 0) {
    TGreatPower::SorryYouLose();
    return;
  }
  g_pSimMgr->StartNextPhase();
}

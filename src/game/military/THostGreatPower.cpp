#include "game/military/THostGreatPower.h"
#include "game/ui_tags_common.h"

#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/core/TStream.h"
#include "game/ui_core/TViewMgr.h"

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
  stream->WriteBytes(&nationLostEventDispatched, 1);
}

// The host runs the base dispatch first (local UI runtime context); when that accepts the
// action it also mirrors it to the remote nations over the wire.
// FUNCTION: IMPERIALISM 0x00541080
char THostGreatPower::TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                                    int arg4) {
  if (TGreatPower::TryDispatchNationActionViaUiContextOrFallback(arg1, arg2, arg3, arg4) != 0) {
    g_pGameFlowState->DispatchTurnEvent1AWithNationActionPayload(
        this->nationSlot, static_cast<short>(arg1), static_cast<short>(arg2),
        static_cast<short>(arg3), static_cast<short>(arg4));
    return 1;
  }
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
  } while (nation < &g_apNationStates_End);

  TViewMgr* uiRuntimeContext = g_pViewMgr;
  short ownerNationSlot = this->nationSlot;
  uiRuntimeContext->MakeDiplomacyOfferDialog(ownerNationSlot, ownerNationSlot, 0x29a);
}

// FUNCTION: IMPERIALISM 0x00541170
void THostGreatPower::SorryYouLose(void) {
  if (nationLostEventDispatched == 0) {
    g_pGameFlowState->DispatchTaggedGameStateEvent1F20(kControlTagLost, nationSlot | 0xff00, -3);
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

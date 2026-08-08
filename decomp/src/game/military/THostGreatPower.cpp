#include "game/military/THostGreatPower.h"
#include "game/ui_tags_common.h"

#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/core/TStream.h"
#include "game/ui_core/TViewMgr.h"

// FUNCTION: IMPERIALISM 0x00540f20
bool THostGreatPower::IsHost(void) const {
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
char THostGreatPower::ReplyToTradeOffer(NationSlot targetNationSlot, short amount, short price,
                                        ResourceKindStorage resourceKind) {
  if (TGreatPower::ReplyToTradeOffer(targetNationSlot, amount, price, resourceKind) != 0) {
    g_pGameFlowState->DispatchTurnEvent1AWithNationActionPayload(this->nationSlot, targetNationSlot,
                                                                 amount, price, resourceKind);
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005410f0
void THostGreatPower::ReplyToDiplomacyOffers(void) {
  TGreatPower::ReplyToDiplomacyOffers();

  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation != 0 && nation->IsRemote() == 0) {
      g_pGameFlowState->ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry(nationSlot);
    }
  }

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
  for (int nationIndex = 0; nationIndex < 7; ++nationIndex) {
    TGreatPower* nation = g_apNationStates[nationIndex];
    if (nationIndex != nationSlot &&
        g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(nationIndex)) != 0 &&
        nation->diplomacyEligibilityA0 != 0) {
      ++eligibleOtherNationCount;
    }
  }

  if (eligibleOtherNationCount == 0) {
    TGreatPower::SorryYouLose();
    return;
  }
  g_pSimMgr->StartNextPhase();
}

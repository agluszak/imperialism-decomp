#include "game/TProxyGreatPower.h"
#include "game/global_data_tables.h"
#include "game/NetMessage.h"
#include "game/TNetMgr.h"
#include "game/TSimMgr.h"
#include "game/TMultiplayerMgr.h"
#include "game/TTurnStartEvent.h"
#include "game/TUiRuntimeContext.h"
#include "game/UiRuntimeContext.h"

// FUNCTION: IMPERIALISM 0x005408c0
bool TProxyGreatPower::IsClient() {
  return true;
}

// FUNCTION: IMPERIALISM 0x005408e0
bool TProxyGreatPower::IsRemote(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x00540900
void TProxyGreatPower::ReplyToDiplomacyOffers() {
  ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants();
}

// FUNCTION: IMPERIALISM 0x00540920
char TProxyGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage() {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x00540940
// TProxyGreatPower::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00540970
TProxyGreatPower::~TProxyGreatPower() {}

// SYNTHETIC: IMPERIALISM 0x00540840
// TProxyGreatPower::CreateObject

// SYNTHETIC: IMPERIALISM 0x005409e0
// TProxyGreatPower::GetRuntimeClass

IMPLEMENT_DYNCREATE(TProxyGreatPower, TGreatPower)

// FUNCTION: IMPERIALISM 0x00540a00
void TProxyGreatPower::AddToTreasury(int amount) {
  TGreatPower::AddToTreasury(amount);

  TurnEvent14NationMetricPacket packet;
  packet.messageTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventCode = 0x14;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x20;
  packet.DestinateToGP(this->nationSlot);
  packet.nationSlot18 = this->nationSlot;
  packet.amount1C = amount;
  g_pNetMgr006a6014->Send(&packet, 0);
}

// FUNCTION: IMPERIALISM 0x00540aa0
void TProxyGreatPower::DispatchTurnEvent2103WithNationFromRecord() {}

// FUNCTION: IMPERIALISM 0x00540ac0
void TProxyGreatPower::QueueDiplomacyProposalCodeForTargetNation(ProposalCode proposalCode,
                                                                 NationSlot targetNationSlot) {
  TGreatPower::QueueDiplomacyProposalCodeForTargetNation(proposalCode, targetNationSlot);

  TurnEvent16DiplomacyProposalPacket packetPayload;
  packetPayload.messageTag = 0x74696D65;
  packetPayload.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packetPayload.nationSlot18 = this->nationSlot;
  packetPayload.eventCode = 0x16;
  packetPayload.messageLength = 0x20;
  packetPayload.proposalCode1A = proposalCode;
  packetPayload.targetNationId1C = targetNationSlot;

  packetPayload.DestinateToGP(static_cast<int>(this->nationSlot));
  g_pNetMgr006a6014->Send(&packetPayload, 0);
}

// FUNCTION: IMPERIALISM 0x00540b80
void TProxyGreatPower::RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary() {}

// FUNCTION: IMPERIALISM 0x00540ba0
char TProxyGreatPower::TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                                     int arg4) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00540c20
void TProxyGreatPower::SetTradePolicyTo(NationSlot targetNation, short tradePolicy) {
  int packedPolicy = static_cast<int>(targetNation) << 16 | static_cast<int>(tradePolicy);
  g_pGameFlowState->DispatchTaggedGameStateEvent1F20(0x74726164, packedPolicy, this->nationSlot);
  TGreatPower::SetTradePolicyTo(targetNation, tradePolicy);
}

// FUNCTION: IMPERIALISM 0x00540c70
void TProxyGreatPower::AddTurnStartEvent(TTurnStartEvent* event) {
  g_pGameFlowState->DispatchTurnEvent31TaggedPayload(0x73746172, event, this->nationSlot);
  event->Free();
}

// FUNCTION: IMPERIALISM 0x00540cb0
void TProxyGreatPower::SorryYouLose() {
  g_pGameFlowState->DispatchTaggedGameStateEvent1F20(0x6c6f7374, this->nationSlot, -3);
  g_pGameFlowState->ReplaceNationStateForSlotAndRefreshStatus(this->nationSlot);
}

// FUNCTION: IMPERIALISM 0x00540cf0
int TProxyGreatPower::HandleWarTransitionRequest(int targetNation, int sourceNation) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00540dc0
int TProxyGreatPower::HandleWarTransitionRequestWithRoleSwap(int targetNation, int sourceNation,
                                                             char swapRoles) {
  return 0;
}

#include "game/military/TProxyGreatPower.h"
#include "game/ui_tags_common.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/military/NetMessage.h"
#include "game/net/TNetMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/nation/TTurnStartEvent.h"
#include "game/ui_core/TViewMgr.h"

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
  packet.messageTag = kControlTagTime;
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
void TProxyGreatPower::AddOfferFrom(NationSlot sourceNationSlot,
                                    DiplomacyProposalCodeStorage proposalCode) {
  TGreatPower::AddOfferFrom(sourceNationSlot, proposalCode);

  TurnEvent16DiplomacyProposalPacket packetPayload;
  packetPayload.messageTag = kControlTagTime;
  packetPayload.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packetPayload.nationSlot18 = this->nationSlot;
  packetPayload.eventCode = 0x16;
  packetPayload.messageLength = 0x20;
  packetPayload.sourceNationSlot1A = sourceNationSlot;
  packetPayload.proposalCode1C = proposalCode;

  packetPayload.DestinateToGP(static_cast<int>(this->nationSlot));
  g_pNetMgr006a6014->Send(&packetPayload, 0);
}

// FUNCTION: IMPERIALISM 0x00540b80
void TProxyGreatPower::RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary() {}

// Same split as the TGreatPower base (0x4ddbb0), but a proxy nation routes the accepted
// action to the host over the wire instead of into the local UI runtime context.
// FUNCTION: IMPERIALISM 0x00540ba0
char TProxyGreatPower::ReplyToTradeOffer(NationSlot targetNationSlot, short amount, short price,
                                         ResourceKindStorage resourceKind) {
  if (this->StillBuyingItem(resourceKind) != 0) {
    g_pGameFlowState->DispatchTurnEvent1AWithNationActionPayload(this->nationSlot, targetNationSlot,
                                                                 amount, price, resourceKind);
    return 1;
  }

  this->AddToDealBook(1, targetNationSlot, 0, resourceKind, 0);
  return 0;
}

// FUNCTION: IMPERIALISM 0x00540c20
void TProxyGreatPower::SetTradePolicyTo(NationSlot targetNation, short tradePolicy) {
  int packedPolicy = static_cast<int>(targetNation) << 16 | static_cast<int>(tradePolicy);
  g_pGameFlowState->DispatchTaggedGameStateEvent1F20(kControlTagTrad, packedPolicy,
                                                     this->nationSlot);
  TGreatPower::SetTradePolicyTo(targetNation, tradePolicy);
}

// FUNCTION: IMPERIALISM 0x00540c70
void TProxyGreatPower::AddTurnStartEvent(TTurnStartEvent* event) {
  g_pGameFlowState->SendStreamObject(kControlTagStar, event, this->nationSlot);
  event->Free();
}

// FUNCTION: IMPERIALISM 0x00540cb0
void TProxyGreatPower::SorryYouLose() {
  g_pGameFlowState->DispatchTaggedGameStateEvent1F20(kControlTagLost, this->nationSlot, -3);
  g_pGameFlowState->ReplaceNationStateForSlotAndRefreshStatus(this->nationSlot);
}

// Emits the event-0x1D war-transition request and reports 2 ("request pending"): a proxy
// nation cannot resolve the transition locally, the host answers.
// FUNCTION: IMPERIALISM 0x00540cf0
int TProxyGreatPower::HandleWarTransitionRequest(int targetNation, int sourceNation) {
  TurnEvent1DWarTransitionPacket packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventCode = 0x1d;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x20;
  packet.SetTimeEmitPacketGameFlowTurnId();
  packet.toNetworkId = -1;
  packet.DestinateTo(this->nationSlot);
  packet.actionCode1C = 'i';
  packet.nationA1D = static_cast<signed char>(targetNation);
  packet.nationB1E = static_cast<signed char>(sourceNation);
  g_pNetMgr006a6014->Send(&packet, 0);
  return 2;
}

// The role-swap sibling of 0x540cf0: same event-0x1D packet with the 'a' request kind and
// the extra swapRoles byte at +0x1F.
// FUNCTION: IMPERIALISM 0x00540dc0
int TProxyGreatPower::HandleWarTransitionRequestWithRoleSwap(int targetNation, int sourceNation,
                                                             char swapRoles) {
  TurnEvent1DWarTransitionPacket packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventCode = 0x1d;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x20;
  packet.SetTimeEmitPacketGameFlowTurnId();
  packet.toNetworkId = -1;
  packet.DestinateTo(this->nationSlot);
  packet.actionCode1C = 'a';
  packet.nationA1D = static_cast<signed char>(targetNation);
  packet.nationB1E = static_cast<signed char>(sourceNation);
  packet.mode1F = static_cast<unsigned char>(swapRoles);
  g_pNetMgr006a6014->Send(&packet, 0);
  return 2;
}

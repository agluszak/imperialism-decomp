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
bool TProxyGreatPower::IsClient() const {
  return true;
}

// FUNCTION: IMPERIALISM 0x005408e0
bool TProxyGreatPower::IsRemote(void) const {
  return true;
}

// FUNCTION: IMPERIALISM 0x00540900
void TProxyGreatPower::ReplyToDiplomacyOffers() {
  ResetPolicies();
}

// FUNCTION: IMPERIALISM 0x00540920
bool TProxyGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage() {
  return false;
}

// FUNCTION: IMPERIALISM 0x00540970
TProxyGreatPower::~TProxyGreatPower() {}

IMPLEMENT_DYNCREATE(TProxyGreatPower, TGreatPower)

// FUNCTION: IMPERIALISM 0x00540a00
void TProxyGreatPower::AddToTreasury(int amount) {
  TGreatPower::AddToTreasury(amount);

  TurnEvent14NationMetricPacket packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.eventCode = 0x14;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x20;
  packet.DestinateToGP(nationSlot);
  packet.nationSlot = nationSlot;
  packet.amount = amount;
  g_pNetMgr->Send(&packet, false);
}

// FUNCTION: IMPERIALISM 0x00540aa0
void TProxyGreatPower::ShowNewspaperForRecordNation() {}

// FUNCTION: IMPERIALISM 0x00540ac0
void TProxyGreatPower::AddOfferFrom(NationSlot sourceNationSlot,
                                    DiplomacyProposalCodeStorage proposalCode) {
  TGreatPower::AddOfferFrom(sourceNationSlot, proposalCode);

  TurnEvent16DiplomacyProposalPacket packetPayload;
  packetPayload.messageTag = kControlTagTime;
  packetPayload.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packetPayload.nationSlot = nationSlot;
  packetPayload.eventCode = 0x16;
  packetPayload.messageLength = 0x20;
  packetPayload.sourceNationSlot = sourceNationSlot;
  packetPayload.proposalCode = proposalCode;

  packetPayload.DestinateToGP(static_cast<int>(nationSlot));
  g_pNetMgr->Send(&packetPayload, false);
}

// FUNCTION: IMPERIALISM 0x00540b80
void TProxyGreatPower::FinishCityPhase() {}

// FUNCTION: IMPERIALISM 0x00540ba0
bool TProxyGreatPower::ReplyToTradeOffer(NationSlot targetNationSlot, short amount, short price,
                                         ResourceKindStorage resourceKind) {
  if (StillBuyingItem(resourceKind)) {
    g_pGameFlowState->SendTradeOffer(nationSlot, targetNationSlot, amount, price, resourceKind);
    return true;
  }

  AddToDealBook(1, targetNationSlot, 0, resourceKind, 0);
  return false;
}

// FUNCTION: IMPERIALISM 0x00540c20
void TProxyGreatPower::SetTradePolicyTo(NationSlot targetNation, short tradePolicy) {
  int packedPolicy = static_cast<int>(targetNation) << 16 | static_cast<int>(tradePolicy);
  g_pGameFlowState->SendGameControl(kControlTagTrad, packedPolicy, nationSlot);
  TGreatPower::SetTradePolicyTo(targetNation, tradePolicy);
}

// FUNCTION: IMPERIALISM 0x00540c70
void TProxyGreatPower::AddTurnStartEvent(TTurnStartEvent* event) {
  g_pGameFlowState->SendStreamObject(kControlTagStar, event, nationSlot);
  event->Free();
}

// FUNCTION: IMPERIALISM 0x00540cb0
void TProxyGreatPower::SorryYouLose() {
  g_pGameFlowState->SendGameControl(kControlTagLost, nationSlot, -3);
  g_pGameFlowState->DehumanizePlayer(nationSlot);
}

// FUNCTION: IMPERIALISM 0x00540cf0
int TProxyGreatPower::ConsiderWarOfIntervention(int targetNation, int sourceNation) {
  TurnEvent1DWarTransitionPacket packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.eventCode = 0x1d;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x20;
  packet.SetTimeEmitPacketGameFlowTurnId();
  packet.toNetworkId = -1;
  packet.DestinateTo(nationSlot);
  packet.actionCode = 'i';
  packet.nationA1D = static_cast<signed char>(targetNation);
  packet.nationB1E = static_cast<signed char>(sourceNation);
  g_pNetMgr->Send(&packet, false);
  return 2;
}

// FUNCTION: IMPERIALISM 0x00540dc0
int TProxyGreatPower::ConsiderWarOfAlliance(int targetNation, int sourceNation, char swapRoles) {
  TurnEvent1DWarTransitionPacket packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.eventCode = 0x1d;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x20;
  packet.SetTimeEmitPacketGameFlowTurnId();
  packet.toNetworkId = -1;
  packet.DestinateTo(nationSlot);
  packet.actionCode = 'a';
  packet.nationA1D = static_cast<signed char>(targetNation);
  packet.nationB1E = static_cast<signed char>(sourceNation);
  packet.mode1F = static_cast<unsigned char>(swapRoles);
  g_pNetMgr->Send(&packet, false);
  return 2;
}

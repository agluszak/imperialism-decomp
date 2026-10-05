#include "game/military/TClientGreatPower.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/TViewMgr.h"
#include "game/military/NetMessage.h"
#include "game/net/TNetMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/net/TMultiplayerMgr.h"

// FUNCTION: IMPERIALISM 0x005412b0
bool TClientGreatPower::IsClient(void) const {
  return true;
}

// FUNCTION: IMPERIALISM 0x005412d0
bool TClientGreatPower::IsRemote(void) const {
  return false;
}

// FUNCTION: IMPERIALISM 0x00541320
TClientGreatPower::~TClientGreatPower() {}

IMPLEMENT_DYNCREATE(TClientGreatPower, TGreatPower)

// FUNCTION: IMPERIALISM 0x005413b0
void TClientGreatPower::AcceptOffer(short proposalIndex) {
  TurnEvent17ProposalResolutionPacket packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventCode = 0x17;
  packet.fromNetworkId = 0;
  packet.toNetworkId = -1;
  packet.messageLength = 0x20;
  packet.nationSlot18 = this->nationSlot;
  packet.acceptedFlag1A = true;
  packet.proposalIndex1C = proposalIndex;
  g_pNetMgr006a6014->Send(&packet, false);
}

// FUNCTION: IMPERIALISM 0x00541450
void TClientGreatPower::RejectOffer(short proposalQueueIndex) {
  TurnEvent17ProposalResolutionPacket packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventCode = 0x17;
  packet.fromNetworkId = 0;
  packet.toNetworkId = -1;
  packet.messageLength = 0x20;
  packet.nationSlot18 = this->nationSlot;
  packet.acceptedFlag1A = false;
  packet.proposalIndex1C = proposalQueueIndex;
  g_pNetMgr006a6014->Send(&packet, false);
}

// FUNCTION: IMPERIALISM 0x005414f0
void TClientGreatPower::ReplyToDiplomacyOffers(void) {
  TGreatPower::ReplyToDiplomacyOffers();

  TurnEventFResumeAckPacket packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.eventCode = 0xf;
  packet.toNetworkId = 0;
  packet.toNetworkId = -1;
  packet.messageLength = 0;
  packet.messageLength = 0x20;
  packet.SetTimeEmitPacketGameFlowTurnId();
  packet.nationSlot1C = static_cast<short>(g_pSimMgr->GetActiveNationId());
  g_pNetMgr006a6014->Send(&packet, false);

  g_pViewMgr->MakeDiplomacyOfferDialog(nationSlot, nationSlot, 0x29a);
}

// FUNCTION: IMPERIALISM 0x005415c0
int TClientGreatPower::HandleWarTransitionRequestWithRoleSwap(int targetNation, int sourceNation,
                                                              char swapRoles) {
  struct TurnEvent1EPacketPayload : TimelyNetMessagePrefix {
    unsigned char activeNationIdBeforePayload;
    unsigned char targetNation;
    unsigned char sourceNation;
    unsigned char commandCode;
    unsigned char swapRoles;
    bool acceptedFlag;
  };

  int accepted =
      TGreatPower::HandleWarTransitionRequestWithRoleSwap(targetNation, sourceNation, swapRoles);
  TurnEvent1EPacketPayload packetPayload;
  packetPayload.messageTag = kControlTagTime;
  packetPayload.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packetPayload.eventCode = 0x1e;
  packetPayload.messageLength = 0x24;
  packetPayload.SetTimeEmitPacketGameFlowTurnId();
  packetPayload.toNetworkId = -1;
  packetPayload.activeNationIdBeforePayload =
      static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packetPayload.targetNation = static_cast<unsigned char>(targetNation);
  packetPayload.sourceNation = static_cast<unsigned char>(sourceNation);
  packetPayload.commandCode = 0x61;
  packetPayload.swapRoles = static_cast<unsigned char>(swapRoles);
  packetPayload.acceptedFlag = accepted == 1 ? 1 : 0;
  g_pNetMgr006a6014->Send(&packetPayload, false);
  return accepted;
}

// FUNCTION: IMPERIALISM 0x005416b0
int TClientGreatPower::HandleWarTransitionRequest(int targetNation, int sourceNation) {
  struct TurnEvent1EPacketPayload : TimelyNetMessagePrefix {
    unsigned char activeNationIdBeforePayload;
    bool acceptedFlag;
    unsigned char commandCode;
    unsigned char commandArgA;
    unsigned char commandArgB;
  };

  int accepted = TGreatPower::HandleWarTransitionRequest(targetNation, sourceNation);
  TurnEvent1EPacketPayload packetPayload;
  packetPayload.messageTag = kControlTagTime;
  packetPayload.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packetPayload.eventCode = 0x1E;
  packetPayload.messageLength = 0x24;
  packetPayload.SetTimeEmitPacketGameFlowTurnId();
  packetPayload.toNetworkId = -1;
  packetPayload.activeNationIdBeforePayload =
      static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packetPayload.acceptedFlag = accepted != 0 ? 1 : 0;
  packetPayload.commandCode = 0x69;
  packetPayload.commandArgA = static_cast<unsigned char>(targetNation);
  packetPayload.commandArgB = static_cast<unsigned char>(sourceNation);
  g_pNetMgr006a6014->Send(&packetPayload, false);
  return accepted;
}

// FUNCTION: IMPERIALISM 0x00541790
void TClientGreatPower::SorryYouLose(void) {
  g_pGameFlowState->DispatchTaggedGameStateEvent1F20(kControlTagLose, this->nationSlot, -1);
}

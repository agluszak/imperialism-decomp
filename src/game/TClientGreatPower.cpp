#include "game/TClientGreatPower.h"
#include "game/global_data_tables.h"
#include "game/TUiRuntimeContext.h"
#include "game/UiRuntimeContext.h"
#include "game/NetMessage.h"
#include "game/TNetMgr.h"
#include "game/TSimMgr.h"
#include "game/TMultiplayerMgr.h"

// FUNCTION: IMPERIALISM 0x005412b0
char TClientGreatPower::ReturnFalseNationStateCapabilityFlag98(void) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005412d0
char TClientGreatPower::ShouldDispatchImmediatelySlot28(void) {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x005412f0
// TClientGreatPower::`scalar deleting destructor'
TClientGreatPower::~TClientGreatPower() {}
// SYNTHETIC: IMPERIALISM 0x00541230
// TClientGreatPower::CreateObject

// SYNTHETIC: IMPERIALISM 0x00541390
// TClientGreatPower::GetRuntimeClass

IMPLEMENT_DYNCREATE(TClientGreatPower, TGreatPower)

// FUNCTION: IMPERIALISM 0x005413b0
void TClientGreatPower::ApplyAcceptedDiplomacyProposalCode(short proposalIndex) {
  (void)proposalIndex;
}

// FUNCTION: IMPERIALISM 0x00541450
void TClientGreatPower::QueueInterNationEventForProposalCode12D_130(
    unsigned short proposalQueueIndex) {
  (void)proposalQueueIndex;
}

// FUNCTION: IMPERIALISM 0x005414f0
void TClientGreatPower::ProcessPendingDiplomacyProposalQueue(void) {
  TGreatPower::ProcessPendingDiplomacyProposalQueue();
}

// FUNCTION: IMPERIALISM 0x005415c0
int TClientGreatPower::PropagateWarTransitionSlot280(int targetNation, int sourceNation, int mode) {
  return TGreatPower::PropagateWarTransitionSlot280(targetNation, sourceNation, mode);
}

// FUNCTION: IMPERIALISM 0x005416b0
int TClientGreatPower::CheckTransitionSlot27C(int targetNation, int sourceNation) {
  struct TurnEvent1EPacketPayload : TimelyNetMessagePrefix {
    unsigned char activeNationIdBeforePayload;
    unsigned char acceptedFlag;
    unsigned char commandCode;
    unsigned char commandArgA;
    unsigned char commandArgB;
  };

  int accepted = TGreatPower::CheckTransitionSlot27C(targetNation, sourceNation);
  TurnEvent1EPacketPayload packetPayload;
  packetPayload.messageTag = 0x74696D65;
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
  g_pNetMgr006a6014->Send(&packetPayload, 0);
  return accepted;
}

// FUNCTION: IMPERIALISM 0x00541790
void TClientGreatPower::DispatchTurnEvent11F8NoPayloadSlot2AC(void) {}

TClientGreatPower::TClientGreatPower() : TGreatPower() {}

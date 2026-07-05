#include "game/TProxyGreatPower.h"
#include "game/global_data_tables.h"
#include "game/NetMessage.h"
#include "game/TNetMgr.h"
#include "game/TSimMgr.h"
#include "game/TMultiplayerMgr.h"
#include "game/TUiRuntimeContext.h"
#include "game/UiRuntimeContext.h"

// FUNCTION: IMPERIALISM 0x005408c0
char TProxyGreatPower::ReturnFalseNationStateCapabilityFlag98() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005408e0
char TProxyGreatPower::ShouldDispatchImmediatelySlot28(void) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00540900
void TProxyGreatPower::ProcessPendingDiplomacyProposalQueue() {}

// FUNCTION: IMPERIALISM 0x00540920
void TProxyGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage() {}

// SYNTHETIC: IMPERIALISM 0x00540940
// TProxyGreatPower::`scalar deleting destructor'
TProxyGreatPower::~TProxyGreatPower() {}

// SYNTHETIC: IMPERIALISM 0x00540840
// TProxyGreatPower::CreateObject

// SYNTHETIC: IMPERIALISM 0x005409e0
// TProxyGreatPower::GetRuntimeClass

IMPLEMENT_DYNCREATE(TProxyGreatPower, TGreatPower)

TProxyGreatPower::TProxyGreatPower() {}

// FUNCTION: IMPERIALISM 0x00540a00
void TProxyGreatPower::AddToNationMetricAtField10(int amount) {}

// FUNCTION: IMPERIALISM 0x00540aa0
void TProxyGreatPower::DispatchTurnEvent2103WithNationFromRecord() {}

// FUNCTION: IMPERIALISM 0x00540ac0
void TProxyGreatPower::QueueDiplomacyProposalCodeForTargetNation(short proposalCode,
                                                                 short targetNationId) {
  struct TurnEvent16PacketPayload : NetMessage {
    int packetTag;
    unsigned char activeNationId;
    unsigned char padAfterActiveNation;
    short sourceNation;
    short proposalCode;
    short targetNationId;
  };

  TGreatPower::QueueDiplomacyProposalCodeForTargetNation(proposalCode, targetNationId);

  TurnEvent16PacketPayload packetPayload;
  packetPayload.packetTag = 0x74696D65;
  packetPayload.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packetPayload.sourceNation = this->nationSlot;
  packetPayload.eventCode = 0x16;
  packetPayload.messageLength = 0x20;
  packetPayload.proposalCode = proposalCode;
  packetPayload.targetNationId = targetNationId;

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
void TProxyGreatPower::ResetDiplomacyLevelForNationSlot12(NationSlot nationSlot, int resetLevel) {}

// FUNCTION: IMPERIALISM 0x00540c70
void TProxyGreatPower::AddNodeToMissionNodeQueue(void* node) {}

// FUNCTION: IMPERIALISM 0x00540cb0
void TProxyGreatPower::DispatchTurnEvent11F8NoPayloadSlot2AC() {}

// FUNCTION: IMPERIALISM 0x00540cf0
int TProxyGreatPower::CheckTransitionSlot27C(int targetNation, int sourceNation) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00540dc0
int TProxyGreatPower::PropagateWarTransitionSlot280(int targetNation, int sourceNation, int mode) {
  return 0;
}

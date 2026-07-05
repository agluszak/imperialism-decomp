#include "game/NetMessage.h"

#include "game/TMultiplayerMgr.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x005420a0
void NetMessage::DestinateToGP(int nationSlot) {
  toNetworkId = g_pGameFlowState->nationSessionIds[nationSlot];
}

// FUNCTION: IMPERIALISM 0x00542120
void TimelyNetMessagePrefix::SetTimeEmitPacketGameFlowTurnId() {
  uiTurnToken = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
}

// FUNCTION: IMPERIALISM 0x005438e0
TimelyNetMessagePrefix* TimelyNetMessagePrefix::InitializeEmitEventHeaderWithActiveNation() {
  messageTag = 0x74696d65; // 'time'
  activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  return this;
}

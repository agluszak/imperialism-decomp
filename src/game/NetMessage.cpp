#include "game/NetMessage.h"

#include "game/TMultiplayerMgr.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x005420a0
void NetMessage::DestinateToGP(int nationSlot) {
  toNetworkId = g_pGameFlowState->nationSessionIds[nationSlot];
}

// FUNCTION: IMPERIALISM 0x005420d0
void NetMessage::DestinateTo(int nationSlot) {
  if (nationSlot != -2 && nationSlot != -3) {
    if (nationSlot == -1) {
      toNetworkId = -1;
      return;
    }
    toNetworkId = g_pGameFlowState->nationSessionIds[nationSlot];
    return;
  }
  toNetworkId = 0;
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

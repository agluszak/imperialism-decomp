#include "game/military/NetMessage.h"
#include "game/ui_tags_common.h"
#include <string.h>

#include "game/net/TMultiplayerMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

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
TimelyMessageHeader* TimelyMessageHeader::InitializeEmitEventHeaderWithActiveNation() {
  messageTag = kControlTagTime; // 'time'
  activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  return this;
}

// FUNCTION: IMPERIALISM 0x00544cd0
void TurnEvent2SyncPacket::ApplyEncodedDeltaPayloadToBufferByMode(void* buffer) {
  switch (deltaKind21) {
  case 0:
    memcpy(buffer, payload.raw, messageLength - 0x24);
    break;
  case 1: {
    TurnEvent2ByteDeltaEntry* cursor = reinterpret_cast<TurnEvent2ByteDeltaEntry*>(payload.raw);
    for (int count = (messageLength - 0x24) / 3; count != 0; --count) {
      static_cast<unsigned char*>(buffer)[cursor->index] = cursor->value;
      ++cursor;
    }
    break;
  }
  case 2: {
    TurnEvent2ShortDeltaEntry* cursor = reinterpret_cast<TurnEvent2ShortDeltaEntry*>(payload.raw);
    for (int count = (messageLength - 0x24) / 4; count != 0; --count) {
      static_cast<short*>(buffer)[cursor->index] = cursor->value;
      ++cursor;
    }
    break;
  }
  case 3: {
    TurnEvent2IntDeltaEntry* cursor = reinterpret_cast<TurnEvent2IntDeltaEntry*>(payload.raw);
    for (int count = (messageLength - 0x24) / 6; count != 0; --count) {
      static_cast<int*>(buffer)[cursor->index] = cursor->value;
      ++cursor;
    }
    break;
  }
  }
}

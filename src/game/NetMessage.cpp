#include "game/NetMessage.h"
#include <string.h>

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
TimelyMessageHeader* TimelyMessageHeader::InitializeEmitEventHeaderWithActiveNation() {
  messageTag = 0x74696d65; // 'time'
  activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  return this;
}

// FUNCTION: IMPERIALISM 0x00544cd0
void TurnEvent2SyncPacket::ApplyEncodedDeltaPayloadToBufferByMode(void* buffer) {
  switch (deltaKind21) {
  case 0:
    memcpy(buffer, payload, messageLength - 0x24);
    break;
  case 1: {
    unsigned char* cursor = reinterpret_cast<unsigned char*>(payload);
    for (int count = (messageLength - 0x24) / 3; count != 0; --count) {
      unsigned short index = *reinterpret_cast<unsigned short*>(cursor);
      unsigned char value = cursor[2];
      cursor += 3;
      static_cast<unsigned char*>(buffer)[index] = value;
    }
    break;
  }
  case 2: {
    short* cursor = payload;
    for (int count = (messageLength - 0x24) / 4; count != 0; --count) {
      unsigned short index = *reinterpret_cast<unsigned short*>(cursor);
      short value = cursor[1];
      cursor += 2;
      static_cast<short*>(buffer)[index] = value;
    }
    break;
  }
  case 3: {
    unsigned char* cursor = reinterpret_cast<unsigned char*>(payload);
    for (int count = (messageLength - 0x24) / 6; count != 0; --count) {
      unsigned short index = *reinterpret_cast<unsigned short*>(cursor);
      int value = *reinterpret_cast<int*>(cursor + 2);
      cursor += 6;
      static_cast<int*>(buffer)[index] = value;
    }
    break;
  }
  }
}

#include "game/TWNetSessionManager.h"

// FUNCTION: IMPERIALISM 0x00480850
bool TWNetSessionManager::TrySendNetworkPacket(int nationId, void* packet, unsigned int byteCount) {
  int* directPlay = reinterpret_cast<int*>(this->directPlayInterface04);
  if (directPlay == 0) {
    return false;
  }
  typedef int(__stdcall * DirectPlaySendSlot1a)(int* self, int localPlayerId, int nationId,
                                               int sendFlags, void* packetBytes,
                                               unsigned int byteCount);
  DirectPlaySendSlot1a sendSlot1a = reinterpret_cast<DirectPlaySendSlot1a>(
      reinterpret_cast<void**>(directPlay)[0x68 / sizeof(void*)]);
  int sendResult =
      sendSlot1a(directPlay, this->localPlayerId60, nationId, 1, packet, byteCount);
  this->lastErrorCode0c = sendResult;
  return sendResult >= 0;
}

TWNetSessionManager* g_pNetworkSessionContext006a5f64 = 0;

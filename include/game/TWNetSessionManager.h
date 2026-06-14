#pragma once

#include "decomp_types.h"

// DirectPlay session manager singleton (DAT_006a5f64). TrySendNetworkPacketViaManagerContext
// is a real __thiscall method on this object.
class TWNetSessionManager {
public:
  unsigned char pad00[4];
  void* directPlayInterface04;
  unsigned char pad08[4];
  int lastErrorCode0c;
  unsigned char pad10[0x60 - 0x10];
  int localPlayerId60;

  // FUNCTION: IMPERIALISM 0x00480850
  bool TrySendNetworkPacket(int nationId, void* packet, unsigned int byteCount);
};

extern TWNetSessionManager* g_pNetworkSessionContext006a5f64;

#pragma once

#include "decomp_types.h"

// DirectPlay session manager. Lives as a global object embedded at fixed address 0x006a5f60
// (not a pointer-to-object); the original loads `MOV ECX, 0x6a5f60` directly. TrySendNetworkPacket
// is `__thiscall` on this object.
class TWNetSessionManager {
public:
  unsigned char pad00[4];
  void* directPlayInterface04;
  unsigned char pad08[4];
  int lastErrorCode0c;
  unsigned char pad10[0x60 - 0x10];
  int localPlayerId60;

  bool TrySendNetworkPacket(int nationId, void* packet, unsigned int byteCount);
};

// The global instance itself. `&g_NetworkSessionManager006a5f60` resolves to 0x006a5f60.
extern TWNetSessionManager g_NetworkSessionManager006a5f60;

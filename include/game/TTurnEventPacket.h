#pragma once

#include "decomp_types.h"

// Flat routing prefix passed to EnqueueOrSendTurnEventPacketToNation. Layout matches the
// dword prefix at param_1 in the original (eventCode..payloadSize); Enqueue overwrites
// defaultNationId and resolves targetNationId before queue/send.
struct TTurnEventPacketRoutingPrefix {
  int eventCode;
  int defaultNationId;
  int targetNationId;
  int payloadSize;

  void SetPayloadNationIdFromSlotIndex(int nationSlot);

  undefined4 EnqueueOrSendTurnEventPacketToNation(char queueOnly);
};

// Join-empire packet body built on the stack in DispatchJoinEmpireModeEventPacket24_27.
struct TJoinEmpireTurnEventPacket {
  TTurnEventPacketRoutingPrefix routing;
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad0b[3];
  int sourceNationSlot;
  int targetNationSlot;
  int modeValue;
};

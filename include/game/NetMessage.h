#pragma once

#include "decomp_types.h"

// Windows counterpart of the Mac build's network message header (Mac oracle names the
// class NetMessage with methods DestinateTo(int)/DestinateToGP(int); on Mac the header
// role is played by NetSprocket's NSpMessageHeader {what, from, to, messageLen}, and
// TNetMgr::Send takes NSpMessageHeader* — our TNetMgr::Send @ 0x5e3d40 takes this).
// 0x10-byte plain header prefixed to every turn-event packet; no vtable.
// TNetMgr::Send stamps fromNetworkId and resolves toNetworkId (-1 = broadcast) before
// queueing/sending. Name evidence is Mac-oracle only (Hard Rule: names/signatures, not
// addresses/layout).
struct NetMessage {
  int eventCode;     // +0x00 — turn-event code ('what')
  int fromNetworkId; // +0x04 — sender network id ('from'); overwritten by TNetMgr::Send
  int toNetworkId;   // +0x08 — destination network id ('to'); -1 = broadcast
  int messageLength; // +0x0c — total packet size in bytes ('messageLen')

  // Set the destination id from a great-power slot index via
  // TMultiplayerMgr::nationSessionIds (Mac oracle: NetMessage::DestinateToGP(int)).
  void DestinateToGP(int nationSlot);

  // Sentinel-aware destination stamp (Mac oracle: NetMessage::DestinateTo(int)):
  // -1 broadcasts, -2/-3 route to session id 0, otherwise the slot's session id.
  void DestinateTo(int nationSlot);
};

// 'time'-tagged (0x74696d65) timely-message variant whose turn-token word sits at +0x18
// (three-byte pad after the active-nation byte). Used by the advisory/diplomacy emitters
// (0x540cf0..0x5416b0 band); 0x542120 writes word [this+0x18] from
// TMultiplayerMgr::pendingNationSlotIndex.
struct TimelyNetMessagePrefix : NetMessage {
  int messageTag;               // +0x10 — 'time'
  unsigned char activeNationId; // +0x14
  unsigned char pad15[3];
  short uiTurnToken; // +0x18

  void SetTimeEmitPacketGameFlowTurnId();
  // Stamp messageTag='time' + the active nation id and return this (0x5438e0; used by
  // the diplomacy turn-event reply emitters).
  TimelyNetMessagePrefix* InitializeEmitEventHeaderWithActiveNation();
};

// 0x5449b0 (TMultiplayerMgr TU): heap-build the turn-event-2 sync packet, delta or full.
// Turn-event-2 relation-matrix sync packet. Variable-length: full form carries the raw
// 0x89c-short block, delta form (deltaKind21 == 2) carries (index, value) pairs for the
// entries that differ from the baseline.
struct TurnEvent2SyncPacket : NetMessage {
  int pad10;                 // +0x10 - zeroed, no 'time' tag on this packet
  int pad14;                 // +0x14
  short pendingNationSlot;   // +0x18
  unsigned char pad1a[6];    // +0x1a
  unsigned char flag20;      // +0x20 - cleared by the caller after the baseline refresh
  unsigned char deltaKind21; // +0x21 - 2 = delta pairs, 0 = full block
  unsigned char pad22[2];
  short payload[1]; // +0x24 - variable length
};
TurnEvent2SyncPacket* __cdecl
BuildTurnEvent2ArraySyncPacketDeltaOrFull(unsigned int shortCount, short* current, short* baseline);

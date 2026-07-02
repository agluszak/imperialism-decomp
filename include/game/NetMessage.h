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

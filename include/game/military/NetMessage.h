#pragma once

#include "decomp_types.h"
#include "game/ui_tags_common.h"
#include "game/nation_domain_types.h"

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

// Heap packet while it is parked in TMultiplayerMgr's two deferred-processing queues.
// The queue link occupies +0x10; once a packet is dequeued, that slot is again available
// to the concrete packet family (normally the timely-message tag).
struct TurnEventQueuePacket : NetMessage {
  TurnEventQueuePacket* nextQueuePacket;
};

// 'time'-tagged ('time') timely-message variant whose turn-token word sits at +0x18
// (three-byte pad after the active-nation byte). Used by the advisory/diplomacy emitters
// (0x540cf0..0x5416b0 band); 0x542120 writes word [this+0x18] from
// TMultiplayerMgr::pendingNationSlotIndex.
// 'time'-tagged header shared by every timely packet family: the stamp helper writes
// only the tag + active-nation byte, so payloads that reuse +0x18 for their own fields
// (the event-0x25 status tags, the event-9 chat slot byte) derive from this base while
// the turn-token variant below adds uiTurnToken.
struct TimelyMessageHeader : NetMessage {
  int messageTag;               // +0x10 — 'time'
  unsigned char activeNationId; // +0x14
  unsigned char pad15[3];

  // Stamp messageTag='time' + the active nation id and return this (0x5438e0; used by
  // the diplomacy turn-event reply emitters).
  TimelyMessageHeader* InitializeEmitEventHeaderWithActiveNation();
};

struct TimelyNetMessagePrefix : TimelyMessageHeader {
  short uiTurnToken; // +0x18

  void SetTimeEmitPacketGameFlowTurnId();
};

// Event-0xF per-nation turn-resume acknowledgement.
struct TurnEventFResumeAckPacket : TimelyNetMessagePrefix {
  NationSlot nationSlot1C;
  unsigned char pad1e[2];
};

// Event-0x14 treasury delta for one nation.
struct TurnEvent14NationMetricPacket : TimelyMessageHeader {
  NationSlot nationSlot18;
  unsigned char pad1a[2];
  int amount1C;
};

// Event-0x16 diplomacy proposal for one nation.
struct TurnEvent16DiplomacyProposalPacket : TimelyMessageHeader {
  NationSlot nationSlot18;
  DiplomacyProposalCodeStorage proposalCode1A;
  NationSlot targetNationId1C;
  unsigned char pad1e[2];
};

// Event-0x17 proposal resolution (accept/decline).
struct TurnEvent17ProposalResolutionPacket : TimelyMessageHeader {
  NationSlot nationSlot18;
  unsigned char acceptedFlag1A;
  unsigned char pad1b;
  short proposalIndex1C;
  unsigned char pad1e[2];
};

// Packed network payload entries used by TurnEvent2SyncPacket. These are wire records,
// not views of the destination arrays: x86 intentionally performs the unaligned word/dword
// loads at +0 and +2 that the packet encoding requires.
#pragma pack(push, 1)
struct TurnEvent2ByteDeltaEntry {
  unsigned short index;
  unsigned char value;
};
struct TurnEvent2ShortDeltaEntry {
  unsigned short index;
  short value;
};
struct TurnEvent2IntDeltaEntry {
  unsigned short index;
  int value;
};
#pragma pack(pop)
ASSERT_SIZE(TurnEvent2ByteDeltaEntry, 3);
ASSERT_SIZE(TurnEvent2ShortDeltaEntry, 4);
ASSERT_SIZE(TurnEvent2IntDeltaEntry, 6);

union TurnEvent2DeltaPayload {
  unsigned char raw[1];
  TurnEvent2ByteDeltaEntry byteEntries[1];
  TurnEvent2ShortDeltaEntry shortEntries[1];
  TurnEvent2IntDeltaEntry intEntries[1];
};

// 0x5449b0 (TMultiplayerMgr TU): heap-build the turn-event-2 sync packet, delta or full.
// Turn-event-2 relation-matrix sync packet. Variable-length: full form carries the raw
// 0x89c-short block, delta form (deltaKind21 == 2) carries (index, value) pairs for the
// entries that differ from the baseline.
struct TurnEvent2SyncPacket : NetMessage {
  int pad10;                    // +0x10 - zeroed, no 'time' tag on this packet
  int pad14;                    // +0x14
  NationSlot pendingNationSlot; // +0x18
  unsigned char pad1a[6];       // +0x1a
  unsigned char flag20;         // +0x20 - cleared by the caller after the baseline refresh
  unsigned char deltaKind21;    // +0x21 - 2 = delta pairs, 0 = full block
  unsigned char pad22[2];
  TurnEvent2DeltaPayload payload; // +0x24 - variable-length wire records

  // 0x544cd0 — apply the payload to `buffer` per deltaKind21: 0 = raw block copy,
  // 1 = (short index, byte value) triples, 2 = (short index, short value) pairs,
  // 3 = (short index, int value) records. The receiver decides the element width, so
  // the buffer is opaque here (TDiplomacyMgr passes its short relation matrix).
  void ApplyEncodedDeltaPayloadToBufferByMode(void* buffer);
};
TurnEvent2SyncPacket* __cdecl
BuildTurnEvent2ArraySyncPacketDeltaOrFull(unsigned int shortCount, short* current, short* baseline);

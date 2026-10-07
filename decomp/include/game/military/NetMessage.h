#pragma once

#include "decomp_types.h"
#include "game/game_phase.h"
#include "game/ui_tags_common.h"
#include "game/nation_domain_types.h"

struct NetMessage {
  int eventCode;     // turn-event code ('what')
  int fromNetworkId; // sender network id ('from'); overwritten by TNetMgr::Send
  int toNetworkId;   // destination network id ('to'); -1 = broadcast
  int messageLength; // total packet size in bytes ('messageLen')

  void DestinateToGP(int nationSlot);

  void DestinateTo(int nationSlot);
};

struct TurnEventQueuePacket : NetMessage {
  TurnEventQueuePacket* nextQueuePacket;
};

struct TimelyMessageHeader : NetMessage {
  int messageTag; // 'time'
  unsigned char activeNationId;
  unsigned char pad15[3];

  TimelyMessageHeader* InitializeEmitEventHeaderWithActiveNation();
};

struct TimelyNetMessagePrefix : TimelyMessageHeader {
  GamePhaseStorage syncPhase;

  void SetTimeEmitPacketGameFlowTurnId();
};

// Event-0xF per-nation turn-resume acknowledgement.
struct TurnEventFResumeAckPacket : TimelyNetMessagePrefix {
  NationSlot nationSlot;
  unsigned char pad1e[2];
};

// Event-0x14 treasury delta for one nation.
struct TurnEvent14NationMetricPacket : TimelyMessageHeader {
  NationSlot nationSlot;
  unsigned char pad1a[2];
  int amount;
};

// Event-0x16 diplomacy proposal for one nation.
struct TurnEvent16DiplomacyProposalPacket : TimelyMessageHeader {
  NationSlot nationSlot;
  NationSlot sourceNationSlot;
  DiplomacyProposalCodeStorage proposalCode;
  unsigned char pad1e[2];
};

// Event-0x17 proposal resolution (accept/decline).
struct TurnEvent17ProposalResolutionPacket : TimelyMessageHeader {
  NationSlot nationSlot;
  bool acceptedFlag;
  unsigned char pad1b;
  short proposalIndex;
  unsigned char pad1e[2];
};

struct TurnEvent1DWarTransitionPacket : TimelyNetMessagePrefix {
  char actionCode; // 'i' selects the two-arg check
  signed char nationA1D;
  signed char nationB1E;
  unsigned char mode1F;
};

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

struct TurnEvent2DeltaPayload {
  unsigned char raw[1];
};

struct TurnEvent2SyncPacket : NetMessage {
  int pad10; // zeroed, no 'time' tag on this packet
  int pad14;
  GamePhaseStorage syncPhase;
  unsigned char pad1a[6];
  bool flag20;             // cleared by the caller after the baseline refresh
  unsigned char deltaKind; // 2 = delta pairs, 0 = full block
  unsigned char pad22[2];
  TurnEvent2DeltaPayload payload; // variable-length wire records

  void ApplyEncodedDeltaPayloadToBufferByMode(void* buffer);

  void Free();
};
TurnEvent2SyncPacket* __cdecl
BuildTurnEvent2ArraySyncPacketDeltaOrFull(unsigned int shortCount, short* current, short* baseline);
TurnEvent2SyncPacket* __cdecl
BuildTurnEvent2ByteArraySyncPacketDeltaOrFull(unsigned int byteCount, unsigned char* current,
                                              unsigned char* baseline);
TurnEvent2SyncPacket* __cdecl
BuildTurnEvent2IntArraySyncPacketDeltaOrFull(int intCount, int* current, int* baseline);

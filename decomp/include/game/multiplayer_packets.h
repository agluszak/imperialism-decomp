#pragma once

// Shared multiplayer turn-event wire layouts.
//
// These packet shapes are read and written from more than one translation unit
// (TMultiplayerMgr.cpp emit/receive paths, the HandleDiplomacyTurnEventPacketByCode
// dispatcher TU, and TNetMgr's reachability probe). Each layout is protocol ground
// truth: it used to be declared once per TU under suffixed names, which is exactly
// the silent-drift hazard the type-modeling guardrail warns about, so the single
// definition lives here. Packets used by only one TU stay local to that TU.
//
// Wire framing: every packet derives from the 0x10-byte NetMessage header (see
// NetMessage.h); 'timely' packets prefix the 'time' four-cc tag, the active-nation
// byte, and the pending-nation slot via TimelyMessageHeader/TimelyNetMessagePrefix.

#include "compat.h"
#include "game/game_phase.h"
#include "game/multiplayer_session_tags.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/ui_tags_widgets.h"
#include "game/military/NetMessage.h"
#include "game/nation_domain_types.h" // CongressLeadership / CongressSupportTally
#include "game/map/TMapMgr.h"         // TTerrainStateRecord (event 0x23 payload)
#include "game/news_domain_types.h"

class TObject;

// Serializer tag+object pair for the 0x31 dispatch of TMultiplayerMgr::WriteMessageTo.
struct TaggedSerializablePayload {
  int tag;
  TObject* object;
};

struct StreamMessagePayload32 {
  long scalarValue;
};

struct TurnEvent8NameAnnouncePacket : TimelyMessageHeader {
  char nationSlot;          // +0x18
  char senderName19[0x21];  // +0x19
  char messageText3a[0x2a]; // +0x3a, total 0x64
};

// Event-9 lobby chat/seat-state packet.
struct LobbyChatEvent9Packet : TimelyMessageHeader {
  unsigned char nationSlot; // +0x18
  unsigned char pad19[3];
  int field1C;            // +0x1c - zeroed by seat-state messages
  char senderName[0x21];  // +0x20
  char messageText[0x23]; // +0x41, total 0x64
};

struct LobbyTextPairEvent8Packet : TimelyMessageHeader {
  unsigned char sourceNationSlot;
  char playerName19[0x21];
  char playerNameMirror[0x22];
};

// Event-0xE host session-init record.
struct TurnEventESessionInitPacket : TimelyMessageHeader {
  char mapSeedText[0x21];       // +0x18 - passed to CreatePlanet
  unsigned char mapParamByte39; // +0x39 - third Rebuild arg
  char hostGameName3A[0x22];    // +0x3a
  int saveSlotDword5C;          // +0x5c -> queueSyncDword
  int scenarioTag;              // +0x60 -> scenarioSelectionTag
  signed char difficultyLevel;  // +0x64
  unsigned char nameTableFlag;  // +0x65 -> useLocalizedNameTables
  unsigned char pad66[2];       // total 0x68
};

// Event-0x13 nine-dword nation-news payload.
struct TurnEvent13NewsPacket : TimelyMessageHeader {
  short nationSlot; // +0x18
  unsigned char pad1a[2];
  NewsEvent newsEvent; // +0x1c, total 0x40
};

// Event-0x26 full diplomacy-matrix snapshot.
struct TurnEvent26DiplomacyMatrixPacket : TimelyMessageHeader {
  short relationCodeMatrix[0x180];              // +0x018
  unsigned char pendingPolicyCodeMatrix[0x180]; // +0x318
  short pendingPolicyTierMatrix[0x180];         // +0x498
  CongressLeadership congressLeadership;        // +0x798
  CongressSupportTally congressSupport;         // +0x79c..+0x7a1
  unsigned char pad7a2[2];                      // +0x7a2
  unsigned char relationTailBlock[0x70];        // +0x7a4, total 0x814
};

// Turn-event-1 payload: the remaining turn-resume pending-nation bitmask.
struct TurnEvent1PendingMaskPacket : TimelyMessageHeader {
  int pendingMask; // +0x18, total 0x1c
};

// Turn-event-0xA payload: the resuming nation announces its home region and city name.
struct TurnEventACityAnnouncePacket : TimelyNetMessagePrefix {
  unsigned char nationId1C; // +0x1c
  unsigned char pad1d;
  short homeTile;        // +0x1e
  char cityName20[0x24]; // +0x20 (strncpy'd 0x21), total 0x44
};

struct TurnEventBNationDirectoryPacket : TimelyNetMessagePrefix {
  short homeTileBySlot[0x17];        // +0x1c
  char cityNameBySlot[0x17][0x17];   // +0x4a
  unsigned char pad25b[0xe6];        // reserve to 0x17 * 0x21
  char nationNameBySlot[0x17][0x17]; // +0x341
  unsigned char pad552[0xe6];        // reserve to 0x17 * 0x21
  short portZoneOrdinalBySlot[0x17]; // +0x638
  unsigned char pad666[2];           // total 0x668
};

struct TurnEvent18DiplomacyArraysPacket : TimelyNetMessagePrefix {
  short diplomacyPolicyByNation[7][0x17]; // +0x1c
  short diplomacyGrantByNation[7][0x17];  // +0x15e
  short needLevelByNation[7][0x17];       // +0x2a0
  unsigned char pad3e2[2];                // total 0x3e4
};

struct TurnEvent1FStatusPacket : TimelyMessageHeader {
  int statusTag; // +0x18 - 'aced'/'abdi'/'uhed'/'cgam'/'lose'/'foff'/...
  int value1C;   // +0x1c, total 0x20
};

// Turn-event-0x23 payload: one map tile's 0x24-byte terrain state record.
struct TurnEvent23TileStatePacket : TimelyNetMessagePrefix {
  short tileIndex; // +0x1c
  unsigned char pad1e[2];
  TTerrainStateRecord record; // +0x20, total 0x44
};

struct NationStatusEvent25Packet : TimelyMessageHeader {
  int statusTags[7]; // +0x18 - four-cc per-nation status ('unkn' default)

  void InitializeNationStatusEvent25PayloadDefaults();
};

struct TurnEvent2BPresenceMaskPacket : TimelyMessageHeader {
  unsigned char replyRequestFlag; // +0x18 - nonzero requests the echo reply
  signed char nationMask;         // +0x19 - OR'd (signed) into the accumulator
  unsigned char pad1a[2];         // total 0x1c
};

// Turn-event-0x2D payload: a minor nation's need-level array.
struct TurnEvent2DMinorNeedPacket : TimelyNetMessagePrefix {
  short nationSlot;              // +0x1c
  short needLevelByNation[0x17]; // +0x1e, total 0x4c
};

ASSERT_SIZE(TaggedSerializablePayload, 0x8);
ASSERT_SIZE(StreamMessagePayload32, 0x4);
ASSERT_SIZE(TurnEvent8NameAnnouncePacket, 0x64);
ASSERT_SIZE(LobbyChatEvent9Packet, 0x64);
ASSERT_SIZE(LobbyTextPairEvent8Packet, 0x5c);
ASSERT_SIZE(TurnEventESessionInitPacket, 0x68);
ASSERT_SIZE(TurnEvent13NewsPacket, 0x40);
ASSERT_SIZE(TurnEvent26DiplomacyMatrixPacket, 0x814);
ASSERT_SIZE(TurnEvent1PendingMaskPacket, 0x1c);
ASSERT_SIZE(TurnEventACityAnnouncePacket, 0x44);
ASSERT_SIZE(TurnEventBNationDirectoryPacket, 0x668);
ASSERT_SIZE(TurnEvent18DiplomacyArraysPacket, 0x3e4);
ASSERT_SIZE(TurnEvent1FStatusPacket, 0x20);
ASSERT_SIZE(TurnEvent23TileStatePacket, 0x44);
ASSERT_SIZE(NationStatusEvent25Packet, 0x34);
ASSERT_SIZE(TurnEvent2BPresenceMaskPacket, 0x1c);
ASSERT_SIZE(TurnEvent2DMinorNeedPacket, 0x4c);
ASSERT_OFFSET(TurnEvent8NameAnnouncePacket, nationSlot, 0x18);
ASSERT_OFFSET(TurnEvent8NameAnnouncePacket, messageText3a, 0x3a);
ASSERT_OFFSET(TurnEvent26DiplomacyMatrixPacket, congressLeadership, 0x798);
ASSERT_OFFSET(TurnEventBNationDirectoryPacket, homeTileBySlot, 0x1c);
ASSERT_OFFSET(TurnEventBNationDirectoryPacket, portZoneOrdinalBySlot, 0x638);
ASSERT_OFFSET(TurnEvent18DiplomacyArraysPacket, diplomacyPolicyByNation, 0x1c);
ASSERT_OFFSET(TurnEvent23TileStatePacket, record, 0x20);

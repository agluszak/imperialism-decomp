#pragma once

#include "game/map_domain_types.h"
// Multiplayer wire layouts shared by more than one translation unit. Every packet derives
// from NetMessage; 'timely' packets add the TimelyMessageHeader prefix.

#include "compat.h"
#include "game/game_phase.h"
#include "game/multiplayer_session_tags.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/ui_tags_widgets.h"
#include "game/military/NetMessage.h"
#include "game/nation_domain_types.h"
#include "game/map/TMapMgr.h"
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
  char nationSlot;
  char senderName[33];
  char messageText[42];
};

// Event-9 lobby chat/seat-state packet.
struct LobbyChatEvent9Packet : TimelyMessageHeader {
  unsigned char nationSlot;
  unsigned char pad19[3];
  int sessionId; // zeroed by seat-state messages
  char senderName[33];
  char messageText[35];
};

struct LobbyTextPairEvent8Packet : TimelyMessageHeader {
  unsigned char sourceNationSlot;
  char playerName[33];
  char playerNameMirror[34];
};

// Event-0xE host session-init record.
struct TurnEventESessionInitPacket : TimelyMessageHeader {
  char mapSeedText[33];           // passed to CreatePlanet
  unsigned char wrapHorizontally; // third Rebuild arg
  char hostGameName[34];
  int queueSync;   // > queueSyncDword
  int scenarioTag; // > scenarioSelectionTag
  signed char difficultyLevel;
  unsigned char nameTableFlag; // > useLocalizedNameTables
  unsigned char pad66[2];
};

// Event-0x13 nine-dword nation-news payload.
struct TurnEvent13NewsPacket : TimelyMessageHeader {
  short nationSlot;
  unsigned char pad1a[2];
  NewsEvent newsEvent;
};

// Event-0x26 full diplomacy-matrix snapshot.
struct TurnEvent26DiplomacyMatrixPacket : TimelyMessageHeader {
  short relationCodeMatrix[kProvinceCount];
  unsigned char pendingPolicyCodeMatrix[kProvinceCount];
  short pendingPolicyTierMatrix[kProvinceCount];
  CongressLeadership congressLeadership;
  CongressSupportTally congressSupport;
  unsigned char pad7a2[2];
  unsigned char relationTailBlock[112];
};

// Turn-event-1 payload: the remaining turn-resume pending-nation bitmask.
struct TurnEvent1PendingMaskPacket : TimelyMessageHeader {
  int pendingMask;
};

// Turn-event-0xA payload: the resuming nation announces its home region and city name.
struct TurnEventACityAnnouncePacket : TimelyNetMessagePrefix {
  unsigned char nationId;
  unsigned char pad1d;
  short homeTile;
  char cityName[36]; // total 0x44
};

struct TurnEventBNationDirectoryPacket : TimelyNetMessagePrefix {
  short homeTileBySlot[kNationSlotCount];
  char cityNameBySlot[kNationSlotCount][0x17];
  unsigned char pad25b[230]; // reserve to 0x17 * 0x21
  char nationNameBySlot[kNationSlotCount][0x17];
  unsigned char pad552[230]; // reserve to 0x17 * 0x21
  short portZoneOrdinalBySlot[kNationSlotCount];
  unsigned char pad666[2];
};

struct TurnEvent18DiplomacyArraysPacket : TimelyNetMessagePrefix {
  short diplomacyPolicyByNation[kMajorNationCount][kNationSlotCount];
  short diplomacyGrantByNation[kMajorNationCount][kNationSlotCount];
  short tradePolicyByNation[kMajorNationCount][kNationSlotCount];
};

struct TurnEvent1FStatusPacket : TimelyMessageHeader {
  int statusTag; // 'aced'/'abdi'/'uhed'/'cgam'/'lose'/'foff'/...
  int controlValue;
};

// Turn-event-0x23 payload: one map tile's 0x24-byte terrain state record.
struct TurnEvent23TileStatePacket : TimelyNetMessagePrefix {
  short tileIndex;
  unsigned char pad1e[2];
  TTerrainStateRecord record;
};

struct NationStatusEvent25Packet : TimelyMessageHeader {
  int statusTags[7]; // four-cc per-nation status ('unkn' default)

  void SetDefaults();
};

struct TurnEvent2BPresenceMaskPacket : TimelyMessageHeader {
  unsigned char replyRequestFlag; // nonzero requests the echo reply
  signed char nationMask;         // OR'd (signed) into the accumulator
  unsigned char pad1a[2];
};

// Turn-event-0x2D payload: a minor nation's need-level array.
struct TurnEvent2DMinorNeedPacket : TimelyNetMessagePrefix {
  short nationSlot;
  short tradePolicyByNation[kNationSlotCount];
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
ASSERT_OFFSET(TurnEvent8NameAnnouncePacket, messageText, 0x3a);
ASSERT_OFFSET(TurnEvent26DiplomacyMatrixPacket, congressLeadership, 0x798);
ASSERT_OFFSET(TurnEventBNationDirectoryPacket, homeTileBySlot, 0x1c);
ASSERT_OFFSET(TurnEventBNationDirectoryPacket, portZoneOrdinalBySlot, 0x638);
ASSERT_OFFSET(TurnEvent18DiplomacyArraysPacket, diplomacyPolicyByNation, 0x1c);
ASSERT_OFFSET(TurnEvent23TileStatePacket, record, 0x20);

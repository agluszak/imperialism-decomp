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
#include "game/multiplayer_session_tags.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/ui_tags_widgets.h"
#include "game/military/NetMessage.h"
#include "game/nation_domain_types.h" // CongressLeadership / CongressSupportTally
#include "game/map/TMapMgr.h"         // TTerrainStateRecordView (event 0x23 payload)
#include "game/news_domain_types.h"

class TObject;

// Serializer tag+object pair for the 0x31 dispatch of TMultiplayerMgr::WriteMessageTo.
struct TaggedSerializablePayload {
  int tag;
  TObject* object;
};

// TMultiplayerMgr::SendStreamMessage / WriteMessageTo transport their tag-selected
// payload in one 32-bit `long` (confirmed by the retail Mac signature and the Windows
// RET 0x0c/0x10 call sites). Scalar tags use scalarValue; object tags use the matching
// pointer arm. This keeps the original wire/ABI representation explicit without
// scattering pointer/integer casts through the dispatcher.
//
//   event 0x28: object
//   event 0x2e: scalarValue narrowed to signed short (nation filter)
//   event 0x2f: scalarValue as signed int (terrain descriptor slot)
//   event 0x30: scalarValue as signed int (nation filter)
//   event 0x31: taggedObject
//   event 0x32: no payload; scalarValue is ignored
union StreamMessagePayload32 {
  long scalarValue;
  TObject* object;
  TaggedSerializablePayload* taggedObject;
};

// Event-8 lobby name/status announce: the selected/source nation followed by two
// player-name strings. Both the session UI and receive dispatcher use this wire shape.
struct TurnEvent8NameAnnouncePacket : TimelyMessageHeader {
  char nationSlot18;        // +0x18
  char senderName19[0x21];  // +0x19
  char messageText3a[0x2a]; // +0x3a, total 0x64
};

// Event-9 lobby chat/seat-state packet.
struct LobbyChatEvent9Packet : TimelyMessageHeader {
  unsigned char nationSlot18; // +0x18
  unsigned char pad19[3];
  int field1C;            // +0x1c - zeroed by seat-state messages
  char senderName[0x21];  // +0x20
  char messageText[0x23]; // +0x41, total 0x64
};

// Event-8 lobby text pair emitted from the selected nation and the manager's two
// cached 32-character player-name fields.
struct LobbyTextPairEvent8Packet : TimelyMessageHeader {
  unsigned char sourceNationSlot18;
  char playerName19[0x21];
  char playerNameMirror3A[0x22];
};

// Event-0xE host session-init record.
struct TurnEventESessionInitPacket : TimelyMessageHeader {
  char mapSeedText18[0x21];      // +0x18 - passed to RebuildMapContextAndGlobalMapState
  unsigned char mapParamByte39;  // +0x39 - third Rebuild arg
  char hostGameName3A[0x22];     // +0x3a
  int saveSlotDword5C;           // +0x5c -> queueSyncDword
  int scenarioTag60;             // +0x60 -> scenarioSelectionTag
  signed char difficultyLevel64; // +0x64
  unsigned char nameTableFlag65; // +0x65 -> useLocalizedNameTables68
  unsigned char pad66[2];        // total 0x68
};

// Event-0x13 nine-dword nation-news payload.
struct TurnEvent13NewsPacket : TimelyMessageHeader {
  short nationSlot18; // +0x18
  unsigned char pad1a[2];
  NewsEvent newsEvent1C; // +0x1c, total 0x40
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
  short homeTile1E;      // +0x1e
  char cityName20[0x24]; // +0x20 (strncpy'd 0x21), total 0x44
};

// Turn-event-0xB payload: the full nation directory — home-region tile, city/nation
// display names, and port-zone ordinals per terrain slot. The name rows are reserved
// 0x21 bytes apiece in the struct (hence the pads) but the writer advances only 0x17
// bytes per slot while still strncpy'ing 0x21 — original behavior, kept as-is.
struct TurnEventBNationDirectoryPacket : NetMessage {
  int packetTag;                // +0x10 'time'
  unsigned char activeNationId; // +0x14
  unsigned char pad15[3];
  short pendingNationSlot; // +0x18
  unsigned char pad1a[2];
  short homeTileBySlot[0x17];        // +0x1c
  char cityNameBySlot[0x17][0x17];   // +0x4a
  unsigned char pad25b[0xe6];        // reserve to 0x17 * 0x21
  char nationNameBySlot[0x17][0x17]; // +0x341
  unsigned char pad552[0xe6];        // reserve to 0x17 * 0x21
  short portZoneOrdinalBySlot[0x17]; // +0x638
  unsigned char pad666[2];           // total 0x668
};

// Turn-event-0x18 payload: all seven great powers' diplomacy policy/grant/need arrays
// (host broadcast; also read back by the dispatcher).
struct TurnEvent18DiplomacyArraysPacket : NetMessage {
  int packetTag;                // +0x10 'time'
  unsigned char activeNationId; // +0x14
  unsigned char pad15[3];
  short pendingNationSlot; // +0x18
  unsigned char pad1a[2];
  short diplomacyPolicyByNation[7][0x17]; // +0x1c
  short diplomacyGrantByNation[7][0x17];  // +0x15e
  short needLevelByNation[7][0x17];       // +0x2a0
  unsigned char pad3e2[2];                // total 0x3e4
};

// Turn-event-0x1F payload: game-state four-cc tag plus one dword whose meaning is
// keyed by the tag (the vacated/affected nation slot for 'uhed'/'aced'/'abdi'/'lose',
// a terrain-descriptor index for the overlay-label tags).
struct TurnEvent1FStatusPacket : TimelyMessageHeader {
  int statusTag18; // +0x18 - 'aced'/'abdi'/'uhed'/'cgam'/'lose'/'foff'/...
  int value1C;     // +0x1c, total 0x20
};

// Turn-event-0x23 payload: one map tile's 0x24-byte terrain state record.
struct TurnEvent23TileStatePacket : NetMessage {
  int packetTag;                // +0x10 'time'
  unsigned char activeNationId; // +0x14
  unsigned char pad15[3];
  short pendingNationSlot; // +0x18
  unsigned char pad1a[2];
  short tileIndex; // +0x1c
  unsigned char pad1e[2];
  TTerrainStateRecordView record; // +0x20, total 0x44
};

// Turn-event-0x25 nation-status payload: header + seven per-nation status tags,
// defaulted to 'unkn'; the 'time' tag and active-nation byte are stamped separately
// via InitializeEmitEventHeaderWithActiveNation before sending.
struct NationStatusEvent25Packet : TimelyMessageHeader {
  int statusTags[7]; // +0x18 - four-cc per-nation status ('unkn' default)

  // 0x54bce0: zero the NetMessage header, set eventCode 0x25 / length 0x34, default all
  // seven status tags to 'unkn'.
  void InitializeNationStatusEvent25PayloadDefaults();
};

// Turn-event-0x2B presence/ack mask exchange; also emitted by TNetMgr's reachability
// probe (which sends its own nation id with no reply requested).
struct TurnEvent2BPresenceMaskPacket : TimelyMessageHeader {
  unsigned char replyRequestFlag18; // +0x18 - nonzero requests the echo reply
  signed char nationMask19;         // +0x19 - OR'd (signed) into the accumulator
  unsigned char pad1a[2];           // total 0x1c
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
ASSERT_OFFSET(TurnEvent8NameAnnouncePacket, nationSlot18, 0x18);
ASSERT_OFFSET(TurnEvent8NameAnnouncePacket, messageText3a, 0x3a);
ASSERT_OFFSET(TurnEvent26DiplomacyMatrixPacket, congressLeadership, 0x798);
ASSERT_OFFSET(TurnEventBNationDirectoryPacket, homeTileBySlot, 0x1c);
ASSERT_OFFSET(TurnEventBNationDirectoryPacket, portZoneOrdinalBySlot, 0x638);
ASSERT_OFFSET(TurnEvent18DiplomacyArraysPacket, diplomacyPolicyByNation, 0x1c);
ASSERT_OFFSET(TurnEvent23TileStatePacket, record, 0x20);

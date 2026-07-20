#include "game/TAmbitApplication.h"
#include "game/TMultiplayerMgr.h"

#include <string.h>
#include <time.h>

#include "decomp_types.h"
#include "game/CString.h"
#include "game/mapped_flavor_text.h"
#include "game/NetMessage.h"
#include "game/nation_slot_eligibility.h"
#include "game/ImperialismApp.h"

// Turn-event-0x25 nation-status payload: header + seven per-nation status tags,
// defaulted to 'unkn'; the 'time' tag and active-nation byte are stamped separately via
// InitializeEmitEventHeaderWithActiveNation before sending.
struct NationStatusEvent25Packet : TimelyMessageHeader {
  int statusTags[7]; // +0x18 - four-cc per-nation status ('unkn' default)

  // 0x54bce0: zero the NetMessage header, set eventCode 0x25 / length 0x34, default all
  // seven status tags to 'unkn'.
  void InitializeNationStatusEvent25PayloadDefaults();
};

// Event-9 lobby-chat packet sent when a nation drops during session init: the AWOL
// slot byte plus empty sender/message strings (0x64 bytes total).
struct LobbyChatEvent9Packet : TimelyMessageHeader {
  unsigned char nationSlot18; // +0x18
  unsigned char pad19[3];
  int field1C;            // +0x1c - zeroed
  char senderName[0x21];  // +0x20
  char messageText[0x23]; // +0x41 (total 0x64)
};

// Case-0x31 payload of SerializeOrderDataIntoTurnEventByTag: a {tag, object} pair whose
// 'star'-tagged object carries a sub-tag plus two shorts on the 'land' route. Minimal
// typed view until the real order class is recovered.
struct TaggedSerializablePayload {
  int tag;
  TObject* object;
};
struct StarOrderObjectView {
  void* vftable;
  int subTag;  // +0x04 - 'land' selects the two-short route
  short word8; // +0x08
  short wordA; // +0x0a
};

// Turn-event-0x2c payload: composite snapshot of a nation's city production state
// plus the population-summary scalars and metric buckets.
struct TurnEvent2CPacket : NetMessage {
  int packetTag;                // +0x10 'time'
  unsigned char activeNationId; // +0x14
  unsigned char pad15[3];
  short pendingNationSlot; // +0x18
  unsigned char pad1a[2];
  short nationSlot; // +0x1c
  unsigned char pad1e[2];
  int field910;                     // +0x20
  int aidAllocationTotal;           // +0x24
  unsigned char pad28[6];           // +0x28
  short cityMetricsBlock0E[0x1e];   // +0x2e
  short cityMetricsBlock4A[9];      // +0x6a
  short orderCountByType[0x0e];     // +0x7c
  int cityField78;                  // +0x98
  short cityFieldB4;                // +0x9c
  short cityStock[0x17];            // +0x9e
  short productionOrderTable[0x10]; // +0xcc
  short productionAccum[0x10];      // +0xec
  short cityField26C;               // +0x10c
  unsigned char pad10e[2];
  int orderAccumulatedValues[0x17]; // +0x110
  short popFieldAt8;                // +0x16c
  unsigned char pad16e[2];
  int popFieldAtC;         // +0x170
  short popStockLevel;     // +0x174
  short popExtraAt1e;      // +0x176
  short popFieldAt20;      // +0x178
  short popBucketWords[9]; // +0x17a - baseline/production/pendingDelta valueAt4/6/8
}; // total 0x18c

// Turn-event-0x19 payload: per-nation state arrays (city order counters, external
// diplomacy state, slot-7C metrics, policy/grant/need-level tables).
struct TurnEvent19Packet : NetMessage {
  int packetTag;                // +0x10 'time'
  unsigned char activeNationId; // +0x14
  unsigned char pad15[3];
  short pendingNationSlot; // +0x18
  unsigned char pad1a[2];
  short nationSlot;                    // +0x1c
  short needCapA6;                     // +0x1e
  short orderCountByType[0x0e];        // +0x20
  short externalStateByTarget[0x17];   // +0x3c
  short metricBySlot7C[0x11];          // +0x6a
  short diplomacyPolicyByNation[0x17]; // +0x8c
  short diplomacyGrantByNation[0x17];  // +0xba
  short needLevelByNation[0x17];       // +0xe8
  unsigned char pad116[2];             // total 0x118
};

// Turn-event-0x15 payload: the sender nation's full diplomacy need-state block.
struct TurnEvent15Packet : NetMessage {
  int packetTag;                // +0x10 'time'
  unsigned char activeNationId; // +0x14
  unsigned char pad15[3];
  short nationSlot; // +0x18
  unsigned char pad1a[2];
  int treasuryValue;                 // +0x1c
  int grantTotalCost;                // +0x20
  short needCurrentByType[0x17];     // +0x24
  short needTargetByType[0x17];      // +0x52
  short relationDeltaCurrent[0x17];  // +0x80
  short relationDeltaSnapshot[0x17]; // +0xae
  short diplomacyState1c6[0x17];     // +0xdc
  unsigned char pad10a[2];
  int aidAllocationMatrix[0x170]; // +0x10c
  int budgetPoolBase;             // +0x6cc
  int budgetPoolDelta;            // +0x6d0
  int diplomacyBudgetBase;        // +0x6d4
  signed char escalationCounter;  // +0x6d8
  unsigned char pad6d9[3];
  int pendingCommitmentCost;   // +0x6dc
  signed char pressureCounter; // +0x6e0
  unsigned char pad6e1[3];     // total 0x6e4
};
#include "game/TGreatPower.h"
#include "game/TMapMgr.h"
#include "game/TDiplomacyMgr.h"
#include "game/TMinor.h"
#include "game/TCity.h"
#include "game/TCancelGameOptionsCommand.h"
#include "game/TTradeMgr.h"
#include "game/TNavyMgr.h"
#include "game/THandleStream.h"
#include "game/TCountingStream.h"
#include "game/CIterator.h"
#include "game/TPopulationMgr.h"
#include "game/TProductionOrder.h"
#include "game/TNetMgr.h"
#include "game/TSimMgr.h"
#include "game/TStream.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TArmyMgr.h"
#include "game/TOcean.h"
#include "game/TZone.h"
#include "game/TNextDiplomationCommand.h"
#include "game/TLoadSavePicture.h"
#include "game/TMapPreviewView.h"
#include "game/TViewMgr.h"
#include "game/TApplication.h"
#include "game/TAssetMgr.h"
#include "game/TRadioTextCluster.h"
#include "game/TMacViewMgr.h"
#include "game/TCountry.h"
#include "game/TSoundPlayer.h"
#include "game/global_data_tables.h"
#include "game/ScopedMapQuickDrawContext.h"
#include "game/TControl.h"
#include "game/TDeluxeText.h"
#include "game/TDropShadowText.h"
#include "game/TEditText.h"
#include "game/TNewsMgr.h"
#include "game/TLanguageMgr.h"
#include "game/TLoungeDialog.h"
#include "game/TNextTradeCommand.h"
#include "game/TPicture.h"
#include "game/TPoseMessageDialog.h"
#include "game/TStaticText.h"
#include "game/TArmyTacUnit.h"
#include "game/TTacticalBattle.h"
#include "game/TTextPictureButton.h"
#include "game/quickdraw_rendering.h"
#include "game/turn_event_dialog_provisional.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"
#include <cstdlib>
#include <cstring>

using turn_event_dialog::TurnEventDialogNode;

// Leaf helpers reached through ILT thunks / autogen stubs. They are genuine __cdecl free
// functions (verified against the disassembly — none consume ECX as `this` on entry; the
// ECX loads before some calls are optimizer reuse, not a this-arg). Declared extern in the
// generic repo form per Hard Rule 9 and cast to their real typed signatures at the call sites.
extern undefined4 NoOpInitializeGlobalTurnEventQueueManager();

// Forward decl: real definition (with its // FUNCTION: marker) sits address-ordered
// further down this file, near TMultiplayerMgr's other 0x5exxxx-adjacent members.
static char ReturnTrueRuntimeCredentialInitStub();

// FUNCTION: IMPERIALISM 0x0050ec60
NationStateRecordA8::NationStateRecordA8() {}

// FUNCTION: IMPERIALISM 0x005421a0
int FindActiveNationSlotIndexInGameFlowList() {
  int activeId = GetSessionActiveNationId();
  for (int i = 0; i < 7; ++i) {
    if (g_pGameFlowState->nationSessionIds[i] == activeId) {
      return i;
    }
  }
  return -1;
}

// SYNTHETIC: IMPERIALISM 0x005425d0
// TMultiplayerMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x00542650
// TMultiplayerMgr::GetRuntimeClass

// Binary descriptor base is TObject (0x694eb8), not TEventHandler — original macro arg.
IMPLEMENT_DYNCREATE(TMultiplayerMgr, TObject)

// FUNCTION: IMPERIALISM 0x00542670
TMultiplayerMgr::TMultiplayerMgr()
    : TEventHandler(), gameNameString(), defaultNationTextSlots(), nationDisplayNameSlots(),
      playerNameString(), playerNameMirror(), fieldb8() {
  InitializeUiResourceEntryBaseHeaderDefaults();
  memset(nationStatusControlSlots, 0, sizeof(nationStatusControlSlots));
  lobbyDialogView40 = 0;
  primaryTurnEventQueueHead = 0;
  secondaryTurnEventQueueHead = 0;
  sessionPhaseTag = 0x6e616461;
  fieldF4 = 0;
}

// SYNTHETIC: IMPERIALISM 0x005427e0
// TMultiplayerMgr::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00542810
TMultiplayerMgr::~TMultiplayerMgr() {}

// FUNCTION: IMPERIALISM 0x00542900
undefined TMultiplayerMgr::InitializeMultiplayerManagerForSessionContext(int sessionContext) {
  this->InitializePacketHeaderFields_Tag20202020(0);
  field10 = sessionContext;
  diplomacyQueueContext = 0;
  sessionReadyFlag = 0;
  processPrimaryEventQueue = 1;
  processSecondaryEventQueue = 1;

  TNetMgr* queueStorage = new TNetMgr();
  g_pNetMgr006a6014 = queueStorage;
  NoOpInitializeGlobalTurnEventQueueManager();

  CString loadedString;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&loadedString, 0x2759, 1);

  for (int i = 0; i < kNationSlotCount; ++i) {
    nationSessionIds[i] = 0;
    nationStatusTags[i] = 0x756e6173;
    nationDisplayNameSlots[i] = loadedString;
    defaultNationTextSlots[i] = nationDisplayNameSlots[i];
  }

  queueSyncDword = 0;
  activeNationSlotIndex = -1;
  pendingNationSlotIndex = -1;
  g_pNetMgr006a6014->ResetTurnEventQueueRuntimeRecordBuffer();

  GenerateMappedFlavorTextByCurrentContextNation(&playerNameString);
  LoadProfileStringAndAssignSharedRef(&loadedString, s_PlayerName_0069801c,
                                      static_cast<LPCSTR>(playerNameString));
  playerNameString = loadedString;
  playerNameMirror = playerNameString;

  GenerateMappedFlavorTextByCurrentContextNation(&gameNameString);
  LoadProfileStringAndAssignSharedRef(&loadedString, s_GameName_00698010,
                                      static_cast<LPCSTR>(gameNameString));
  gameNameString = loadedString;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00542b10
void TMultiplayerMgr::Free() {}

// FUNCTION: IMPERIALISM 0x00542be0
void TMultiplayerMgr::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00542ff0
void TMultiplayerMgr::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x005430c0
void TMultiplayerMgr::EnableDiplomacyQueueRoutingAndSetContextField44(void* nContext,
                                                                      char fEnable) {
  processPrimaryEventQueue = 1;
  processSecondaryEventQueue = 1;
  if (fEnable != '\0') {
    diplomacyQueueContext = nContext;
    return;
  }
  diplomacyQueueContext = 0;
}

// FUNCTION: IMPERIALISM 0x00543120
void TMultiplayerMgr::ConfigureTurnResumeStateAndNationMask(int pendingNationSlot,
                                                            int activeNationSlot) {
  pendingNationSlotIndex = pendingNationSlot;
  activeNationSlotIndex = activeNationSlot;
  pendingNationBitmask = 0;
  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (g_apTerrainTypeDescriptorTable[nationSlot] != nullptr) {
      pendingNationBitmask |= 1 << nationSlot;
    }
  }
}

struct TurnEvent3Mode18Packet : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15[3];
};

// Turn-event-1 payload: the remaining turn-resume pending-nation bitmask.
struct TurnEvent1PendingMaskPacket : TimelyMessageHeader {
  int pendingMask; // +0x18, total 0x1c
};

// Clear the slot's turn-resume pending bit; when hosting, broadcast the remaining mask
// as an event-1 packet, and once the mask drains (with a pending event code latched)
// flush it through the diplomacy turn-event dispatcher.
// FUNCTION: IMPERIALISM 0x005431a0
void TMultiplayerMgr::ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry(int nationSlot) {
  pendingNationBitmask &= ~(1 << nationSlot);
  unsigned char hosting = g_pSimMgr->field44 == 1;
  if (hosting != 0) {
    TurnEvent1PendingMaskPacket packet;
    packet.messageTag = 0x74696d65;
    packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
    packet.eventCode = 0;
    packet.fromNetworkId = 0;
    packet.toNetworkId = 0;
    packet.eventCode = 1;
    packet.messageLength = 0;
    packet.messageLength = 0x1c;
    packet.toNetworkId = 0;
    packet.pendingMask = pendingNationBitmask;
    g_pNetMgr006a6014->Send(&packet, 0);
  }
  if (pendingNationBitmask == 0 && pendingNationSlotIndex != -1) {
    HandleDiplomacyTurnEventPacketByCode();
  }
}

// FUNCTION: IMPERIALISM 0x00544540
void TMultiplayerMgr::EnsureGameFlowStateAndPostTurnEvent5E5() {
  TMultiplayerMgr* self = this;
  if (self == 0) {
    self = new TMultiplayerMgr();
    g_pGameFlowState = self;
    if (self != 0) {
      self->InitializeMultiplayerManagerForSessionContext(0);
    }
    self = g_pGameFlowState;
  }
  if (self == 0) {
    return;
  }

  ReturnTrueRuntimeCredentialInitStub();
  g_pGlobalUiRootController->InstallCohandler(self, 1);
  g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5e5);
  self->sessionPhaseTag = 0x70726570; // 'prep'
}

// FUNCTION: IMPERIALISM 0x00544630
void TMultiplayerMgr::ResetDiplomacyRuntimeSelectionAndSetModeNada() {
  g_pGlobalUiRootController->InstallCohandler(g_pGameFlowState, 0);
  g_pSimMgr->field44 = 0;
  if (g_pNetMgr006a6014 != 0) {
    g_pNetMgr006a6014->ResetRuntimeSelectionRecordBufferAndReturnTrue();
  }
  sessionPhaseTag = 0x6e616461; // 'nada'
  lobbyDialogView40 = 0;
}

// FUNCTION: IMPERIALISM 0x005446a0
void TMultiplayerMgr::EmitTurnEvent3Mode18WithActiveNation() {
  TurnEvent3Mode18Packet packet;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0;
  packet.eventCode = 3;
  packet.messageLength = 0x18;
  g_pNetMgr006a6014->Send(&packet, 1);
}

// Broadcasts an event-0x10 "time" packet (same minimal payload as event 3) to every nation
// slot that has both a live network session id and its pending-nation bit set.
// FUNCTION: IMPERIALISM 0x00544720
void TMultiplayerMgr::EmitTurnEvent10ForFlaggedNationSlots() {
  for (int slot = 0; slot < kNationSlotCount; ++slot) {
    if (nationSessionIds[slot] != 0 && (pendingNationBitmask & (1 << slot)) != 0) {
      TurnEvent3Mode18Packet packet;
      packet.packetTag = 0x74696d65;
      packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
      packet.eventCode = 0;
      packet.fromNetworkId = 0;
      packet.messageLength = 0;
      packet.eventCode = 0x10;
      packet.messageLength = 0x18;
      packet.toNetworkId = g_pGameFlowState->nationSessionIds[slot];
      g_pNetMgr006a6014->Send(&packet, 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00544e30
char TMultiplayerMgr::DoIdle(int action) {
  (void)action;
  return 0;
}

// ---------------------------------------------------------------------------
// Turn-event emitters. Each builds a 'time'-tagged NetMessage-derived packet on
// the stack and hands it to TNetMgr::Send (queueOnly per callsite). `this` is
// unused, exactly as in the original __thiscall bodies.
// ---------------------------------------------------------------------------

struct TurnEvent12Packet : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15[3];
  short shortA;
  short shortB;
};

// Ghidra pseudo-types used by the promoted state machine below. `code` is Ghidra's
// raw-code-byte type (used both as a scalar and as a code pointer); the slot type is a
// byte cursor so `param_1 + offset` stays a byte offset into the object.
typedef unsigned char code;
typedef unsigned char CObject_slot_0x04_0x04;
typedef unsigned int undefined3;
typedef signed char sbyte;

// Minimal stand-in for the CString locals that the raw decompile touches only via
// their leading char* buffer (m_pchData at offset 0). Real string semantics are not
// required to reproduce this state machine's control flow.
struct GhStr {
  char* m_pchData;
};

// Ghidra bit-concatenation intrinsics (compile-only; exact widths are not load-bearing
// here). CONCAT31(hi,lo) packs a 3-byte high value with a 1-byte low value, etc.
#define CONCAT11(hi, lo)                                                                           \
  ((unsigned short)(((unsigned int)(unsigned char)(hi) << 8) | (unsigned char)(lo)))
#define CONCAT13(hi, lo)                                                                           \
  (((unsigned int)(unsigned char)(hi) << 24) | ((unsigned int)(lo) & 0xffffffu))
#define CONCAT31(hi, lo) (((unsigned int)(hi) << 8) | (unsigned char)(lo))
#define builtin_strncpy(d, s, n) memcpy((d), (s), (n))

// Ghidra's `operator_new()` (size folded away by the optimizer). A real allocation is
// enough to keep the reconstructed pointer flow compiling and linking.
static void* operator_new(void) {
  return malloc(0x400);
}

// Packet views for the turn-state receive machine below (emit-side twins of several
// of these live earlier in this TU and in TMultiplayerMgr_HandleDiplomacyTurnEvent.cpp).

// Event-8 name/status announce: slot byte at +0x18, then two NUL strings at +0x19/+0x3a.
struct TurnEvent8NameAnnouncePacket : TimelyMessageHeader {
  char nationSlot18;        // +0x18
  char senderName19[0x21];  // +0x19
  char messageText3a[0x2a]; // +0x3a, total 0x64
};

// Event-0xC kick/notice text: message text plus the addressed-nations mask and the
// kicking nation id (or -1) in the two tail bytes.
struct TurnEventCKickMessagePacket : TimelyMessageHeader {
  char messageText18[0x100];            // +0x18
  unsigned char targetNationBitmask118; // +0x118 - 1 << slot per addressed nation
  signed char kickerNationId119;        // +0x119 - -1 = no specific kicker
  unsigned char pad11a[2];              // total 0x11c
};

// Event-0xE host session-init record.
struct TurnEventESessionInitPacket : TimelyMessageHeader {
  char mapSeedText18[0x21];      // +0x18 - passed to RebuildMapContextAndGlobalMapState
  unsigned char mapParamByte39;  // +0x39 - third Rebuild arg
  char hostGameName3A[0x22];     // +0x3a
  int saveSlotDword5C;           // +0x5c -> queueSyncDword
  int scenarioTag60;             // +0x60 -> scenarioSelectionTag
  signed char simStateCode64;    // +0x64
  unsigned char nameTableFlag65; // +0x65 -> g_pSimMgr->useLocalizedNameTables68
  unsigned char pad66[2];        // total 0x68
};

// Event-0xF per-nation turn-resume acknowledge (same shape as the dispatcher TU copy).
struct TurnEventFResumeAckPacketM : TimelyNetMessagePrefix {
  short nationSlot1C;     // +0x1c
  unsigned char pad1e[2]; // total 0x20
};

// Event-0xA city announce (same shape as the dispatcher TU copy).
struct TurnEventACityAnnouncePacketM : TimelyNetMessagePrefix {
  unsigned char nationId1C; // +0x1c
  unsigned char pad1d;
  short homeRegion1E;    // +0x1e
  char cityName20[0x24]; // +0x20, total 0x44
};

// Event-0xB nation directory (same shape as the dispatcher TU copy).
struct TurnEventBNationDirectoryPacketM : NetMessage {
  int packetTag;                // +0x10 'time'
  unsigned char activeNationId; // +0x14
  unsigned char pad15[3];
  short pendingNationSlot; // +0x18
  unsigned char pad1a[2];
  short homeRegionBySlot[0x17];      // +0x1c
  char cityNameBySlot[0x17][0x17];   // +0x4a
  unsigned char pad25b[0xe6];        // reserve to 0x17 * 0x21
  char nationNameBySlot[0x17][0x17]; // +0x341
  unsigned char pad552[0xe6];        // reserve to 0x17 * 0x21
  short portZoneOrdinalBySlot[0x17]; // +0x638
  unsigned char pad666[2];           // total 0x668
};

// Event-0x11 masked byte/word/dword poke into one of the two global map tables.
struct TurnEvent11MapPokePacket : TimelyMessageHeader {
  signed char pokeWidthCode18; // +0x18 - 1 byte / 2 word / 4 dword
  unsigned char pad19[3];
  int bufferSelector1C; // +0x1c - 0 terrainStateTable, 1 cityScoreTable, else null base
  int byteOffset20;     // +0x20 - raw byte offset into the selected table
  short valueWord24;    // +0x24
  short maskWord26;     // +0x26, total 0x28
};

// Event-0x13 nine-dword nation payload.
struct TurnEvent13NationPayloadPacket : TimelyMessageHeader {
  short nationSlot18; // +0x18
  unsigned char pad1a[2];
  int payloadDwords1C[9]; // +0x1c, total 0x40
};

// Event-0x14 nation-metric delta.
struct TurnEvent14NationMetricPacket : TimelyMessageHeader {
  short nationSlot18; // +0x18
  unsigned char pad1a[2];
  int amount1C; // +0x1c, total 0x20
};

// Event-0x16 diplomacy proposal for one nation.
struct TurnEvent16DiplomacyProposalPacket : TimelyMessageHeader {
  short nationSlot18;     // +0x18
  short proposalCode1A;   // +0x1a
  short targetNationId1C; // +0x1c
  unsigned char pad1e[2]; // total 0x20
};

// Event-0x17 proposal resolution (accept/decline).
struct TurnEvent17ProposalResolutionPacket : TimelyMessageHeader {
  short nationSlot18;           // +0x18
  unsigned char acceptedFlag1A; // +0x1a
  unsigned char pad1b;
  short proposalIndex1C;  // +0x1c
  unsigned char pad1e[2]; // total 0x20
};

// Event-0x18 host broadcast of all seven great powers' diplomacy arrays (same shape as
// the dispatcher TU emit-side copy).
struct TurnEvent18DiplomacyArraysPacketM : NetMessage {
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

// Events 0x20/0x21/0x22 receive views (the emit-side structs later in this TU pack
// their payload at different offsets; the receive side reads +0x18..).
struct TurnEvent20PacketM : TimelyMessageHeader {
  short eventParam18;    // +0x18
  signed char nationA1A; // +0x1a
  signed char nationB1B; // +0x1b, total 0x1c
};
struct TurnEvent21PacketM : TimelyMessageHeader {
  signed char byte18;  // +0x18
  signed char byte19;  // +0x19
  signed char byte1A;  // +0x1a
  unsigned char pad1b; // total 0x1c
};
struct TurnEvent22PacketM : TimelyMessageHeader {
  signed char byte18; // +0x18
  unsigned char pad19;
  short word1A; // +0x1a, total 0x1c
};

// Event-0x1A nation action + per-nation counterA2 words.
struct TurnEvent1ANationActionPacket : TimelyNetMessagePrefix {
  short sourceNation1C;     // +0x1c
  short param1E;            // +0x1e
  short param20;            // +0x20
  short param22;            // +0x22
  short param24;            // +0x24
  short counterA2BySlot[7]; // +0x26, total 0x34
};

// Event-0x1B one tracked-slot entry.
struct TurnEvent1BTrackedEntryPacket : TimelyNetMessagePrefix {
  short nationSlot1C;       // +0x1c
  short trackedKind1E;      // +0x1e
  short targetNation20;     // +0x20
  short trackedValue22;     // +0x22
  short trackedSlotIndex24; // +0x24
  unsigned char pad26[2];
  int trackedPayload28; // +0x28, total 0x2c
};

// Event-0x1C proposal amount dispatch.
struct TurnEvent1CProposalAmountPacket : TimelyNetMessagePrefix {
  short ownerNation1C;           // +0x1c
  short sourceContext1E;         // +0x1e
  short maxAmount20;             // +0x20
  short targetNation22;          // +0x22
  short amount24;                // +0x24
  unsigned char emitEventFlag26; // +0x26
  unsigned char pad27;           // total 0x28
};

// Event-0x1D war-transition check/propagate.
struct TurnEvent1DWarTransitionPacket : TimelyNetMessagePrefix {
  char actionCode1C;     // +0x1c - 'i' selects the two-arg check
  signed char nationA1D; // +0x1d
  signed char nationB1E; // +0x1e
  unsigned char mode1F;  // +0x1f, total 0x20
};

// Event-0x1E diplomacy relation action.
struct TurnEvent1EDiplomacyActionPacket : TimelyNetMessagePrefix {
  signed char nation1C;   // +0x1c
  signed char nationA1D;  // +0x1d
  signed char nationB1E;  // +0x1e
  char actionCode1F;      // +0x1f - 'a' or 'i'
  unsigned char flag20;   // +0x20 - role-swap selector
  unsigned char flag21;   // +0x21 - gate for the slot-0x284 paths
  unsigned char pad22[2]; // total 0x24
};

// Event-0x1F game-state four-cc tag + one dword payload.
struct TurnEvent1FGameStateTagPacket : TimelyMessageHeader {
  int statusTag18; // +0x18 - 'aced'/'abdi'/'uhed'/'cgam'/'lose'/'foff'/...
  int value1C;     // +0x1c, total 0x20
};

// Event-0x23 one map tile's terrain-state record (same shape as the dispatcher TU copy).
struct TurnEvent23TileStatePacketM : NetMessage {
  int packetTag;                // +0x10 'time'
  unsigned char activeNationId; // +0x14
  unsigned char pad15[3];
  short pendingNationSlot; // +0x18
  unsigned char pad1a[2];
  short tileIndex; // +0x1c
  unsigned char pad1e[2];
  TTerrainStateRecordView record; // +0x20, total 0x44
};

// Event-0x24 one city-score record (receive side: the 0xa8-byte record is contiguous).
struct TurnEvent24CityRecordPacket : TimelyNetMessagePrefix {
  short cityRecordIndex; // +0x1c
  unsigned char pad1e[2];
  NationStateRecordA8 record; // +0x20
};

// Event-0x26 full diplomacy-matrix snapshot for g_pDiplomacyTurnStateManager.
struct TurnEvent26DiplomacyMatrixPacket : TimelyMessageHeader {
  short relationCodeMatrix[kDiplomacyPairMatrixEntries];              // +0x018
  unsigned char pendingPolicyCodeMatrix[kDiplomacyPairMatrixEntries]; // +0x318
  short pendingPolicyTierMatrix[kDiplomacyPairMatrixEntries];         // +0x498
  short selectedSourceNationSlot;                                     // +0x798
  short selectedTargetNationSlot;                                     // +0x79a
  short selectionFlagsA;                                              // +0x79c
  short selectionFlagsB;                                              // +0x79e
  short selectionFlagsC;                                              // +0x7a0
  unsigned char pad7a2[2];                                            // +0x7a2
  unsigned char relationTailBlock[0x70];                              // +0x7a4, total 0x814
};

// Event-0x27 join-empire dispatch.
struct TurnEvent27JoinEmpirePacket : TimelyMessageHeader {
  int terrainSlot18;      // +0x18 - index into g_apTerrainTypeDescriptorTable
  int targetNationSlot1C; // +0x1c
  int mode20;             // +0x20, total 0x24
};

// Event-0x2D minor need levels (same shape as the dispatcher TU copy).
struct TurnEvent2DMinorNeedPacketM : TimelyNetMessagePrefix {
  short nationSlot;              // +0x1c
  short needLevelByNation[0x17]; // +0x1e, total 0x4c
};

// Events 0x29/0x2A tactical battle commands by fourcc tag.
struct TacticalCommandPacket : TimelyMessageHeader {
  int commandTag18; // +0x18 'sele'/'move'/'mine'/'digg'/'depl'/'raly' (0x29), 'fire' (0x2a)
  int unitId1C;     // +0x1c - resolved via SeekLinkedListCursorByNestedId
  int arg20;        // +0x20
  int arg24;        // +0x24
  int arg28;        // +0x28 ('fire' only)
  int arg2C;        // +0x2c ('fire' only), total 0x30
};

// Event-0x2B presence/ack mask exchange.
struct TurnEvent2BPresenceMaskPacket : TimelyMessageHeader {
  unsigned char replyRequestFlag18; // +0x18 - nonzero requests the echo reply
  signed char nationMask19;         // +0x19 - OR'd (signed) into the accumulator
  unsigned char pad1a[2];           // total 0x1c
};

void LoadUiStringAndDispatchSharedMessageCommand(short group, short index, TView* control);

// FUNCTION: IMPERIALISM 0x00544e70
unsigned char TMultiplayerMgr::InitializeProtocolOptionControlFromProvider(TView* provider) {
  lobbyDialogView40 = provider;
  if (!g_pNetMgr006a6014->ResetRuntimeProtocolOptionsAndRebuildSelectionSource(provider)) {
    return 0;
  }

  int defaultProtocolTag = 0;
  g_pUiViewManager->LoadSettingValueByKeyIntoOut("DefaultProtocol", 0x70726f30 /* 'pro0' */,
                                                 &defaultProtocolTag);
  TRadioTextCluster* protControl =
      static_cast<TRadioTextCluster*>(provider->ResolveControlByTag(kControlTagProt));
  protControl->AssertValid();
  TView* defaultOption = protControl->ResolveControlByTag(defaultProtocolTag);
  if (defaultOption != 0) {
    protControl->SetSelectedTextOptionByTag(defaultProtocolTag, true);
  } else {
    protControl->SetSelectedTextOptionByTag(0x70726f30 /* 'pro0' */, true);
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x00544f30
unsigned char TMultiplayerMgr::ResetGameFlowStateAndPostTurnEvent5DC() {
  lobbyDialogView40 = 0;
  g_pGlobalUiRootController->InstallCohandler(g_pGameFlowState, 0);
  g_pSimMgr->field44 = 0;
  if (g_pNetMgr006a6014 != 0) {
    g_pNetMgr006a6014->ResetRuntimeSelectionRecordBufferAndReturnTrue();
  }
  sessionPhaseTag = 0x6e616461; // 'nada'
  lobbyDialogView40 = 0;
  g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5dc);
  return 1;
}

// FUNCTION: IMPERIALISM 0x00544fc0
unsigned char TMultiplayerMgr::ValidateGameFlowNameAndSelectionContext(int protocolValue,
                                                                       int flag) {
  return g_pNetMgr006a6014->OpenRuntimeSelectionSourceByIndexAndCopyPath(
      protocolValue, flag, static_cast<LPCSTR>(gameNameString));
}

// FUNCTION: IMPERIALISM 0x00544ff0
unsigned char TMultiplayerMgr::ValidateAndPrepareGameFlowNameForDispatch() {
  CString gameName = gameNameString;
  SaveSettingValueFromPointerByKey(&gameName, "GameName");

  int now;
  do {
    now = static_cast<int>(time(0));
    queueSyncDword = now;
  } while (now == 0);

  unsigned char opened = g_pNetMgr006a6014->OpenRuntimeSelectionSourceAndApplyActiveNationState(
      static_cast<LPCSTR>(gameName), static_cast<LPCSTR>(playerNameString), g_szEmptyString);
  if (opened) {
    lobbyDialogView40 = nullptr;
    g_pSimMgr->field44 = 1;
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00545110
unsigned char
TMultiplayerMgr::InitializeRuntimeSelectionCredentialsFromProviderAndConnect(TView* provider) {
  ReturnTrueRuntimeCredentialInitStub();
  lobbyDialogView40 = provider;

  TEditText* nameControl = static_cast<TEditText*>(provider->ResolveControlByTag(kControlTagName));
  nameControl->AssertValid();
  CString normalizedPlayerName =
      g_pLanguageMgr->NormalizeRuntimeCredentialNameToken(&playerNameString);
  nameControl->InitDialogWindowAndSyncTitleIfChanged(&normalizedPlayerName, 0);

  TEditText* passControl = static_cast<TEditText*>(provider->ResolveControlByTag(kControlTagPass));
  passControl->AssertValid();
  CString emptyCaption(g_szEmptyString);
  passControl->InitDialogWindowAndSyncTitleIfChanged(&emptyCaption, 0);

  return g_pNetMgr006a6014->ReturnTrueRuntimeCredentialFinalizeStub();
}

// FUNCTION: IMPERIALISM 0x00545290
unsigned char TMultiplayerMgr::ResetGameFlowStateAndPostTurnEvent5DCAlt() {
  lobbyDialogView40 = 0;
  g_pGlobalUiRootController->InstallCohandler(g_pGameFlowState, 0);
  g_pSimMgr->field44 = 0;
  if (g_pNetMgr006a6014 != 0) {
    g_pNetMgr006a6014->ResetRuntimeSelectionRecordBufferAndReturnTrue();
  }
  sessionPhaseTag = 0x6e616461; // 'nada'
  lobbyDialogView40 = 0;
  g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5dc);
  return 1;
}

// FUNCTION: IMPERIALISM 0x00545320
unsigned char TMultiplayerMgr::ApplyJoinGameSelectionAndPostTurnEvent5E4(int selectionTag) {
  CString defaultGameName("Frog");
  unsigned char joined = g_pNetMgr006a6014->OpenJoinGameRuntimeSelectionAndStartSession(
      selectionTag, &playerNameString, defaultGameName);
  if (joined) {
    playerNameMirror = playerNameString;
    lobbyDialogView40 = 0;
    g_pSimMgr->field44 = 2;
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5e4);
    return 1;
  }
  playerNameString = playerNameMirror;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00545480
unsigned char TMultiplayerMgr::AssignStringAtB4FromB0AndResetState40() {
  playerNameMirror = playerNameString;
  lobbyDialogView40 = 0;
  return 1;
}

// FUNCTION: IMPERIALISM 0x005454b0
unsigned char TMultiplayerMgr::ResetNationStatusSlotsAndInitializeNameControls(TView* panel) {
  lobbyDialogView40 = panel;
  CString loadedString;
  for (int i = 0; i < kNationSlotCount; ++i) {
    nationSessionIds[i] = 0;
    nationStatusTags[i] = 0x756e6173; // 'unas'
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&loadedString, 0x2759, 1);
    TStaticText* nameControl =
        static_cast<TStaticText*>(panel->ResolveControlByTag(0x6e616d30u + i)); // 'nam0'-'nam6'
    nameControl->AssertValid();
    nameControl->SetTextAndMaybeRefresh(&loadedString, 1);
  }

  TView* okayControl = panel->ResolveControlByTag(0x6f6b6179u); // 'okay'
  okayControl->AssertValid();
  okayControl->SetEnabled(0, 0);

  if (g_pSimMgr->field44 == 2) {
    TurnEvent3Mode18Packet packet;
    packet.packetTag = 0x74696d65; // 'time'
    packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
    packet.eventCode = 0;
    packet.fromNetworkId = 0;
    packet.toNetworkId = 0;
    packet.eventCode = 0xd;
    packet.toNetworkId = -1;
    packet.messageLength = 0;
    packet.messageLength = 0x18;
    g_pNetMgr006a6014->Send(&packet, 0);
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x00545660
unsigned char TMultiplayerMgr::ResetLocalUiStateAndPostTurnEvent5E5() {
  lobbyDialogView40 = 0;
  ResetNationStatusArraysAndTurnEventContext();
  g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5e5);
  queueSyncDword = 0;
  return 1;
}

// Receive-side state machine for every diplomacy/lobby turn event ('time' packets).
// Dispatches on eventCode 1..0x32 (codes 4..7 return 0); each case applies the payload
// to the local session/world state and often re-broadcasts or acknowledges. Case bodies
// are laid out in the original binary order.
// FUNCTION: IMPERIALISM 0x00545940
unsigned char TMultiplayerMgr::ProcessDiplomacyTurnStateEventStateMachine(NetMessage* packet) {
  switch (packet->eventCode) {
  case 0xf: {
    // Clear the acknowledging nation's pending bit; when hosting, re-broadcast the mask
    // and flush the latched event code once the mask drains.
    TurnEventFResumeAckPacketM* ack = static_cast<TurnEventFResumeAckPacketM*>(packet);
    pendingNationBitmask &= ~(1 << (char)ack->nationSlot1C);
    unsigned char hosting = g_pSimMgr->field44 == 1;
    if (hosting == 0) {
      return 1;
    }
    TurnEvent1PendingMaskPacket maskPacketF;
    maskPacketF.InitializeEmitEventHeaderWithActiveNation();
    maskPacketF.eventCode = 0;
    maskPacketF.fromNetworkId = 0;
    maskPacketF.eventCode = 1;
    maskPacketF.toNetworkId = 0;
    maskPacketF.pendingMask = pendingNationBitmask;
    maskPacketF.messageLength = 0;
    maskPacketF.messageLength = 0x1c;
    maskPacketF.toNetworkId = 0;
    g_pNetMgr006a6014->Send(&maskPacketF, 0);
    if (pendingNationBitmask == 0 && pendingNationSlotIndex != -1) {
      HandleDiplomacyTurnEventPacketByCode();
      return 1;
    }
    break;
  }
  case 0xa: {
    // A resuming nation announces its home region and city name.
    TurnEventACityAnnouncePacketM* announce = static_cast<TurnEventACityAnnouncePacketM*>(packet);
    if (g_pSimMgr->stateFlag114 == 0) {
      g_pGlobalMapState->SetTileTransportFlagsTo0x37AndRefreshNeighbors(announce->homeRegion1E,
                                                                        (char)announce->nationId1C);
      g_apNationStates[(char)announce->nationId1C]->SetHomeCityTileAndDisplayName(
          announce->homeRegion1E, announce->cityName20);
    }
    pendingNationBitmask &= ~(1 << (char)announce->nationId1C);
    unsigned char hostingA = g_pSimMgr->field44 == 1;
    if (hostingA == 0) {
      return 1;
    }
    TurnEvent1PendingMaskPacket maskPacketA;
    maskPacketA.InitializeEmitEventHeaderWithActiveNation();
    maskPacketA.eventCode = 0;
    maskPacketA.fromNetworkId = 0;
    maskPacketA.eventCode = 1;
    maskPacketA.toNetworkId = 0;
    maskPacketA.pendingMask = pendingNationBitmask;
    maskPacketA.messageLength = 0;
    maskPacketA.messageLength = 0x1c;
    maskPacketA.toNetworkId = 0;
    g_pNetMgr006a6014->Send(&maskPacketA, 0);
    if (pendingNationBitmask == 0 && pendingNationSlotIndex != -1) {
      HandleDiplomacyTurnEventPacketByCode();
      return 1;
    }
    break;
  }
  case 0xb: {
    // Full nation directory: refresh each minor's home tile, city/nation names, and
    // port-zone ordinal, then rebuild all status labels.
    TurnEventBNationDirectoryPacketM* directory =
        static_cast<TurnEventBNationDirectoryPacketM*>(packet);
    for (int dirSlot = 0; dirSlot < 0x17; ++dirSlot) {
      if (dirSlot != g_pSimMgr->GetActiveNationId() &&
          g_apTerrainTypeDescriptorTable[dirSlot]->ShouldDispatchImmediatelySlot28() != 0) {
        g_apTerrainTypeDescriptorTable[dirSlot]->SetNationSelectedRegionAndMapCellLabel(
            directory->homeRegionBySlot[dirSlot], directory->cityNameBySlot[dirSlot]);
        {
          CString nationName(directory->nationNameBySlot[dirSlot]);
          g_apTerrainTypeDescriptorTable[dirSlot]->SetNationDisplayNameAndLocalizationSlotRef(
              nationName);
        }
        {
          CString nationName2(directory->nationNameBySlot[dirSlot]);
          g_apTerrainTypeDescriptorTable[dirSlot]->identitySharedString1 = nationName2;
        }
        if (g_pSimMgr->stateFlag114 == 0) {
          g_pGlobalMapState->SetTileTransportFlagsTo0x37AndRefreshNeighbors(
              directory->homeRegionBySlot[dirSlot], (short)dirSlot);
        }
      }
      TZone* portZone =
          g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(static_cast<short>(dirSlot));
      portZone->contextOrdinal14 = directory->portZoneOrdinalBySlot[dirSlot];
    }
    RefreshNationStatusLabelsAndCodesForSlotOrAll(-1);
    break;
  }
  case 8: {
    // Name/session announce for one slot (or -1 probe): echo an event-9 back to the
    // matching session, kick mismatched sessions with the localized 0x2759/2 text, and
    // release any other slot bound to the same session ('suna' + empty-name event-9).
    TurnEvent8NameAnnouncePacket* announce8 = static_cast<TurnEvent8NameAnnouncePacket*>(packet);
    int announceSlot = announce8->nationSlot18;
    if (announceSlot == -1) {
      // Faithful out-of-bounds quirk: slot -1 reads the dword before nationSessionIds.
      g_pNetMgr006a6014->NotifyIfNationMatchesSessionActiveNation(nationSessionIds[announceSlot]);
    } else if (nationSessionIds[announceSlot] != 0) {
      int fromId = announce8->fromNetworkId;
      if (nationSessionIds[announceSlot] == fromId) {
        LobbyChatEvent9Packet echo;
        echo.InitializeEmitEventHeaderWithActiveNation();
        echo.field1C = fromId;
        echo.eventCode = 0;
        echo.fromNetworkId = 0;
        echo.toNetworkId = 0;
        echo.messageLength = 0;
        echo.toNetworkId = 0;
        echo.messageLength = 0x64;
        echo.eventCode = 9;
        echo.nationSlot18 = (unsigned char)announceSlot;
        strcpy(echo.senderName, announce8->senderName19);
        strcpy(echo.messageText, announce8->messageText3a);
        g_pNetMgr006a6014->Send(&echo, 1);
        return 1;
      } else {
        TurnEventCKickMessagePacket kick;
        kick.messageTag = 0x74696d65; // 'time'
        short activeNation8 = g_pSimMgr->GetActiveNationId();
        kick.eventCode = 0;
        kick.activeNationId = (unsigned char)activeNation8;
        kick.fromNetworkId = 0;
        kick.eventCode = 0xc;
        kick.toNetworkId = 0;
        kick.targetNationBitmask118 = 0xff;
        kick.messageLength = 0;
        kick.messageLength = 0x11c;
        // Dead second query kept for fidelity: the original re-reads the active nation
        // here and discards the result.
        g_pSimMgr->GetActiveNationId();
        kick.toNetworkId = announce8->fromNetworkId;
        kick.kickerNationId119 = -1;
        CString kickText;
        g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&kickText, 0x2759, 2);
        strcpy(kick.messageText18, kickText);
        g_pNetMgr006a6014->Send(&kick, 0);
        return 1;
      }
    }
    for (int scanSlot = 0; scanSlot < 7; ++scanSlot) {
      if (nationSessionIds[scanSlot] == announce8->fromNetworkId) {
        nationSessionIds[scanSlot] = 0;
        nationStatusTags[scanSlot] = 0x756e6173; // 'suna'
        const char* emptyName = g_szEmptyString;
        LobbyChatEvent9Packet vacate;
        vacate.InitializeEmitEventHeaderWithActiveNation();
        vacate.eventCode = 0;
        vacate.fromNetworkId = 0;
        vacate.nationSlot18 = (unsigned char)scanSlot;
        vacate.toNetworkId = 0;
        vacate.toNetworkId = 0;
        vacate.messageLength = 0;
        vacate.field1C = 0;
        vacate.messageLength = 0x64;
        vacate.eventCode = 9;
        strcpy(vacate.senderName, emptyName);
        strcpy(vacate.messageText, emptyName);
        g_pNetMgr006a6014->Send(&vacate, 1);
      }
    }
    if (announceSlot != -1) {
      LobbyChatEvent9Packet claim;
      claim.InitializeEmitEventHeaderWithActiveNation();
      claim.eventCode = 0;
      claim.field1C = announce8->fromNetworkId;
      claim.fromNetworkId = 0;
      claim.eventCode = 9;
      claim.toNetworkId = 0;
      claim.messageLength = 0;
      claim.toNetworkId = 0;
      claim.messageLength = 0x64;
      claim.nationSlot18 = (unsigned char)announceSlot;
      strcpy(claim.senderName, announce8->senderName19);
      strcpy(claim.messageText, announce8->messageText3a);
      g_pNetMgr006a6014->Send(&claim, 1);
      return 1;
    }
    break;
  }
  case 9: {
    // A session claims (or vacates) a nation slot: adopt the names/session id, restamp
    // the status tag, refresh the lounge dialog's row, and - when hosting - retune the
    // start button and lobby message. Slot 0xf3 asks the host to re-broadcast its own
    // claim instead.
    LobbyChatEvent9Packet* chat = reinterpret_cast<LobbyChatEvent9Packet*>(packet);
    if (chat->nationSlot18 != 0xf3) {
      char slot9 = (char)chat->nationSlot18;
      int sessionId = chat->field1C;
      {
        CString senderName(chat->senderName);
        defaultNationTextSlots[slot9] = senderName;
      }
      {
        CString messageText9(chat->messageText);
        nationDisplayNameSlots[slot9] = messageText9;
      }
      int oldSessionId = nationSessionIds[slot9];
      nationSessionIds[slot9] = sessionId;
      unsigned char isLocal;
      if (sessionId == GetSessionActiveNationId() && sessionId != 0) {
        isLocal = 1;
        activeNationTagIndex = (unsigned char)slot9;
      } else {
        isLocal = 0;
      }
      CString statusText;
      if (sessionId == 0) {
        g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&statusText, 0x2759, 1);
        nationStatusTags[slot9] = 0x756e6173; // 'suna'
      } else {
        statusText = nationDisplayNameSlots[slot9];
        unsigned char sessionBusy;
        if (sessionPhaseTag == 0x676f696e /* 'goin' */ && g_pSimMgr->GetActiveNationId() != -1) {
          sessionBusy = 1;
        } else {
          sessionBusy = 0;
        }
        nationStatusTags[slot9] =
            (-(unsigned int)sessionBusy & 0xf0100f00) + 0x72656479; // 'busy' : 'redy'
      }
      nationDisplayNameSlots[slot9] = statusText;
      defaultNationTextSlots[slot9] = nationDisplayNameSlots[slot9];
      TLoungeDialog* lounge;
      if (lobbyDialogView40 != 0 &&
          lobbyDialogView40->IsKindOf(RUNTIME_CLASS(TLoungeDialog)) != 0) {
        lounge = (TLoungeDialog*)lobbyDialogView40;
      } else {
        lounge = 0;
      }
      if (lounge != 0) {
        TStaticText* nameLabel =
            (TStaticText*)lounge->ResolveControlByTag(0x6e616d30 /* 'nam0' */ + slot9);
        nameLabel->AssertValid();
        CString normalizedName = g_pLanguageMgr->NormalizeRuntimeCredentialNameToken(&statusText);
        nameLabel->SetTextAndMaybeRefresh(&normalizedName, 1);
        ApplyUiTextStyleAndThemeFlags((TDropShadowText*)nameLabel, 0, 0xe,
                                      isLocal != 0 ? 0x2b6c : 0x2b6b,
                                      isLocal != 0 ? 0x2b6b : 0x2b6c);
        if (oldSessionId == GetSessionActiveNationId() || sessionId == GetSessionActiveNationId()) {
          int mySlot = 6;
          while (mySlot >= 0 && nationSessionIds[mySlot] != GetSessionActiveNationId()) {
            --mySlot;
          }
          TMapPreviewView* mapControl =
              static_cast<TMapPreviewView*>(lounge->ResolveControlByTag(0x6d617020 /* 'map ' */));
          mapControl->AssertValid();
          mapControl->selectedNation68 = mySlot;
          mapControl->EnhancePhoto();
          RECT mapRect;
          mapControl->QueryContentBounds(&mapRect);
          {
            ScopedMapQuickDrawContext quickDraw(mapControl);
            mapControl->ApplyRectSlot110(&mapRect);
          }
          TPicture* coatControl = (TPicture*)lounge->ResolveControlByTag(0x636f6174 /* 'coat' */);
          coatControl->AssertValid();
          if (mySlot >= 0) {
            coatControl->SetPictureResourceIdAndRefresh((short)(mySlot + 0x120a), 1);
          }
          coatControl->SetEnabled(mySlot >= 0, 1);
        }
        if (g_pSimMgr->field44 == 1) {
          unsigned char localPresent = 0;
          int liveCount = 0;
          for (int liveSlot = 0; liveSlot < 7; ++liveSlot) {
            if (nationSessionIds[liveSlot] != 0) {
              ++liveCount;
              if (nationSessionIds[liveSlot] == GetSessionActiveNationId()) {
                localPresent = 1;
              }
            }
          }
          unsigned char canStart;
          if (liveCount < 2 || localPresent == 0) {
            canStart = 0;
          } else {
            canStart = 1;
          }
          TTextPictureButton* okayButton =
              (TTextPictureButton*)lounge->ResolveControlByTag(0x6f6b6179 /* 'okay' */);
          okayButton->AssertValid();
          CString startText;
          g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&startText, 0x2759, 3);
          if (canStart != 0) {
            okayButton->buttonText = startText;
            okayButton->RefreshControl();
          }
          okayButton->SetState(canStart, 0);
          okayButton->SetEnabled(canStart, 1);
          okayButton->themeCode9A = 0x2b6c;
          okayButton->themeCode9C = 0x2b6b;
          okayButton->pointSize98 = 0xc;
          TView* messControl = lounge->ResolveControlByTag(0x6d657373 /* 'mess' */);
          messControl->AssertValid();
          messControl->SetEnabled(canStart == 0, 1);
          LoadUiStringAndDispatchSharedMessageCommand(0x2742, canStart != 0 ? 0xa : 0xc,
                                                      messControl);
          lounge->AssertValid();
          lounge->SetPictureResourceIdAndRefresh(canStart != 0 ? 0x11f9 : 0x11f8, 1);
        }
      }
      return 1;
    }
    if (g_pSimMgr->field44 == 1) {
      int sessionId2 = GetSessionActiveNationId();
      short mySlot2 = (char)activeNationTagIndex;
      LobbyChatEvent9Packet claim2;
      claim2.InitializeEmitEventHeaderWithActiveNation();
      claim2.nationSlot18 = (unsigned char)mySlot2;
      claim2.field1C = sessionId2;
      claim2.eventCode = 0;
      claim2.eventCode = 9;
      claim2.fromNetworkId = 0;
      claim2.toNetworkId = 0;
      claim2.messageLength = 0;
      claim2.toNetworkId = 0;
      claim2.messageLength = 0x64;
      strcpy(claim2.senderName, playerNameString);
      strcpy(claim2.messageText, playerNameMirror);
      g_pNetMgr006a6014->Send(&claim2, 1);
      return 1;
    }
    break;
  }
  case 0xc: {
    // Kick/leave notice: if the local nation is addressed, build the "[nation] kicked
    // you" (or generic) text, run the 0x7e4 modal dialog, and on an 'rsvp' response
    // queue a 'pose' command.
    TurnEventCKickMessagePacket* kickView = static_cast<TurnEventCKickMessagePacket*>(packet);
    int localSlot = g_pSimMgr->GetActiveNationId();
    if (localSlot == -1) {
      int sessionIdC = GetSessionActiveNationId();
      int probe;
      for (probe = 0; probe < 7; ++probe) {
        if (g_pGameFlowState->nationSessionIds[probe] == sessionIdC) {
          break;
        }
      }
      localSlot = probe < 7 ? probe : -1;
    }
    if (localSlot != -1 && (kickView->targetNationBitmask118 & (1 << localSlot)) == 0) {
      return 1;
    }
    int kickerNation = kickView->kickerNationId119;
    CString messageTextC(kickView->messageText18);
    CString templateTextC;
    CString titleText;
    if (kickerNation != -1 && kickerNation != localSlot) {
      g_pSimMgr->GetString(0x2749, 7, &templateTextC);
      scanBracketExpressions(g_pSimMgr, &titleText, static_cast<const char*>(templateTextC),
                             static_cast<const char*>(defaultNationTextSlots[kickerNation]));
    } else {
      BuildUiMessageTextFromBracketTemplate(g_pSimMgr, &titleText, 0x2749, 3, 0x2749, 0);
    }
    TUiTextStyleDescriptor styleDescriptor;
    styleDescriptor.textColor = 0;
    BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xc, 0x2b67);
    TurnEventDialogNode* dialog = static_cast<TurnEventDialogNode*>(
        g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x7e4));
    if (dialog == 0) {
      FailNilPointerWithAssert(s_SourcePathUMultiplayerMgr_00698040, 0x7ef);
    }
    dialog->ShowTurnEventDialog(1);
    void* content = dialog->QueryTurnEventContentObject();
    if (content != 0) {
      *reinterpret_cast<int*>(reinterpret_cast<char*>(content) + 0x14) = 0x6f6b6179; // 'okay'
    }
    POINT placement;
    g_pUiRuntimeContext->ComputeTurnEventDialogPlacementByCode(dialog, &placement);
    dialog->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
    TPicture* goldPicture = static_cast<TPicture*>(dialog->ResolveControlByTag(0x444c4f47));
    goldPicture->AssertValid();
    if (goldPicture == 0) {
      FailNilPointerWithAssert(s_SourcePathUMultiplayerMgr_00698040, 0x7fd);
    }
    goldPicture->SetPictureResourceIdAndRefresh(0x24cd, 0);
    TPicture* coatPicture = static_cast<TPicture*>(dialog->ResolveControlByTag(0x636f6174));
    coatPicture->AssertValid();
    if (coatPicture == 0) {
      FailNilPointerWithAssert(s_SourcePathUMultiplayerMgr_00698040, 0x802);
    }
    coatPicture->SetPictureResourceIdAndRefresh(static_cast<short>(kickerNation + 0x251c), 0);
    TStaticText* titleControl = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x7469746c));
    titleControl->AssertValid();
    if (titleControl == 0) {
      FailNilPointerWithAssert(s_SourcePathUMultiplayerMgr_00698040, 0x807);
    }
    titleControl->SetTextStyleAndMaybeRefresh(&styleDescriptor, 0);
    titleControl->SetTextAlignmentAndMaybeRefresh(1, 0);
    titleControl->SetTextAndMaybeRefresh(&titleText, 0);
    TDeluxeText* infoControl = static_cast<TDeluxeText*>(dialog->ResolveControlByTag(0x696e666f));
    infoControl->AssertValid();
    infoControl->SetTextEntryFromChars(static_cast<const char*>(messageTextC),
                                       messageTextC.GetLength());
    infoControl->ApplyTextStyleDescriptorAndMaybeRefresh(&styleDescriptor, 0);
    unsigned char savedProcessPrimary = g_pGameFlowState->processPrimaryEventQueue;
    g_pGameFlowState->processPrimaryEventQueue = 0;
    if (kickerNation != -1 || localSlot != -1) {
      TPicture* cancelButton = static_cast<TPicture*>(dialog->ResolveControlByTag(0x636e636c));
      cancelButton->AssertValid();
      cancelButton->controlTag = 0x72737670; // 'rsvp'
      cancelButton->SetEnabled(1, 0);
      cancelButton->SetState(1, 0);
      cancelButton->SetPictureResourceIdAndRefresh(0x53a, 0);
    }
    int responseTag = dialog->RefreshTurnEventDialog();
    dialog->Close();
    dialog->Free();
    if (responseTag == 0x72737670) { // 'rsvp'
      TPoseMessageDialog* poseCommand = new TPoseMessageDialog();
      poseCommand->kickedByNationSlot18 = kickerNation;
      poseCommand->InitializeRangePair(0x706f7365 /* 'pose' */, g_pGlobalUiRootController, 0, 0, 0);
      g_pGlobalUiRootController->DispatchUiSelectionToHandler(poseCommand);
    }
    g_pGameFlowState->processPrimaryEventQueue = savedProcessPrimary;
    break;
  }
  case 1: {
    // Adopt the host's remaining pending-nation bitmask.
    pendingNationBitmask = static_cast<TurnEvent1PendingMaskPacket*>(packet)->pendingMask;
    break;
  }
  case 2: {
    // Apply the relation-matrix sync payload unless the baseline-refresh flag is set.
    TurnEvent2SyncPacket* syncPacket = static_cast<TurnEvent2SyncPacket*>(packet);
    if (syncPacket->flag20 != 0) {
      return 1;
    }
    g_pDiplomacyTurnStateManager->ApplyTurnEvent2SyncPacketToRelationMatrix(syncPacket);
    break;
  }
  case 0xd:
    // Re-emit the event-0xE/9 session context packets for the requesting session.
    EmitTurnEventEAnd9SessionContextPackets(packet);
    break;
  case 0xe: {
    // Host session-init: adopt sim state/game name/scenario selection, then build the
    // world per the scenario tag ('load'/'rand'/'scnX') and refresh the lounge.
    TurnEventESessionInitPacket* sessionInit = static_cast<TurnEventESessionInitPacket*>(packet);
    g_pSimMgr->SetStateCodeAndUpdateZeroOrOutOfRangeFlag(sessionInit->simStateCode64);
    g_pSimMgr->useLocalizedNameTables68 = sessionInit->nameTableFlag65;
    {
      CString hostGameName(sessionInit->hostGameName3A);
      gameNameString = hostGameName;
    }
    scenarioSelectionTag = sessionInit->scenarioTag60;
    queueSyncDword = sessionInit->saveSlotDword5C;
    sessionPhaseTag = 0x696e6974; // 'init'
    if (scenarioSelectionTag == 0x6c6f6164 /* 'load' */) {
      unsigned char probed =
          BuildSaveSlotPathAndProbeMetadata(queueSyncDword, g_pszClientSavePrefix_0065BF5C);
      if (probed == 0) {
        CString messageTextE;
        g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&messageTextE, 0x2742,
                                                                        0x14);
        g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
            messageTextE, &g_cstrNationAwolMessageStore, 0, 0);
        TCancelGameOptionsCommand* cancelCommand = new TCancelGameOptionsCommand();
        cancelCommand->InitializeRangePair(0x63676f70 /* 'cgop' */, g_pGlobalUiRootController, 0, 0,
                                           0);
        g_pGlobalUiRootController->DispatchUiSelectionToHandler(cancelCommand);
        return 1;
      }
      g_pGameFlowState->lobbyDialogView40 = 0;
      g_pGameFlowState->sessionPhaseTag = 0x676f696e; // 'goin'
      g_pGameFlowState->RefreshNationStatusLabelsAndCodesForSlotOrAll(-1);
      return 1;
    } else if (scenarioSelectionTag == 0x72616e64 /* 'rand' */) {
      g_pSimMgr->RebuildGlobalOrderManagersAndCapabilityState(1);
      g_pSimMgr->RebuildMapContextAndGlobalMapState(1, sessionInit->mapSeedText18,
                                                    sessionInit->mapParamByte39);
    } else if (scenarioSelectionTag >= 0x73636e30 /* 'scn0' */ &&
               scenarioSelectionTag <= 0x73637a39 /* 'scz9' */) {
      g_pSimMgr->RebuildGlobalOrderManagersAndCapabilityState(1);
      unsigned char rebuilt = g_pSimMgr->RecreateActiveMapContextAndInitializeGlobalMapState(
          scenarioSelectionTag - 0x73636e30);
      if (rebuilt == 0) {
        CString messageTextE2;
        g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&messageTextE2, 0x2742, 2);
        g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
            messageTextE2, &g_cstrNationAwolMessageStore, 0, 0);
        TCancelGameOptionsCommand* cancelCommand2 = new TCancelGameOptionsCommand();
        cancelCommand2->InitializeRangePair(0x63676f70 /* 'cgop' */, g_pGlobalUiRootController, 0,
                                            0, 0);
        g_pGlobalUiRootController->DispatchUiSelectionToHandler(cancelCommand2);
        return 1;
      }
    } else {
      return 1;
    }
    // Shared tail: refresh the lounge dialog's map/message controls (the original
    // tolerates a null lounge receiver).
    TLoungeDialog* loungeE;
    if (lobbyDialogView40 != 0 && lobbyDialogView40->IsKindOf(RUNTIME_CLASS(TLoungeDialog)) != 0) {
      loungeE = (TLoungeDialog*)lobbyDialogView40;
    } else {
      loungeE = 0;
    }
    loungeE->RefreshMapAndMessageControlsForCurrentContext();
    break;
  }
  case 3: {
    // Enter the 'goin' phase; a session with no nation slot posts the cancel command,
    // otherwise the local nation goes 'busy' and the event-0x25 status board goes out.
    sessionPhaseTag = 0x676f696e; // 'goin'
    activeNationSlotIndex = -1;
    pendingNationSlotIndex = -1;
    int sessionId3 = GetSessionActiveNationId();
    int matchSlot = 0;
    int* sessionIdCursor = nationSessionIds;
    do {
      if (*sessionIdCursor == sessionId3) {
        break;
      }
      ++matchSlot;
      ++sessionIdCursor;
    } while (matchSlot < 7);
    if (matchSlot >= 7) {
      matchSlot = -1;
    }
    if (matchSlot == -1) {
      TCancelGameOptionsCommand* cancelCommand3 = new TCancelGameOptionsCommand();
      cancelCommand3->InitializeRangePair(0x63676f70 /* 'cgop' */, g_pGlobalUiRootController, 0, 0,
                                          0);
      g_pGlobalUiRootController->DispatchUiSelectionToHandler(cancelCommand3);
      return 1;
    }
    int tagSlot = g_pSimMgr->GetActiveNationId();
    if (tagSlot == -1) {
      tagSlot = (char)activeNationTagIndex;
    }
    nationStatusTags[tagSlot] = 0x62757379; // 'busy'
    NationStatusEvent25Packet statusPacket;
    statusPacket.messageTag = 0x74696d65; // 'time'
    statusPacket.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
    statusPacket.eventCode = 0;
    statusPacket.fromNetworkId = 0;
    statusPacket.eventCode = 0x25;
    statusPacket.messageLength = 0;
    statusPacket.messageLength = 0x34;
    for (int tagInit = 0; tagInit < 7; ++tagInit) {
      statusPacket.statusTags[tagInit] = 0x756e6b6e; // 'unkn'
    }
    statusPacket.toNetworkId = 0;
    statusPacket.statusTags[tagSlot] = 0x62757379; // 'busy'
    g_pNetMgr006a6014->Send(&statusPacket, 0);
    g_pSimMgr->PostMainWindowCommand100ForTurnFlow();
    break;
  }
  case 0x10:
    g_pSimMgr->PostMainWindowCommand100ForTurnFlow();
    break;
  case 0x11: {
    // Masked byte/word/dword poke into a global map table; the host rebroadcasts.
    TurnEvent11MapPokePacket* poke = static_cast<TurnEvent11MapPokePacket*>(packet);
    switch (poke->pokeWidthCode18) {
    case 1: {
      unsigned char* bufferBase1 = 0;
      if (poke->bufferSelector1C == 0) {
        bufferBase1 = reinterpret_cast<unsigned char*>(g_pGlobalMapState->terrainStateTable);
      } else if (poke->bufferSelector1C == 1) {
        bufferBase1 = reinterpret_cast<unsigned char*>(g_pGlobalMapState->cityScoreTable);
      }
      unsigned char maskByte = static_cast<unsigned char>(poke->maskWord26);
      unsigned char* target1 = bufferBase1 + poke->byteOffset20;
      *target1 =
          static_cast<unsigned char>((*target1 & static_cast<unsigned char>(~maskByte)) |
                                     (static_cast<unsigned char>(poke->valueWord24) & maskByte));
      break;
    }
    case 2: {
      unsigned char* bufferBase2 = 0;
      if (poke->bufferSelector1C == 0) {
        bufferBase2 = reinterpret_cast<unsigned char*>(g_pGlobalMapState->terrainStateTable);
      } else if (poke->bufferSelector1C == 1) {
        bufferBase2 = reinterpret_cast<unsigned char*>(g_pGlobalMapState->cityScoreTable);
      }
      short* target2 = reinterpret_cast<short*>(bufferBase2 + poke->byteOffset20);
      *target2 = static_cast<short>((*target2 & ~poke->maskWord26) |
                                    (poke->valueWord24 & poke->maskWord26));
      break;
    }
    case 4: {
      unsigned char* bufferBase4 = 0;
      if (poke->bufferSelector1C == 0) {
        bufferBase4 = reinterpret_cast<unsigned char*>(g_pGlobalMapState->terrainStateTable);
      } else if (poke->bufferSelector1C == 1) {
        bufferBase4 = reinterpret_cast<unsigned char*>(g_pGlobalMapState->cityScoreTable);
      }
      int maskBits = poke->maskWord26;
      int* target4 = reinterpret_cast<int*>(bufferBase4 + poke->byteOffset20);
      *target4 = (poke->valueWord24 & maskBits) | (*target4 & ~maskBits);
      break;
    }
    default:
      break;
    }
    unsigned char hosting11 = g_pSimMgr->field44 == 1;
    if (hosting11 == 0) {
      return 1;
    }
    TurnEvent11MapPokePacket rebroadcast = *poke;
    rebroadcast.eventCode = 0;
    rebroadcast.fromNetworkId = 0;
    rebroadcast.toNetworkId = 0;
    rebroadcast.eventCode = 0x11;
    rebroadcast.messageLength = 0;
    rebroadcast.messageLength = 0x28;
    rebroadcast.toNetworkId = 0;
    g_pNetMgr006a6014->Send(&rebroadcast, 0);
    break;
  }
  case 0x12: {
    // City ownership change via the map manager virtual.
    TurnEvent12Packet* cityOwner = static_cast<TurnEvent12Packet*>(packet);
    g_pGlobalMapState->DispatchFormationEntryActionsAndMaybeCreateTurnEvent12(cityOwner->shortA,
                                                                              cityOwner->shortB);
    break;
  }
  case 0x13: {
    // Queue the nine-dword payload into the nation's event bucket.
    TurnEvent13NationPayloadPacket* nationPayload =
        static_cast<TurnEvent13NationPayloadPacket*>(packet);
    g_pInterNationEventQueueManager->QueueInterNationEventIntoNationBucket(
        nationPayload->nationSlot18, reinterpret_cast<int>(nationPayload->payloadDwords1C), 1);
    break;
  }
  case 0x20: {
    TurnEvent20PacketM* dedupedEvent = static_cast<TurnEvent20PacketM*>(packet);
    g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(
        dedupedEvent->eventParam18, dedupedEvent->nationA1A, dedupedEvent->nationB1B, 1);
    break;
  }
  case 0x21: {
    TurnEvent21PacketM* mergedEvent = static_cast<TurnEvent21PacketM*>(packet);
    g_pInterNationEventQueueManager->QueueInterNationEventType0FWithBitmaskMerge(
        mergedEvent->byte18, mergedEvent->byte19, mergedEvent->byte1A, 1);
    break;
  }
  case 0x22: {
    TurnEvent22PacketM* type11Event = static_cast<TurnEvent22PacketM*>(packet);
    g_pInterNationEventQueueManager->QueueInterNationEventType11(type11Event->byte18,
                                                                 type11Event->word1A, 1);
    break;
  }
  case 0x1d: {
    // War-transition check ('i') or propagate on the active nation.
    TurnEvent1DWarTransitionPacket* warTransition =
        static_cast<TurnEvent1DWarTransitionPacket*>(packet);
    TGreatPower* nation1D = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    if (warTransition->actionCode1C == 0x69 /* 'i' */) {
      nation1D->CheckTransitionSlot27C(warTransition->nationA1D, warTransition->nationB1E);
    } else {
      nation1D->PropagateWarTransitionSlot280(warTransition->nationA1D, warTransition->nationB1E,
                                              warTransition->mode1F);
    }
    break;
  }
  case 0x1e: {
    // Diplomacy relation action - 'a' applies relation code 2 (or routes through the
    // relation-4/event-18 path), 'i' incites a third party or flips a minor's owner;
    // always finishes by posting the 'NeXT' diplomacy command.
    TurnEvent1EDiplomacyActionPacket* action =
        static_cast<TurnEvent1EDiplomacyActionPacket*>(packet);
    if (action->actionCode1F == 0x61 /* 'a' */) {
      if (action->flag21 != 0) {
        TGreatPower* nation1E = g_apNationStates[action->nation1C];
        if (action->flag20 == 0) {
          nation1E->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(action->nationB1E, 2,
                                                                         action->nationA1D);
        } else {
          nation1E->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(action->nationA1D, 2,
                                                                         action->nationB1E);
        }
      } else {
        if (action->flag20 == 0) {
          g_pDiplomacyTurnStateManager->ApplyRelationCode4AndQueueEvent18ForTargetNation(
              action->nation1C, action->nationA1D, 1);
        } else {
          g_pDiplomacyTurnStateManager->ApplyRelationCode4AndQueueEvent18ForTargetNation(
              action->nation1C, action->nationB1E, 0);
        }
      }
    } else if (action->actionCode1F == 0x69 /* 'i' */ && action->flag21 != 0) {
      if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(action->nation1C, action->nationB1E) ==
          0) {
        g_apNationStates[action->nation1C]->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(
            action->nationB1E, 1, action->nationA1D);
      } else {
        TMinor* minor1E = g_apSecondaryNationStateSlots[action->nationA1D];
        if (minor1E->DecodeOwnerNationSlot() != static_cast<short>(action->nation1C)) {
          minor1E->ApplyJoinEmpireModeForTargetNation(action->nation1C, 1);
        }
      }
    }
    TNextDiplomationCommand* nextCommand = new TNextDiplomationCommand();
    nextCommand->DispatchUiPacketWithTagNEXT();
    break;
  }
  case 0x1a: {
    // In teardown mode adopt the per-nation diplomacyCounterA2 words, then route the
    // decision through the UI runtime.
    TurnEvent1ANationActionPacket* nationAction =
        static_cast<TurnEvent1ANationActionPacket*>(packet);
    unsigned char tearingDown = g_pSimMgr->field44 == 2;
    if (tearingDown != 0) {
      for (int counterSlot = 0; counterSlot < 7; ++counterSlot) {
        TGreatPower* counterNation = g_apNationStates[counterSlot];
        if (counterNation != 0) {
          counterNation->diplomacyCounterA2 = nationAction->counterA2BySlot[counterSlot];
        }
      }
    }
    short sourceNation = nationAction->sourceNation1C;
    if (sourceNation != g_pSimMgr->GetActiveNationId()) {
      g_pUiRuntimeContext->DispatchDecisionSlot98(sourceNation, nationAction->param1E, 0, 0, 0);
      return 1;
    }
    unsigned char stillTearingDown = g_pSimMgr->field44 == 2;
    if (stillTearingDown == 0) {
      return 1;
    }
    g_pUiRuntimeContext->DispatchDecisionSlot98(sourceNation, nationAction->param1E,
                                                nationAction->param20, nationAction->param22, 0);
    break;
  }
  case 0x1b: {
    // Append one tracked-slot entry to the nation.
    TurnEvent1BTrackedEntryPacket* trackedEntry =
        static_cast<TurnEvent1BTrackedEntryPacket*>(packet);
    g_apNationStates[trackedEntry->nationSlot1C]->AppendTrackedSlotEntry(
        trackedEntry->trackedKind1E, trackedEntry->targetNation20, trackedEntry->trackedValue22,
        trackedEntry->trackedSlotIndex24, trackedEntry->trackedPayload28);
    break;
  }
  case 0x1c: {
    // Dispatch the proposal amount through the trade manager; a hosting session then
    // posts the 'NeXT' trade command.
    TurnEvent1CProposalAmountPacket* proposalAmount =
        static_cast<TurnEvent1CProposalAmountPacket*>(packet);
    g_pNationInteractionStateManager->DispatchProposalAmountSlot60(
        proposalAmount->ownerNation1C, proposalAmount->sourceContext1E, proposalAmount->amount24,
        proposalAmount->maxAmount20, proposalAmount->targetNation22,
        proposalAmount->emitEventFlag26, 1);
    unsigned char hosting1C = g_pSimMgr->field44 == 1;
    if (hosting1C == 0) {
      return 1;
    }
    TNextTradeCommand* tradeCommand = new TNextTradeCommand();
    tradeCommand->InitializeRangePairFromDiplomacyConstants();
    g_pGlobalUiRootController->DispatchUiSelectionToHandler(tradeCommand);
    break;
  }
  case 0x14: {
    // Add the amount to the terrain-slot nation's field-0x10 metric.
    TurnEvent14NationMetricPacket* metricDelta =
        static_cast<TurnEvent14NationMetricPacket*>(packet);
    g_apTerrainTypeDescriptorTable[metricDelta->nationSlot18]->AddToNationMetricAtField10(
        metricDelta->amount1C);
    break;
  }
  case 0x15: {
    // Receive side of EmitNationDiplomacyNeedStateSnapshotEvent15: copy the full
    // diplomacy need-state block into the great power.
    TurnEvent15Packet* needState = static_cast<TurnEvent15Packet*>(packet);
    TGreatPower* nation15 = g_apNationStates[needState->nationSlot];
    nation15->treasuryValue10 = needState->treasuryValue;
    nation15->grantTotalCost = needState->grantTotalCost;
    for (int needType = 0; needType < 0x17; ++needType) {
      nation15->needCurrentByType[needType] = needState->needCurrentByType[needType];
      nation15->needTargetByType[needType] = needState->needTargetByType[needType];
      nation15->relationDeltaCurrent[needType] = needState->relationDeltaCurrent[needType];
      nation15->relationDeltaSnapshot[needType] = needState->relationDeltaSnapshot[needType];
      nation15->diplomacyState1c6[needType] = needState->diplomacyState1c6[needType];
      for (int aidRow = 0; aidRow < 0x10; ++aidRow) {
        nation15->aidAllocationMatrix[aidRow * 0x17 + needType] =
            needState->aidAllocationMatrix[aidRow * 0x17 + needType];
      }
    }
    nation15->budgetPoolBase = needState->budgetPoolBase;
    nation15->budgetPoolDelta = needState->budgetPoolDelta;
    nation15->diplomacyBudgetBase = needState->diplomacyBudgetBase;
    nation15->escalationCounter = needState->escalationCounter;
    nation15->pendingCommitmentCost = needState->pendingCommitmentCost;
    nation15->pressureCounter = needState->pressureCounter;
    break;
  }
  case 0x19: {
    // Receive side of EmitTurnEvent19NationStateArraysForSlot.
    TurnEvent19Packet* stateArrays = static_cast<TurnEvent19Packet*>(packet);
    short nationSlot19 = stateArrays->nationSlot;
    if (nationSlot19 == g_pSimMgr->GetActiveNationId()) {
      return 1;
    }
    TGreatPower* nation19 = g_apNationStates[nationSlot19];
    nation19->needCapA6 = stateArrays->needCapA6;
    for (int orderType19 = 0; orderType19 < 0x0e; ++orderType19) {
      nation19->city->orderCountByType5c[orderType19] = stateArrays->orderCountByType[orderType19];
    }
    nation19->RecomputeDiplomacyAidBudgetScoreFromResourceWeights();
    for (int stockSlot19 = 0; stockSlot19 < 0x17; ++stockSlot19) {
      nation19->SetCityStockCounterAndRefresh(static_cast<short>(stockSlot19),
                                              stateArrays->externalStateByTarget[stockSlot19]);
    }
    nation19->ResetDiplomacyNeedScoresAndClearAidAllocationMatrix();
    for (int metricSlot19 = 0; metricSlot19 < 0x11; ++metricSlot19) {
      nation19->SetDiplomacyState1c6ClampedToCounterA4(static_cast<short>(metricSlot19),
                                                       stateArrays->metricBySlot7C[metricSlot19]);
    }
    nation19->SnapshotDiplomacyState1c6Into250();
    for (int target19 = 0; target19 < 0x17; ++target19) {
      nation19->diplomacyPolicyByNation[target19] = stateArrays->diplomacyPolicyByNation[target19];
      nation19->diplomacyGrantByNation[target19] = stateArrays->diplomacyGrantByNation[target19];
      nation19->needLevelByNation[target19] = stateArrays->needLevelByNation[target19];
    }
    break;
  }
  case 0x2c: {
    // Receive side of EmitTurnEvent2CNationStateCompositeForSlot.
    TurnEvent2CPacket* composite = static_cast<TurnEvent2CPacket*>(packet);
    int nationSlot2C = composite->nationSlot;
    if (nationSlot2C == g_pSimMgr->GetActiveNationId()) {
      return 1;
    }
    g_apNationStates[nationSlot2C]->field910 = composite->field910;
    g_apNationStates[nationSlot2C]->aidAllocationTotal = composite->aidAllocationTotal;
    TCity* city2C;
    if (g_apNationStates[nationSlot2C] == 0) {
      city2C = 0;
    } else {
      city2C = g_apNationStates[nationSlot2C]->city;
    }
    for (int metric0E = 0; metric0E < 0x1e; ++metric0E) {
      city2C->cityMetricsBlock0E[metric0E] = composite->cityMetricsBlock0E[metric0E];
    }
    for (int metric4A = 0; metric4A < 9; ++metric4A) {
      city2C->cityMetricsBlock4A[metric4A] = composite->cityMetricsBlock4A[metric4A];
    }
    for (int orderType2C = 0; orderType2C < 0x0e; ++orderType2C) {
      city2C->orderCountByType5c[orderType2C] = composite->orderCountByType[orderType2C];
    }
    g_apNationStates[nationSlot2C]->RecomputeDiplomacyAidBudgetScoreFromResourceWeights();
    city2C->field78 = composite->cityField78;
    city2C->fieldB4 = composite->cityFieldB4;
    short* stock2C = &city2C->cityStockCottonB6;
    for (int stockType = 0; stockType < 0x17; ++stockType) {
      stock2C[stockType] = composite->cityStock[stockType];
    }
    for (int orderSlot2C = 0; orderSlot2C < 0x10; ++orderSlot2C) {
      city2C->productionOrderTable1dc[orderSlot2C] = composite->productionOrderTable[orderSlot2C];
    }
    for (int accumSlot = 0; accumSlot < 0x10; ++accumSlot) {
      city2C->productionAccum1fc[accumSlot] = composite->productionAccum[accumSlot];
    }
    city2C->field26c = composite->cityField26C;
    // Second, duplicate copy of the city stock block - original behavior, kept as-is.
    for (int stockType2 = 0; stockType2 < 0x17; ++stockType2) {
      stock2C[stockType2] = composite->cityStock[stockType2];
    }
    for (int record2C = 0; record2C < 0x17; ++record2C) {
      TProductionOrder* order2C = city2C->tradeCommodityRecordPtrs[record2C];
      if (order2C != 0) {
        order2C->accumulatedValue = composite->orderAccumulatedValues[record2C];
      }
    }
    TPopulationMgr* summary2C = city2C->productionSummary1d8;
    summary2C->fieldAt8 = composite->popFieldAt8;
    summary2C->fieldAtC = composite->popFieldAtC;
    summary2C->stockLevel1c = composite->popStockLevel;
    summary2C->extraAt1e = composite->popExtraAt1e;
    summary2C->fieldAt20 = composite->popFieldAt20;
    summary2C->baselineSlots10->valueAt4 = composite->popBucketWords[0];
    summary2C->baselineSlots10->valueAt6 = composite->popBucketWords[1];
    summary2C->baselineSlots10->valueAt8 = composite->popBucketWords[2];
    summary2C->productionSlots14->valueAt4 = composite->popBucketWords[3];
    summary2C->productionSlots14->valueAt6 = composite->popBucketWords[4];
    summary2C->productionSlots14->valueAt8 = composite->popBucketWords[5];
    summary2C->pendingDeltaSlots18->valueAt4 = composite->popBucketWords[6];
    summary2C->pendingDeltaSlots18->valueAt6 = composite->popBucketWords[7];
    summary2C->pendingDeltaSlots18->valueAt8 = composite->popBucketWords[8];
    break;
  }
  case 0x2d: {
    // Minor-nation need snapshot.
    TurnEvent2DMinorNeedPacketM* minorNeed = static_cast<TurnEvent2DMinorNeedPacketM*>(packet);
    TMinor* minor2D = g_apSecondaryNationStateSlots[minorNeed->nationSlot];
    for (int needSlot2D = 0; needSlot2D < 0x17; ++needSlot2D) {
      minor2D->needLevelByNation[needSlot2D] = minorNeed->needLevelByNation[needSlot2D];
    }
    break;
  }
  case 0x16: {
    // Queue a diplomacy proposal code on the addressed nation.
    TurnEvent16DiplomacyProposalPacket* proposal =
        static_cast<TurnEvent16DiplomacyProposalPacket*>(packet);
    g_apNationStates[proposal->nationSlot18]->QueueDiplomacyProposalCodeForTargetNation(
        proposal->proposalCode1A, proposal->targetNationId1C);
    break;
  }
  case 0x17: {
    // Resolve a pending diplomacy proposal.
    TurnEvent17ProposalResolutionPacket* resolution =
        static_cast<TurnEvent17ProposalResolutionPacket*>(packet);
    if (resolution->acceptedFlag1A != 0) {
      g_apNationStates[resolution->nationSlot18]->ApplyAcceptedDiplomacyProposalCode(
          resolution->proposalIndex1C);
    } else {
      g_apNationStates[resolution->nationSlot18]->QueueInterNationEventForProposalCode12D_130(
          resolution->proposalIndex1C);
    }
    break;
  }
  case 0x18: {
    // Host broadcast of all seven great powers' diplomacy arrays.
    TurnEvent18DiplomacyArraysPacketM* arrays =
        static_cast<TurnEvent18DiplomacyArraysPacketM*>(packet);
    for (int arraySlot = 0; arraySlot < 7; ++arraySlot) {
      TGreatPower* arrayNation = g_apNationStates[arraySlot];
      if (arrayNation != 0) {
        for (int arrayTarget = 0; arrayTarget < 0x17; ++arrayTarget) {
          arrayNation->diplomacyPolicyByNation[arrayTarget] =
              arrays->diplomacyPolicyByNation[arraySlot][arrayTarget];
          arrayNation->diplomacyGrantByNation[arrayTarget] =
              arrays->diplomacyGrantByNation[arraySlot][arrayTarget];
          arrayNation->needLevelByNation[arrayTarget] =
              arrays->needLevelByNation[arraySlot][arrayTarget];
        }
      }
    }
    break;
  }
  case 0x28:
  case 0x2e:
  case 0x2f:
  case 0x30:
  case 0x31:
  case 0x32: {
    // Streamed-payload family: copy the raw packet into a global-memory block, wrap it
    // in a THandleStream, and hand it to the code-switched stream reader. The
    // save-format version global is stamped 'netX' for the deserialization.
    g_nSaveFormatVersion = 0x6e657458; // 'netX'
    int packetBytes = packet->messageLength;
    HGLOBAL packetMemory = GlobalAlloc(GMEM_MOVEABLE, packetBytes);
    void* streamBuffer = GlobalLock(packetMemory);
    memmove(streamBuffer, packet, packetBytes);
    GlobalUnlock(packetMemory);
    THandleStream* reader = new THandleStream();
    reader->AttachGlobalMemoryHandleAndResetPosition(packetMemory, 0x10);
    HandleTurnEventCodes28_2E_2F_30_31_32(reader);
    reader->Free();
    g_nSaveFormatVersion = -1;
    break;
  }
  case 0x1f: {
    // Session/game-flow four-cc status dispatcher.
    TurnEvent1FGameStateTagPacket* gameState =
        reinterpret_cast<TurnEvent1FGameStateTagPacket*>(packet);
    switch (gameState->statusTag18) {
    case 0x61626469: { // 'abdi' - nation abdicated: notice; host replaces the slot with an AI
      CString templateTextAbdi;
      CString formattedAbdi;
      CString nationNameAbdi;
      g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&templateTextAbdi, 0x2737,
                                                                      0x32);
      g_apTerrainTypeDescriptorTable[gameState->value1C]->FormatOverlayTerrainLabelText(
          &nationNameAbdi);
      scanBracketExpressions(g_pSimMgr, &formattedAbdi, static_cast<const char*>(templateTextAbdi),
                             static_cast<const char*>(nationNameAbdi));
      g_pUiRuntimeContext->CreateModalMessageCommandAndQueue(&formattedAbdi, 0);
      unsigned char hostingAbdi = g_pSimMgr->field44 == 1;
      if (hostingAbdi != 0) {
        ReplaceNationStateForSlotAndRefreshStatus(gameState->value1C);
      }
      return 1;
    }
    case 0x61636564: { // 'aced' - accession notice; the affected local player posts 'gwen'
      unsigned char isLocalNationAced = g_pSimMgr->GetActiveNationId() == gameState->value1C;
      CString templateTextAced;
      CString formattedAced;
      CString nationNameAced;
      g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(
          &templateTextAced, 0x2742, isLocalNationAced != 0 ? 0x23 : 0x1c);
      g_apTerrainTypeDescriptorTable[gameState->value1C]->FormatOverlayTerrainLabelText(
          &nationNameAced);
      scanBracketExpressions(g_pSimMgr, &formattedAced, static_cast<const char*>(templateTextAced),
                             static_cast<const char*>(nationNameAced));
      g_pUiRuntimeContext->CreateModalMessageCommandAndQueue(&formattedAced, 0);
      if (isLocalNationAced != 0) {
        g_pGlobalUiRootController->CreateAndQueueTurnEventPacketTagGWEN();
      }
      return 1;
    }
    case 0x75686564: // 'uhed' - nation left unheaded: replace with AI locally
      ReplaceNationStateForSlotAndRefreshStatus(gameState->value1C);
      return 1;
    case 0x6367616d: { // 'cgam' - cancel game
      TCancelGameOptionsCommand* cancelCommandCgam = new TCancelGameOptionsCommand();
      cancelCommandCgam->InitializeRangePair(0x63676f70 /* 'cgop' */, g_pGlobalUiRootController, 0,
                                             0, 0);
      g_pGlobalUiRootController->DispatchUiSelectionToHandler(cancelCommandCgam);
      CString messageCgam;
      g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&messageCgam, 0x2742, 0x27);
      g_pUiRuntimeContext->CreateModalMessageCommandAndQueue(&messageCgam, 0);
      return 1;
    }
    case 0x6c6f7365: // 'lose' - the named nation lost
      g_apNationStates[gameState->value1C]->HandleNationLost();
      return 1;
    case 0x666f6666: { // 'foff' - seat refused: show string[value1C], post the cancel command
      CString messageFoff;
      g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&messageFoff, 0x2742,
                                                                      gameState->value1C);
      g_pUiRuntimeContext->CreateModalMessageCommandAndQueue(&messageFoff, 0);
      TCancelGameOptionsCommand* cancelCommandFoff = new TCancelGameOptionsCommand();
      cancelCommandFoff->InitializeRangePair(0x63676f70 /* 'cgop' */, g_pGlobalUiRootController, 0,
                                             0, 0);
      g_pGlobalUiRootController->DispatchUiSelectionToHandler(cancelCommandFoff);
      return 1;
    }
    case 0x6e616d65: // 'name' - refresh the status board row (global manager receiver)
      g_pGameFlowState->RefreshNationStatusLabelsAndCodesForSlotOrAll(gameState->value1C);
      return 1;
    case 0x6c6f7374: { // 'lost' - connection to a nation lost
      int lostCode = gameState->value1C;
      unsigned char droppedFlag = (lostCode & 0xff00) != 0;
      int lostNationSlot = lostCode & 0xff;
      unsigned char isLocalNationLost = lostNationSlot == g_pSimMgr->GetActiveNationId();
      CString templateTextLost;
      CString formattedLost;
      CString nationNameLost;
      g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(
          &templateTextLost, 0x2742,
          (droppedFlag != 0 ? 2 : 0) + (isLocalNationLost != 0 ? 1 : 0) + 0x1f);
      g_apTerrainTypeDescriptorTable[lostNationSlot]->FormatOverlayTerrainLabelText(
          &nationNameLost);
      scanBracketExpressions(g_pSimMgr, &formattedLost, static_cast<const char*>(templateTextLost),
                             static_cast<const char*>(nationNameLost));
      g_pUiRuntimeContext->CreateModalMessageCommandAndQueue(&formattedLost, 0);
      if (isLocalNationLost != 0) {
        unsigned char sessionTornDownLost = g_pSimMgr->field44 == 2;
        if (sessionTornDownLost != 0) {
          g_pGlobalUiRootController->CreateAndQueueTurnEventPacketTagGWEN();
        }
      }
      return 1;
    }
    case 0x71756974:   // 'quit'
    case 0x6e657767: { // 'newg' - session ending: optional notice, then close or restart
      unsigned char restartFlag = static_cast<unsigned char>(gameState->value1C);
      unsigned char sessionTornDownQuit = g_pSimMgr->field44 == 2;
      if (sessionTornDownQuit != 0) {
        CString messageQuit;
        if (restartFlag != 0) {
          g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&messageQuit, 0x2742,
                                                                          0x1d);
        } else {
          g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&messageQuit, 0x2742,
                                                                          0x1e);
        }
        g_pUiRuntimeContext->CreateModalMessageCommandAndQueue(&messageQuit, 0);
      }
      unsigned char stillTornDownQuit = g_pSimMgr->field44 == 2;
      if (stillTornDownQuit == 0 && gameState->statusTag18 != 0x6e657767 /* 'newg' */) {
        PostWmCloseToMainThreadWindow();
        return 1;
      }
      g_pGlobalUiRootController->CreateAndQueueTurnEventPacketTagGWEN();
      return 1;
    }
    case 0x72656765: { // 'rege' - regenerate map clip regions after teardown
      unsigned char sessionTornDownRege = g_pSimMgr->field44 == 2;
      if (sessionTornDownRege != 0) {
        g_pStrategicMapViewSystem->RebuildNationClipRegionsAndDispatchMapEvent();
      }
      return 1;
    }
    case 0x7265706f: { // 'repo' - a session reports for a nation slot: seat it or refuse
      int repoSlot = gameState->value1C & 7;
      unsigned char hostCanSeatEmptySlot = 0;
      if (g_apNationStates[repoSlot] == 0 && packet->fromNetworkId == GetSessionActiveNationId() &&
          g_pSimMgr->field44 == 1) {
        hostCanSeatEmptySlot = 1;
      }
      if (repoSlot >= 0 && repoSlot < 7 &&
          (hostCanSeatEmptySlot != 0 ||
           (g_apNationStates[repoSlot] != 0 &&
            (packet->fromNetworkId == GetSessionActiveNationId() ||
             g_apNationStates[repoSlot]->ShouldDispatchImmediatelySlot28() != 0)))) {
        LobbyChatEvent9Packet seatAnnounce;
        seatAnnounce.messageTag = 0x74696d65; // 'time'
        seatAnnounce.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
        seatAnnounce.eventCode = 0;
        seatAnnounce.field1C = packet->fromNetworkId;
        seatAnnounce.fromNetworkId = 0;
        seatAnnounce.eventCode = 9;
        seatAnnounce.toNetworkId = 0;
        seatAnnounce.messageLength = 0;
        seatAnnounce.toNetworkId = 0;
        seatAnnounce.messageLength = 0x64;
        seatAnnounce.nationSlot18 = static_cast<unsigned char>(repoSlot);
        strcpy(seatAnnounce.senderName, defaultNationTextSlots[repoSlot]);
        strcpy(seatAnnounce.messageText, nationDisplayNameSlots[repoSlot]);
        g_pNetMgr006a6014->Send(&seatAnnounce, 1);
        CString formattedRepo;
        CString templateTextRepo;
        g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&templateTextRepo, 0x2759,
                                                                        0xa);
        CString nationNameRepo(defaultNationTextSlots[repoSlot]);
        scanBracketExpressions(g_pSimMgr, &formattedRepo,
                               static_cast<const char*>(templateTextRepo),
                               static_cast<const char*>(nationNameRepo));
        TurnEventCKickMessagePacket joinBroadcast;
        joinBroadcast.messageTag = 0x74696d65; // 'time'
        joinBroadcast.eventCode = 0;
        joinBroadcast.fromNetworkId = 0;
        joinBroadcast.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
        joinBroadcast.toNetworkId = 0;
        joinBroadcast.eventCode = 0xc;
        joinBroadcast.messageLength = 0;
        joinBroadcast.messageLength = 0x11c;
        joinBroadcast.targetNationBitmask118 = 0xff;
        joinBroadcast.kickerNationId119 = static_cast<signed char>(g_pSimMgr->GetActiveNationId());
        strcpy(joinBroadcast.messageText18, formattedRepo);
        joinBroadcast.eventCode = 0xc;
        joinBroadcast.kickerNationId119 = -1; // double-write over the active id - original
        joinBroadcast.toNetworkId = 0;
        joinBroadcast.targetNationBitmask118 = static_cast<unsigned char>(0xff - (1 << repoSlot));
        g_pNetMgr006a6014->Send(&joinBroadcast, 1);
      } else {
        TurnEvent1FGameStateTagPacket refuse;
        refuse.messageTag = 0x74696d65; // 'time'
        refuse.eventCode = 0;
        refuse.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
        refuse.fromNetworkId = 0;
        refuse.toNetworkId = 0;
        refuse.eventCode = 0x1f;
        refuse.messageLength = 0;
        refuse.messageLength = 0x20;
        refuse.toNetworkId = packet->fromNetworkId;
        refuse.statusTag18 = 0x666f6666; // 'foff'
        refuse.value1C = 0x29;
        g_pNetMgr006a6014->Send(&refuse, 0);
      }
      return 1;
    }
    case 0x73617665: // 'save' - latch the save flag and save with the network label
      fieldF4 = static_cast<unsigned char>(gameState->value1C);
      SaveGameWithModeAndOptionalLabel(queueSyncDword, (char*)g_pszClientSavePrefix_0065BF5C);
      return 1;
    case 0x74726164: { // 'trad' - reset diplomacy level: packed (nationSlot << 16 | level)
      int tradeCode = gameState->value1C;
      g_apNationStates[g_pSimMgr->GetActiveNationId()]->ResetDiplomacyLevelForNationSlot12(
          static_cast<short>(static_cast<unsigned int>(tradeCode) >> 0x10),
          static_cast<short>(tradeCode));
      return 1;
    }
    case 0x74726173: // 'tras' - rebuild + discard the transport-influence map
      g_apNationStates[g_pSimMgr->GetActiveNationId()]->BuildTransportLinkedInfluenceMap(0);
      return 1;
    default:
      return 1;
    }
  }
  case 0x23: { // patch selected fields of one map tile's terrain-state record
    TurnEvent23TileStatePacketM* tileState = static_cast<TurnEvent23TileStatePacketM*>(packet);
    TTerrainStateRecordView* tile = &g_pGlobalMapState->terrainStateTable[tileState->tileIndex];
    tile->ownerNationTag04 = tileState->record.ownerNationTag04;
    tile->regionSubtypeTag05 = tileState->record.regionSubtypeTag05;
    tile->adjacencyBits06 = tileState->record.adjacencyBits06;
    tile->developmentClassNibbles0c = tileState->record.developmentClassNibbles0c;
    tile->pendingDevelopmentFlag0d = (unsigned char)(tile->pendingDevelopmentFlag0d |
                                                     tileState->record.pendingDevelopmentFlag0d);
    tile->secondaryOwnerNationTag18 = tileState->record.secondaryOwnerNationTag18;
    tile->activeFlags1c = tileState->record.activeFlags1c;
    break;
  }
  case 0x24: { // patch selected fields of one city-score record
    TurnEvent24CityRecordPacket* cityRecord = static_cast<TurnEvent24CityRecordPacket*>(packet);
    TGlobalMapCityScoreRecord* city24 =
        &g_pGlobalMapState->cityScoreTable[cityRecord->cityRecordIndex];
    city24->ownerNationCode00 = cityRecord->record.ownerNationCode00;
    city24->developmentStage = cityRecord->record.developmentStage;
    city24->fortLevel03 = cityRecord->record.fortLevel03;
    city24->lastTurnTick = cityRecord->record.lastTurnTick;
    {
      // 10-short copy 0x82..0x95 (explicit word loop in the original, not rep movs).
      short* cityWordCursor = &city24->resourceDevelopmentCounts82[0];
      short* recordWordCursor = cityRecord->record.resourceDevelopmentCounts82;
      int wordCountdown = 10;
      do {
        *cityWordCursor = *recordWordCursor;
        ++recordWordCursor;
        ++cityWordCursor;
        --wordCountdown;
      } while (wordCountdown != 0);
    }
    city24->exploredByNationMaskA1 = cityRecord->record.exploredByNationMaskA1;
    city24->resourcePresenceMaskA2 = cityRecord->record.resourcePresenceMaskA2;
    break;
  }
  case 0x25: { // merge nation status tags; ding when exactly one nation stays busy
    NationStatusEvent25Packet* statusBoard = static_cast<NationStatusEvent25Packet*>(packet);
    int readyCount = 0;
    int busyCount = 0;
    {
      int* incomingTagCursor = statusBoard->statusTags;
      int* ownTagCursor = nationStatusTags;
      int tagCountdown = 7;
      do {
        if (*incomingTagCursor != 0x756e6b6e /* 'unkn' */) {
          *ownTagCursor = *incomingTagCursor;
        }
        if (*ownTagCursor == 0x72656479 /* 'redy' */) {
          ++readyCount;
        } else if (*ownTagCursor == 0x62757379 /* 'busy' */) {
          ++busyCount;
        }
        ++incomingTagCursor;
        ++ownTagCursor;
        --tagCountdown;
      } while (tagCountdown != 0);
    }
    if (0 < readyCount && busyCount == 1) {
      int busySlot = g_pSimMgr->GetActiveNationId();
      if (busySlot == -1) {
        int sessionId25 = GetSessionActiveNationId();
        int* sessionCursor25 = g_pGameFlowState->nationSessionIds;
        busySlot = 0;
        do {
          if (*sessionCursor25 == sessionId25) {
            break;
          }
          ++busySlot;
          ++sessionCursor25;
        } while (busySlot < 7);
        if (busySlot == 7) {
          busySlot = -1; // a -1 here indexes nationStatusTags[-1] below - original
                         // out-of-bounds behavior, kept as-is
        }
      }
      if (nationStatusTags[busySlot] == 0x62757379 /* 'busy' */ && fieldF4 != 0) {
        g_pSfxPlaybackSystem->PlaySoundEffect(0x13f2, 0, 1);
      }
    }
    break;
  }
  case 0x26: { // bulk-load the diplomacy matrices into g_pDiplomacyTurnStateManager
    TurnEvent26DiplomacyMatrixPacket* matrix =
        static_cast<TurnEvent26DiplomacyMatrixPacket*>(packet);
    memcpy(g_pDiplomacyTurnStateManager->relationCodeMatrix04, matrix->relationCodeMatrix,
           sizeof(g_pDiplomacyTurnStateManager->relationCodeMatrix04));
    memcpy(g_pDiplomacyTurnStateManager->pendingPolicyCodeMatrix304,
           matrix->pendingPolicyCodeMatrix,
           sizeof(g_pDiplomacyTurnStateManager->pendingPolicyCodeMatrix304));
    memcpy(g_pDiplomacyTurnStateManager->pendingPolicyTierMatrix484,
           matrix->pendingPolicyTierMatrix,
           sizeof(g_pDiplomacyTurnStateManager->pendingPolicyTierMatrix484));
    // The original copies each pair with a single 32-bit register move.
    *reinterpret_cast<int*>(&g_pDiplomacyTurnStateManager->selectedSourceNationSlot784) =
        *reinterpret_cast<int*>(&matrix->selectedSourceNationSlot);
    *reinterpret_cast<int*>(&g_pDiplomacyTurnStateManager->selectionFlagsA788) =
        *reinterpret_cast<int*>(&matrix->selectionFlagsA);
    g_pDiplomacyTurnStateManager->selectionFlagsC78c = matrix->selectionFlagsC;
    memcpy(g_pDiplomacyTurnStateManager->comparativePowerRows1824, matrix->relationTailBlock,
           sizeof(matrix->relationTailBlock));
    break;
  }
  case 0x27: { // dispatch join-empire mode on one terrain-slot nation
    TurnEvent27JoinEmpirePacket* joinEmpire = static_cast<TurnEvent27JoinEmpirePacket*>(packet);
    g_apTerrainTypeDescriptorTable[joinEmpire->terrainSlot18]->ApplyJoinEmpireModeForTargetNation(
        joinEmpire->targetNationSlot1C, joinEmpire->mode20);
    break;
  }
  case 0x29: { // route a tagged tactical command to the live battle
    TacticalCommandPacket* tactical = static_cast<TacticalCommandPacket*>(packet);
    TTacticalBattle* battle = g_pActiveTacticalBattle;
    battle->AssertValid();
    TArmyTacUnit* unit = battle->SeekLinkedListCursorByNestedId(tactical->unitId1C);
    switch (tactical->commandTag18) {
    case 0x6465706c: // 'depl'
      battle->HandleTacticalCommandTag_depl(unit, tactical->arg20, 1);
      return 1;
    case 0x64696767: // 'digg'
      battle->HandleTacticalCommandTag_digg(unit, tactical->arg20, 1);
      return 1;
    case 0x6d696e65: // 'mine' - the resolved unit cursor is NOT passed here
      battle->HandleTacticalCommandTag_mine(tactical->arg20, tactical->arg24, 1);
      return 1;
    case 0x6d6f7665: // 'move'
      battle->MoveTacticalUnitBetweenTiles(unit, tactical->arg20, tactical->arg24, 1);
      return 1;
    case 0x72616c79: // 'raly'
      battle->HandleTacticalCommandTag_raly(unit, tactical->arg20, tactical->arg24, 1);
      return 1;
    case 0x73656c65: // 'sele'
      battle->SetCurrentTacticalUnitSelection(unit, 1);
      return 1;
    default:
      return 1;
    }
  }
  case 0x2a: { // resolve a 'fire' action between two units of the live battle
    TacticalCommandPacket* fireCommand = static_cast<TacticalCommandPacket*>(packet);
    TTacticalBattle* fireBattle = g_pActiveTacticalBattle;
    fireBattle->AssertValid();
    TArmyTacUnit* attacker = fireBattle->SeekLinkedListCursorByNestedId(fireCommand->unitId1C);
    TArmyTacUnit* target = fireBattle->SeekLinkedListCursorByNestedId(fireCommand->arg20);
    if (fireCommand->commandTag18 != 0x66697265 /* 'fire' */) {
      return 1;
    }
    fireBattle->ApplyTacticalActionEffectsAndMaybeRemoveUnit(
        attacker, target, target->tileIndex8, fireCommand->arg24, fireCommand->arg28,
        static_cast<char>(fireCommand->arg2C), 1);
    break;
  }
  case 0x2b: { // accumulate the presence mask; optionally echo a 0x2b ack
    TurnEvent2BPresenceMaskPacket* presence = static_cast<TurnEvent2BPresenceMaskPacket*>(packet);
    g_nTurnEvent2BNationMaskAccumulator =
        g_nTurnEvent2BNationMaskAccumulator | presence->nationMask19;
    if (presence->replyRequestFlag18 != 0) {
      TurnEvent2BPresenceMaskPacket reply;
      // Inline header stamp (tag + nation), NOT the 0x5438e0 helper - keep the exact
      // interleaved store order, including both double-writes below.
      reply.messageTag = 0x74696d65; // 'time'
      reply.activeNationId = (unsigned char)g_pSimMgr->GetActiveNationId();
      reply.eventCode = 0;
      reply.eventCode = 0x2b;
      reply.fromNetworkId = 0;
      reply.toNetworkId = 0;
      reply.messageLength = 0;
      reply.replyRequestFlag18 = 0;
      reply.messageLength = 0x1c;
      reply.nationMask19 = (signed char)g_pSimMgr->GetActiveNationId();
      reply.toNetworkId = presence->fromNetworkId;
      g_pNetMgr006a6014->Send(&reply, 0);
    }
    break;
  }
  default:
    return 0;
  }
  return 1;
}

struct TurnEvent11Packet : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char flagByte;
  short pad16; // alignment gap before mapOffsetSelector
  int mapOffsetSelector;
  int mapOffset;
  short shortA;
  short shortB;
  unsigned char pad24[4]; // original frame/messageLength is 0x28
};

// FUNCTION: IMPERIALISM 0x00549280
void TMultiplayerMgr::AppendNodeToTurnEventLinkedListAt6C(int node) {
  *reinterpret_cast<int*>(node + 0x10) = 0;
  int* tail = &primaryTurnEventQueueHead;
  for (int n = primaryTurnEventQueueHead; n != 0; n = *reinterpret_cast<int*>(n + 0x10)) {
    tail = reinterpret_cast<int*>(n + 0x10);
  }
  *tail = node;
}

// FUNCTION: IMPERIALISM 0x005493c0
void TMultiplayerMgr::CreateAndSendTurnEvent11_MapOffsetAndFlags(unsigned char flagByte,
                                                                 int mapOffsetSelector,
                                                                 int absoluteOffset, short shortA,
                                                                 short shortB) {
  TurnEvent11Packet packet;
  packet.eventCode = 0x11;
  packet.fromNetworkId = 0;
  packet.toNetworkId = (g_pSimMgr->field44 == 1) ? 0 : -1;
  packet.messageLength = 0x28;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.flagByte = flagByte;
  packet.mapOffsetSelector = mapOffsetSelector;
  int base = 0;
  if (mapOffsetSelector == 0) {
    base = reinterpret_cast<int>(g_pGlobalMapState->terrainStateTable);
  } else if (mapOffsetSelector == 1) {
    base = reinterpret_cast<int>(g_pGlobalMapState->cityScoreTable);
  }
  packet.mapOffset = absoluteOffset - base;
  packet.shortA = shortA;
  packet.shortB = shortB;
  g_pNetMgr006a6014->Send(&packet, 0);
}

// FUNCTION: IMPERIALISM 0x005494b0
void TMultiplayerMgr::CreateAndSendTurnEvent12_TwoShorts(short shortA, short shortB) {
  TurnEvent12Packet packet;
  packet.eventCode = 0x12;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x1c;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.shortA = shortA;
  packet.shortB = shortB;
  g_pNetMgr006a6014->Send(&packet, 0);
}

struct TurnEvent13Packet : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15;
  short nationSlot;
  int payloadDwords[9];
  unsigned char pad3C[4]; // original frame/messageLength is 0x40
};

// FUNCTION: IMPERIALISM 0x00549540
void TMultiplayerMgr::CreateAndSendTurnEvent13_NationAndNineDwords(int nationSlot,
                                                                   int* payloadDwords) {
  TurnEvent13Packet packet;
  packet.eventCode = 0x13;
  packet.fromNetworkId = 0;
  packet.toNetworkId = g_pGameFlowState->nationSessionIds[nationSlot];
  packet.messageLength = 0x40;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.nationSlot = static_cast<short>(nationSlot);
  for (int dwordIndex = 0; dwordIndex < 9; ++dwordIndex) {
    packet.payloadDwords[dwordIndex] = payloadDwords[dwordIndex];
  }
  g_pNetMgr006a6014->Send(&packet, 0);
}

struct TurnEvent20Packet : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15[3];
  short eventParam18;
  unsigned char byteA;
  unsigned char byteB;
};

// FUNCTION: IMPERIALISM 0x005495e0
void TMultiplayerMgr::CreateAndSendTurnEvent20_ShortAndTwoBytes(short eventParam,
                                                                unsigned char byteA,
                                                                unsigned char byteB) {
  TurnEvent20Packet packet;
  packet.eventCode = 0x20;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x1c;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventParam18 = eventParam;
  packet.byteA = byteA;
  packet.byteB = byteB;
  g_pNetMgr006a6014->Send(&packet, 1);
}

struct TurnEvent21Packet : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char byte0;
  unsigned char byte1;
  unsigned char byte2;
  unsigned char pad18[4]; // original frame/messageLength is 0x1c
};

// FUNCTION: IMPERIALISM 0x00549680
void TMultiplayerMgr::CreateAndSendTurnEvent21_ThreeBytes(unsigned char byte0, unsigned char byte1,
                                                          unsigned char byte2) {
  TurnEvent21Packet packet;
  packet.eventCode = 0x21;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x1c;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.byte0 = byte0;
  packet.byte1 = byte1;
  packet.byte2 = byte2;
  g_pNetMgr006a6014->Send(&packet, 1);
}

struct TurnEvent22Packet : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15[3];
  unsigned char byteVal;
  unsigned char pad19;
  short shortVal;
};

// FUNCTION: IMPERIALISM 0x00549720
void TMultiplayerMgr::CreateAndSendTurnEvent22_ByteAndShort(unsigned char byteVal, short shortVal) {
  TurnEvent22Packet packet;
  packet.eventCode = 0x22;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x1c;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.byteVal = byteVal;
  packet.shortVal = shortVal;
  g_pNetMgr006a6014->Send(&packet, 1);
}

struct TurnEvent1APacket : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15;
  short uiTurnToken;
  short field18;
  short field1a;
  short field1c;
  short field1e;
  short field20;
  short field22;
  short nationCapabilityFlags[7];
};

// FUNCTION: IMPERIALISM 0x005497b0
void TMultiplayerMgr::DispatchTurnEvent1AWithNationActionPayload(short param0, short param1,
                                                                 short param2, short param3,
                                                                 short param4) {
  TurnEvent1APacket packet;
  packet.eventCode = 0x1a;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x34;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.uiTurnToken = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
  packet.field18 = param0;
  packet.field1a = 0;
  packet.field1c = param1;
  packet.field1e = param2;
  packet.field20 = param3;
  packet.field22 = param4;
  for (int nationIndex = 0; nationIndex < 7; ++nationIndex) {
    TGreatPower* nationState = g_apNationStates[nationIndex];
    if (nationState != 0) {
      packet.nationCapabilityFlags[nationIndex] =
          nationState->ReturnFalseNationStateCapabilityFlag90(0);
    } else {
      packet.nationCapabilityFlags[nationIndex] = 0;
    }
  }
  g_pNetMgr006a6014->Send(&packet, 1);
}

struct TurnEvent1CPacket : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15[3];
  short pendingNationSlotIndexLow;
  short shortA;
  short shortB;
  // Ground truth stores shortD/shortE before shortC (declaration order matches the
  // original's field offsets, not the parameter order).
  short shortD;
  short shortE;
  short shortC;
  short shortF;
};

// FUNCTION: IMPERIALISM 0x005499b0
void TMultiplayerMgr::CreateAndSendTurnEvent1C_BoolAndSixShorts(bool broadcastFlag, short shortA,
                                                                short shortB, short shortC,
                                                                short shortD, short shortE,
                                                                short shortF) {
  TurnEvent1CPacket packet;
  packet.eventCode = 0x1c;
  packet.fromNetworkId = 0;
  packet.toNetworkId = broadcastFlag ? -1 : 0;
  packet.messageLength = 0x28;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.pendingNationSlotIndexLow = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
  packet.shortA = shortA;
  packet.shortB = shortB;
  packet.shortD = shortD;
  packet.shortE = shortE;
  packet.shortC = shortC;
  packet.shortF = shortF;
  g_pNetMgr006a6014->Send(&packet, 0);
}

// FUNCTION: IMPERIALISM 0x00549ad0
void TMultiplayerMgr::DispatchTurnEventPacketWithCodeAndPayloadBuffer(short eventTag,
                                                                      short destinationSlot,
                                                                      void* payload) {
  TCountingStream* counter = new TCountingStream();
  counter->PrepareForUse();
  SerializeOrderDataIntoTurnEventByTag(counter, eventTag, destinationSlot, payload);
  int packetBytes = counter->streamSlot28();
  counter->Free();
  HGLOBAL packetMemory = GlobalAlloc(GMEM_MOVEABLE, packetBytes);
  THandleStream* writer = new THandleStream();
  writer->AttachGlobalMemoryHandleAndResetPosition(packetMemory, 0x10);
  SerializeOrderDataIntoTurnEventByTag(writer, eventTag, destinationSlot, payload);
  NetMessage* packet = static_cast<NetMessage*>(GlobalLock(packetMemory));
  packet->messageLength = writer->streamSlot28();
  writer->Free();
  g_pNetMgr006a6014->Send(packet, destinationSlot == -3);
  GlobalFree(packetMemory);
}

// FUNCTION: IMPERIALISM 0x00549c60
void TMultiplayerMgr::SerializeOrderDataIntoTurnEventByTag(TStream* stream, short eventTag,
                                                           short destinationSlot, void* payload) {
  TimelyNetMessagePrefix header;
  header.messageTag = 0x74696d65;
  header.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  int tag = eventTag;
  header.eventCode = 0;
  header.fromNetworkId = 0;
  header.messageLength = 0x1c;
  header.eventCode = tag;
  int dest = destinationSlot;
  header.uiTurnToken = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
  if (dest == -2 || dest == -3) {
    header.toNetworkId = 0;
  } else if (dest == -1) {
    header.toNetworkId = -1;
  } else {
    header.toNetworkId = g_pGameFlowState->nationSessionIds[dest];
  }
  stream->WriteBytesSlot78(&header, 0x1c);
  switch (tag) {
  case 0x28:
    static_cast<TObject*>(payload)->WriteTo(stream);
    return;
  case 0x2e:
    g_pNavyOrderManager->SerializeNavyOrderListsByNation(
        stream, static_cast<short>(reinterpret_cast<int>(payload)));
    return;
  case 0x2f:
    PublishTerrainDescriptorAndNotifyOrderListeners(stream, reinterpret_cast<int>(payload));
    return;
  case 0x30:
    PublishNationDescriptorAndNotifyOrderListeners(stream, reinterpret_cast<int>(payload));
    return;
  case 0x31: {
    TaggedSerializablePayload* record = static_cast<TaggedSerializablePayload*>(payload);
    stream->streamSlot8c(record->tag);
    if (record->tag != 0x73746172) { // 'star'
      record->object->WriteTo(stream);
      return;
    }
    StarOrderObjectView* view = reinterpret_cast<StarOrderObjectView*>(record->object);
    record->object->AssertValid();
    stream->streamSlot8c(view->subTag);
    if (view->subTag == 0x6c616e64) { // 'land'
      record->object->AssertValid();
      stream->WriteCountSlot88(view->word8);
      stream->WriteCountSlot88(view->wordA);
      return;
    }
  } break;
  case 0x32:
    g_pNationInteractionStateManager->WriteTo(stream);
  }
}

struct TaggedGameStateTurnEventPacket : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15[3];
  int resolvedNationId;
  int tagParam;
  int valueParam;
};

// FUNCTION: IMPERIALISM 0x0054a340
void TMultiplayerMgr::DispatchTaggedGameStateEvent1F20(int packetTag, int param2,
                                                       int nationSlotOrMode) {
  TaggedGameStateTurnEventPacket packet;
  packet.eventCode = 0x1f;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x20;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.tagParam = packetTag;
  packet.valueParam = param2;
  if ((nationSlotOrMode == -2) || (nationSlotOrMode == -3)) {
    packet.resolvedNationId = 0;
  } else if (nationSlotOrMode == -1) {
    packet.resolvedNationId = -1;
  } else {
    packet.resolvedNationId = g_pGameFlowState->nationSessionIds[nationSlotOrMode];
  }
  g_pNetMgr006a6014->Send(&packet, nationSlotOrMode == -3 ? 1 : 0);
}

#pragma pack(push, 1)
struct CityRedrawInvalidateTurnEventPacket : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15;
  short uiTurnToken;
  short cityId;
  unsigned char cityHeader00[4];
  short cityWord04;
  short cityWord06;
  unsigned char cityByte08;
  short adjacentRegionIds0A[12];
  short adjacentRegionIds22[12];
  unsigned char cityBytes3A[3];
  short cityWord3E;
  short cityWord40;
  short linkedRegionIds42[32];
  short linkedRegionIds82[10];
  TMilitaryUnit* stationedUnitChain98;
  int cityScoreValue9C;
  unsigned char cityBytesA0[4];
  CString cityNameA4;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct TileRedrawInvalidateTurnEventPacket : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15;
  short uiTurnToken;
  short tileIndex;
  TTerrainStateRecordView tileSnapshot;
};
#pragma pack(pop)

// FUNCTION: IMPERIALISM 0x0054a500
void TMultiplayerMgr::PublishTerrainDescriptorAndNotifyOrderListeners(TStream* stream,
                                                                      int terrainSlot) {
  stream->streamSlot7c(static_cast<unsigned char>(terrainSlot + 'a'));
  TCountry* descriptor = g_apTerrainTypeDescriptorTable[terrainSlot];
  if (descriptor == 0) {
    stream->WriteCountSlot88(0);
  } else {
    stream->WriteCountSlot88(descriptor->militaryUnitList44->GetCount());
    CIterator unitIter(descriptor->militaryUnitList44);
    for (TObject* unit = static_cast<TObject*>(unitIter.Reset()); unitIter.More();
         unit = static_cast<TObject*>(unitIter.Advance())) {
      unit->WriteTo(stream);
    }
  }
  stream->streamSlot7c('.');
}

// FUNCTION: IMPERIALISM 0x0054a5e0
void TMultiplayerMgr::PublishNationDescriptorAndNotifyOrderListeners(TStream* stream,
                                                                     int nationFilter) {
  int slot = 0;
  for (TGreatPower** cell = g_apNationStates; cell < g_apNationStates + 7; ++cell, ++slot) {
    bool matches;
    if (nationFilter == -1 || nationFilter == slot) {
      matches = true;
    } else {
      matches = false;
    }
    TGreatPower* nation = *cell;
    if (nation == 0 || !matches) {
      stream->WriteCountSlot88(0);
    } else {
      stream->WriteCountSlot88(nation->trackedObjectList->GetCount());
      CIterator trackedIter(nation->trackedObjectList);
      for (TObject* tracked = static_cast<TObject*>(trackedIter.Reset()); trackedIter.More();
           tracked = static_cast<TObject*>(trackedIter.Advance())) {
        tracked->WriteTo(stream);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0054a9d0
int TMultiplayerMgr::IsSpecialNationDialogModeActive() {
  if (sessionPhaseTag == 0x676f696e) {
    if (g_pSimMgr->GetActiveNationId() != -1) {
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0054ab20
extern "C" void __stdcall DispatchTileRedrawInvalidateEvent(short tileIndex) {
  TileRedrawInvalidateTurnEventPacket packet;
  packet.eventCode = 0x23;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x44;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.uiTurnToken = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
  packet.tileIndex = tileIndex;
  packet.tileSnapshot = g_pGlobalMapState->terrainStateTable[tileIndex];

  g_pNetMgr006a6014->Send(&packet, 0);
}

struct TJoinEmpireTurnEventPacket : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15[3];
  int sourceNationSlot;
  int targetNationSlot;
  int modeValue;
};

// FUNCTION: IMPERIALISM 0x0054abf0
void TMultiplayerMgr::DispatchCityRedrawInvalidateEvent(short cityId) {
  CityRedrawInvalidateTurnEventPacket packet;
  packet.eventCode = 0x24;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 200;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.uiTurnToken = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
  packet.cityId = cityId;

  const TGlobalMapCityScoreRecord* src = &g_pGlobalMapState->cityScoreTable[cityId];
  packet.cityHeader00[0] = src->ownerNationCode00;
  packet.cityHeader00[1] = src->formerOwnerNationCode01;
  packet.cityHeader00[2] = src->developmentStage;
  packet.cityHeader00[3] = src->fortLevel03;
  packet.cityWord04 = src->cityTileIndex04;
  packet.cityWord06 = src->lastTurnTick;
  packet.cityByte08 = src->adjacentRegionCount08;

  for (int wordIndex = 0; wordIndex < 12; ++wordIndex) {
    packet.adjacentRegionIds0A[wordIndex] = src->adjacentRegionIds0A[wordIndex];
    packet.adjacentRegionIds22[wordIndex] = src->adjacentRegionAnchorTiles22[wordIndex];
  }

  packet.cityBytes3A[0] = src->linkedRegionCount;
  packet.cityBytes3A[1] = src->byte3B;
  packet.cityBytes3A[2] = src->byte3C;
  packet.cityWord3E = src->secondaryNeighborTileIndex3e;
  packet.cityWord40 = src->primaryNeighborTileIndex40;

  for (int linkedIndex = 0; linkedIndex < 32; ++linkedIndex) {
    packet.linkedRegionIds42[linkedIndex] = src->linkedRegionIds[linkedIndex];
  }
  packet.linkedRegionIds82[0] = src->resourceDevelopmentCounts82[0];
  packet.linkedRegionIds82[1] = src->resourceDevelopmentCounts82[1];
  packet.linkedRegionIds82[2] = src->resourceDevelopmentCounts82[2];
  packet.linkedRegionIds82[3] = src->resourceDevelopmentCounts82[3];
  packet.linkedRegionIds82[4] = src->resourceDevelopmentCounts82[4];
  packet.linkedRegionIds82[5] = src->resourceDevelopmentCounts82[5];
  packet.linkedRegionIds82[6] = src->resourceDevelopmentCounts82[6];
  packet.linkedRegionIds82[7] = src->resourceDevelopmentCounts82[7];
  packet.linkedRegionIds82[8] = src->resourceDevelopmentCounts82[8];
  packet.linkedRegionIds82[9] = src->resourceDevelopmentCounts82[9];

  packet.stationedUnitChain98 = src->stationedUnitChain98;
  packet.cityScoreValue9C = src->cityScoreValue;
  packet.cityBytesA0[0] = src->padA0;
  packet.cityBytesA0[1] = src->exploredByNationMaskA1;
  packet.cityBytesA0[2] = src->resourcePresenceMaskA2;
  packet.cityBytesA0[3] = src->regionClassA3;
  packet.cityNameA4 = src->cityNameA4;

  g_pNetMgr006a6014->Send(&packet, 0);
}

// FUNCTION: IMPERIALISM 0x0054ae90
NationStateRecordA8& NationStateRecordA8::operator=(const NationStateRecordA8& source) {
  ownerNationCode00 = source.ownerNationCode00;
  formerOwnerNationCode01 = source.formerOwnerNationCode01;
  developmentStage = source.developmentStage;
  fortLevel03 = source.fortLevel03;
  cityTileIndex04 = source.cityTileIndex04;
  lastTurnTick = source.lastTurnTick;
  adjacentRegionCount08 = source.adjacentRegionCount08;
  for (int a = 0; a < 12; ++a) {
    adjacentRegionIds0A[a] = source.adjacentRegionIds0A[a];
  }
  for (int b = 0; b < 12; ++b) {
    adjacentRegionAnchorTiles22[b] = source.adjacentRegionAnchorTiles22[b];
  }
  linkedRegionCount = source.linkedRegionCount;
  field3B = source.field3B;
  field3C = source.field3C;
  secondaryNeighborTileIndex3e = source.secondaryNeighborTileIndex3e;
  primaryNeighborTileIndex40 = source.primaryNeighborTileIndex40;
  for (int c = 0; c < 0x20; ++c) {
    linkedRegionIds42[c] = source.linkedRegionIds42[c];
  }
  for (int d = 0; d < 10; ++d) {
    resourceDevelopmentCounts82[d] = source.resourceDevelopmentCounts82[d];
  }
  reservedUnitChainSlot98 = source.reservedUnitChainSlot98;
  reservedCityScoreSlot9C = source.reservedCityScoreSlot9C;
  padA0 = source.padA0;
  exploredByNationMaskA1 = source.exploredByNationMaskA1;
  resourcePresenceMaskA2 = source.resourcePresenceMaskA2;
  regionClassA3 = source.regionClassA3;
  cityNameA4 = source.cityNameA4;
  return *this;
}

// FUNCTION: IMPERIALISM 0x0054b1b0
void TMultiplayerMgr::RefreshPoseMessageDialogNationSelectionControls(int unused) {
  (void)unused;
  if (FindActiveNationSlotIndexInGameFlowList() == -1) {
    CString notSeatedMessage;
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&notSeatedMessage, 0x2742,
                                                                    0x16);
    g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
        notSeatedMessage, &g_cstrNationAwolMessageStore, 0, 0);
    return;
  }

  TView* dialog = g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x5e7);
  dialog->AssertValid();

  int mySlotIndex = FindActiveNationSlotIndexInGameFlowList();
  for (int i = 0; i < 7; ++i) {
    TView* boxControl = dialog->ResolveControlByTag(0x62786230u + i); // 'box0'-'box6'
    boxControl->AssertValid();
    int sessionId = g_pGameFlowState->nationSessionIds[i];
    bool occupied = sessionId != 0 && sessionId != -2;
    bool occupiedByMe = occupied && (i == mySlotIndex);
    boxControl->SetState(occupied && !occupiedByMe, 0);
    // The original then calls the box control's own slot-0x75/0x76 virtuals (isMine flag,
    // then a bare refresh) -- the 'box' receiver class is unresolved, so left unmodeled.
  }

  // The original then restyles and resolves a 'mesg' control, calls its own slot-0x1f
  // virtual, and dispatches the built style buffer to the dialog's linked children (slot
  // 0x27) -- not yet decoded.
}

// FUNCTION: IMPERIALISM 0x0054b4c0
void TMultiplayerMgr::DispatchTurnEventCode9WithTwoTextTokens(int reasonCode, int field1CValue,
                                                              const char* senderText,
                                                              const char* messageText) {
  LobbyChatEvent9Packet packet;
  packet.eventCode = 9;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = sizeof(packet);
  packet.InitializeEmitEventHeaderWithActiveNation();
  packet.nationSlot18 = static_cast<unsigned char>(reasonCode);
  packet.field1C = field1CValue;
  strcpy(packet.senderName, senderText);
  strcpy(packet.messageText, messageText);
  g_pNetMgr006a6014->Send(&packet, 0);
}

// FUNCTION: IMPERIALISM 0x0054b5d0
void TMultiplayerMgr::EmitNationDiplomacyNeedStateSnapshotEvent15(char broadcastFlag,
                                                                  int nationSlot) {
  TurnEvent15Packet packet;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventCode = 0;
  packet.eventCode = 0x15;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0;
  packet.messageLength = 0x6e4;
  if (broadcastFlag != 0) {
    packet.toNetworkId = -1;
  } else {
    packet.toNetworkId = g_pGameFlowState->nationSessionIds[nationSlot];
  }
  packet.nationSlot = static_cast<short>(nationSlot);
  TGreatPower* nation = g_apNationStates[nationSlot];
  packet.treasuryValue = nation->treasuryValue10;
  packet.grantTotalCost = nation->grantTotalCost;
  for (int i = 0; i < 0x17; ++i) {
    packet.needCurrentByType[i] = nation->needCurrentByType[i];
    packet.needTargetByType[i] = nation->needTargetByType[i];
    packet.relationDeltaCurrent[i] = nation->relationDeltaCurrent[i];
    packet.relationDeltaSnapshot[i] = nation->relationDeltaSnapshot[i];
    packet.diplomacyState1c6[i] = nation->diplomacyState1c6[i];
    for (int j = 0; j < 0x10; ++j) {
      packet.aidAllocationMatrix[j * 0x17 + i] = nation->aidAllocationMatrix[j * 0x17 + i];
    }
  }
  packet.budgetPoolBase = nation->budgetPoolBase;
  packet.budgetPoolDelta = nation->budgetPoolDelta;
  packet.diplomacyBudgetBase = nation->diplomacyBudgetBase;
  packet.escalationCounter = nation->escalationCounter;
  packet.pendingCommitmentCost = nation->pendingCommitmentCost;
  packet.pressureCounter = nation->pressureCounter;
  g_pNetMgr006a6014->Send(&packet, 0);
}

// FUNCTION: IMPERIALISM 0x0054b8c0
int TMultiplayerMgr::GetNationStatusCodeForSlotOrActiveNation(int slot) {
  if (slot == -1) {
    slot = g_pSimMgr->GetActiveNationId();
    if (slot == -1) {
      int sessionActive = GetSessionActiveNationId();
      slot = 0;
      int* sessionId = g_pGameFlowState->nationSessionIds;
      do {
        if (*sessionId == sessionActive) {
          goto resolved;
        }
        ++slot;
        ++sessionId;
      } while (slot < 7);
      slot = -1;
    }
  }
resolved:
  return nationStatusTags[slot];
}

// FUNCTION: IMPERIALISM 0x0054b930
void TMultiplayerMgr::SetNationStatusAwolByNationIdAndDispatchNotices(int networkId) {
  for (int slot = 0; slot < 7; ++slot) {
    if (nationSessionIds[slot] == networkId) {
      int tagSlot = slot;
      if (slot == -1) {
        tagSlot = g_pSimMgr->GetActiveNationId();
      }
      if (tagSlot == -1) {
        tagSlot = activeNationTagIndex;
      }
      nationStatusTags[tagSlot] = 0x61776f6c; // 'awol'
      NationStatusEvent25Packet statusPacket;
      statusPacket.InitializeEmitEventHeaderWithActiveNation();
      statusPacket.InitializeNationStatusEvent25PayloadDefaults();
      statusPacket.toNetworkId = 0;
      statusPacket.statusTags[tagSlot] = 0x61776f6c;
      g_pNetMgr006a6014->Send(&statusPacket, 0);
      nationSessionIds[slot] = -2;
      pendingNationBitmask |= 1 << slot;
      if (sessionPhaseTag == 0x696e6974 && g_pSimMgr->field44 == 1) { // 'init'
        LobbyChatEvent9Packet chat;
        chat.InitializeEmitEventHeaderWithActiveNation();
        chat.eventCode = 0;
        chat.field1C = 0;
        chat.fromNetworkId = 0;
        chat.eventCode = 9;
        chat.toNetworkId = 0;
        chat.messageLength = 0;
        chat.messageLength = 0x64;
        chat.nationSlot18 = static_cast<unsigned char>(slot);
        strcpy(chat.senderName, g_szEmptyString);
        strcpy(chat.messageText, g_szEmptyString);
        g_pNetMgr006a6014->Send(&chat, 1);
      } else {
        CString formatted;
        CString nationName;
        nationName = defaultNationTextSlots[slot];
        CString templateText;
        g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&templateText, 0x2759, 4);
        scanBracketExpressions(g_pSimMgr, &formatted, static_cast<LPCSTR>(templateText),
                               static_cast<LPCSTR>(nationName));
        g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
            formatted, &g_cstrNationAwolMessageStore, 0, 0);
        if (g_pGameFlowState != this || fieldF4 == 0) {
          TCancelGameOptionsCommand* cancelCommand = new TCancelGameOptionsCommand();
          cancelCommand->InitializeRangePair(0x63676f70, g_pGlobalUiRootController, 0, 0,
                                             0); // 'pogc'
          g_pGlobalUiRootController->DispatchUiSelectionToHandler(cancelCommand);
        }
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0054bce0
void NationStatusEvent25Packet::InitializeNationStatusEvent25PayloadDefaults() {
  // The original zeroes the header through a second pointer, so the eventCode /
  // messageLength double-stores below survive (no-alias can't be proven).
  NetMessage* header = this;
  header->eventCode = 0;
  header->fromNetworkId = 0;
  header->toNetworkId = 0;
  header->messageLength = 0;
  messageLength = 0x34;
  eventCode = 0x25;
  for (int slot = 0; slot < 7; ++slot) {
    statusTags[slot] = 0x756e6b6e; // 'unkn'
  }
}

// Builds a turn-event-26 packet snapshotting g_pDiplomacyTurnStateManager's
// relationCodeMatrix04/pendingPolicyCodeMatrix304/pendingPolicyTierMatrix484/
// selectedSourceNationSlot784../comparativePowerRows1824 and sends it via TNetMgr::Send.
// FUNCTION: IMPERIALISM 0x0054c480
void TMultiplayerMgr::EmitTurnEvent26DiplomacyMatrixSnapshot() {
  TurnEvent26DiplomacyMatrixPacket packet;
  packet.messageTag = 0x74696d65; // 'time'
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.eventCode = 0x26;
  packet.messageLength = 0x814;
  memcpy(packet.relationCodeMatrix, g_pDiplomacyTurnStateManager->relationCodeMatrix04,
         sizeof(packet.relationCodeMatrix));
  memcpy(packet.pendingPolicyCodeMatrix, g_pDiplomacyTurnStateManager->pendingPolicyCodeMatrix304,
         sizeof(packet.pendingPolicyCodeMatrix));
  memcpy(packet.pendingPolicyTierMatrix, g_pDiplomacyTurnStateManager->pendingPolicyTierMatrix484,
         sizeof(packet.pendingPolicyTierMatrix));
  packet.selectedSourceNationSlot = g_pDiplomacyTurnStateManager->selectedSourceNationSlot784;
  packet.selectedTargetNationSlot = g_pDiplomacyTurnStateManager->selectedTargetNationSlot786;
  packet.selectionFlagsA = g_pDiplomacyTurnStateManager->selectionFlagsA788;
  packet.selectionFlagsB = g_pDiplomacyTurnStateManager->selectionFlagsB78a;
  packet.selectionFlagsC = g_pDiplomacyTurnStateManager->selectionFlagsC78c;
  memcpy(packet.relationTailBlock, g_pDiplomacyTurnStateManager->comparativePowerRows1824,
         sizeof(packet.relationTailBlock));
  g_pNetMgr006a6014->Send(&packet, 0);
}

// FUNCTION: IMPERIALISM 0x0054c5a0
void TMultiplayerMgr::DispatchJoinEmpireModeEventPacket24_27(int sourceNation, int targetNation,
                                                             int mode) {
  TJoinEmpireTurnEventPacket packet;
  packet.packetTag = 0x74696D65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0;
  packet.sourceNationSlot = sourceNation;
  packet.targetNationSlot = targetNation;
  packet.modeValue = mode;
  packet.messageLength = 0x24;
  packet.eventCode = 0x27;
  g_pNetMgr006a6014->Send(&packet, 0);
}

// FUNCTION: IMPERIALISM 0x0054c630
void TMultiplayerMgr::SetDialogModeTagInitAndInvokeNoOpHook() {
  sessionPhaseTag = 0x696e6974; // 'init'
  g_pNetMgr006a6014->NoOpDialogModeTagChangedHook(1);
}

// FUNCTION: IMPERIALISM 0x0054c660
void TMultiplayerMgr::NoOpCallbackRet4(void* param) {
  (void)param;
}

// FUNCTION: IMPERIALISM 0x0054c680
void TMultiplayerMgr::EmitTacticalCommandPacket(int commandTag, TTacticalUnit* unit, int arg3,
                                                int arg4) {
  // Genuinely empty in the shipped binary (bare `ret 0x10`): the multiplayer
  // tactical-command echo was compiled out of the retail build.
  (void)commandTag;
  (void)unit;
  (void)arg3;
  (void)arg4;
}

// FUNCTION: IMPERIALISM 0x0054c6a0
void TMultiplayerMgr::EmitTacticalFireCommandPacket(int commandTag, TTacticalUnit* attackerUnit,
                                                    TTacticalUnit* targetUnit, int damageA,
                                                    int damageB, int effectCode) {
  // Genuinely empty in the shipped binary (bare `ret 0x18`); see
  // EmitTacticalCommandPacket.
  (void)commandTag;
  (void)attackerUnit;
  (void)targetUnit;
  (void)damageA;
  (void)damageB;
  (void)effectCode;
}

// FUNCTION: IMPERIALISM 0x0054c6e0
void TMultiplayerMgr::ResetNationStatusArraysAndTurnEventContext() {
  CString statusText;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&statusText, 0x2759, 1);
  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    nationSessionIds[nationSlot] = 0;
    nationStatusTags[nationSlot] = 0x756e6173; // 'suna'
    nationDisplayNameSlots[nationSlot] = statusText;
    defaultNationTextSlots[nationSlot] = nationDisplayNameSlots[nationSlot];
  }
  activeNationSlotIndex = -1;
  pendingNationSlotIndex = -1;
  queueSyncDword = 0;
  g_pNetMgr006a6014->ResetTurnEventQueueRuntimeRecordBuffer();
}

// Emit the event-0xE session-init snapshot (scenario tag/seed, host game name, save
// slot, sim state code) followed by seven event-9 seat-claim packets mirroring the
// nation name/session tables; `packet`, when present, addresses both to its sender.
// Skipped entirely before the map exists or while still in the 'prep' phase.
// FUNCTION: IMPERIALISM 0x0054c8e0
void TMultiplayerMgr::EmitTurnEventEAnd9SessionContextPackets(NetMessage* packet) {
  if (g_pGlobalMapState == 0 || sessionPhaseTag == 0x70726570 /* 'prep' */) {
    return;
  }
  {
    TurnEventESessionInitPacket sessionInit;
    sessionInit.messageTag = 0x74696d65; // 'time'
    sessionInit.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
    sessionInit.eventCode = 0;
    sessionInit.eventCode = 0xe;
    sessionInit.fromNetworkId = 0;
    sessionInit.toNetworkId = 0;
    sessionInit.messageLength = 0;
    sessionInit.messageLength = 0x68;
    if (packet != 0) {
      sessionInit.toNetworkId = packet->fromNetworkId;
    } else {
      sessionInit.toNetworkId = 0;
    }
    sessionInit.scenarioTag60 = scenarioSelectionTag;
    unsigned char resumingSavedGame;
    if (sessionPhaseTag == 0x676f696e /* 'goin' */ && g_pSimMgr->GetActiveNationId() != -1) {
      resumingSavedGame = 1;
    } else {
      resumingSavedGame = 0;
    }
    if (resumingSavedGame != 0) {
      sessionInit.scenarioTag60 = 0x6c6f6164; // 'load'
    }
    strcpy(sessionInit.hostGameName3A, gameNameString);
    strcpy(sessionInit.mapSeedText18, g_pGlobalMapState->scenarioTagText1c);
    sessionInit.mapParamByte39 = g_pGlobalMapState->hexNeighborWrapHorizontally20;
    sessionInit.saveSlotDword5C = queueSyncDword;
    // Round-trips through the receive side's SetStateCodeAndUpdateZeroOrOutOfRangeFlag,
    // which stores back into this same +0x40 field.
    sessionInit.simStateCode64 = static_cast<signed char>(g_pSimMgr->redrawEnabled);
    sessionInit.nameTableFlag65 = g_pSimMgr->useLocalizedNameTables68;
    g_pNetMgr006a6014->Send(&sessionInit, 0);
  }
  {
    LobbyChatEvent9Packet seatClaim;
    seatClaim.messageTag = 0x74696d65; // 'time'
    seatClaim.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
    seatClaim.eventCode = 0;
    seatClaim.eventCode = 9;
    seatClaim.fromNetworkId = 0;
    seatClaim.toNetworkId = 0;
    seatClaim.messageLength = 0;
    seatClaim.messageLength = 0x64;
    if (packet != 0) {
      seatClaim.toNetworkId = packet->fromNetworkId;
    } else {
      seatClaim.toNetworkId = 0;
    }
    for (int emitSlot = 0; emitSlot < 7; ++emitSlot) {
      seatClaim.field1C = nationSessionIds[emitSlot];
      seatClaim.nationSlot18 = static_cast<unsigned char>(emitSlot);
      strcpy(seatClaim.senderName, defaultNationTextSlots[emitSlot]);
      strcpy(seatClaim.messageText, nationDisplayNameSlots[emitSlot]);
      g_pNetMgr006a6014->Send(&seatClaim, 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0054cc00
void TMultiplayerMgr::RefreshNationStatusLabelsAndCodesForSlotOrAll(int nationSlot) {
  if (nationSlot == -1) {
    for (int slot = 0; slot < 7; ++slot) {
      RefreshNationStatusLabelsAndCodesForSlotOrAll(slot);
    }
  } else if (g_apNationStates[nationSlot] == 0) {
    {
      CString emptyName(g_szEmptyString);
      defaultNationTextSlots[nationSlot] = emptyName;
    }
    nationStatusTags[nationSlot] = 0x64656164; // 'dead'
  } else {
    bool wrapInParens;
    if (g_apNationStates[nationSlot]->diplomacyEligibilityA0 == 0 ||
        g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(nationSlot)) == 0) {
      wrapInParens = true;
    } else {
      wrapInParens = false;
    }
    CString nationName;
    g_apNationStates[nationSlot]->FormatOverlayTerrainLabelText(&nationName);
    const char* prefix = g_szUiOpenParen_0069806C;
    if (!wrapInParens) {
      prefix = g_szEmptyString;
    }
    CString prefixText(prefix);
    defaultNationTextSlots[nationSlot] = prefixText;
    defaultNationTextSlots[nationSlot] += nationName;
    const char* suffix = g_szUiCloseParen_006973C8;
    if (!wrapInParens) {
      suffix = g_szEmptyString;
    }
    defaultNationTextSlots[nationSlot] += suffix;
    nationDisplayNameSlots[nationSlot] = defaultNationTextSlots[nationSlot];
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(nationSlot)) == 0) {
      nationStatusTags[nationSlot] = 0x64656361; // 'deca'
    }
  }
}

// FUNCTION: IMPERIALISM 0x0054ce80
void TMultiplayerMgr::EmitTurnEvent2CNationStateCompositeForSlot(int nationSlot,
                                                                 int destinationSlot) {
  TurnEvent2CPacket packet;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.fromNetworkId = 0;
  packet.messageLength = 0x18c;
  packet.eventCode = 0x2c;
  packet.pendingNationSlot = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
  if (destinationSlot == -2 || destinationSlot == -3) {
    packet.toNetworkId = 0;
  } else if (destinationSlot == -1) {
    packet.toNetworkId = -1;
  } else {
    packet.toNetworkId = g_pGameFlowState->nationSessionIds[destinationSlot];
  }
  packet.nationSlot = static_cast<short>(nationSlot);
  TGreatPower* nation = g_apNationStates[nationSlot];
  packet.field910 = nation->field910;
  packet.aidAllocationTotal = nation->aidAllocationTotal;
  TCity* city;
  if (nation == 0) {
    city = 0;
  } else {
    city = nation->city;
  }
  if (city != 0) {
    for (int i = 0; i < 0x1e; ++i) {
      packet.cityMetricsBlock0E[i] = city->cityMetricsBlock0E[i];
    }
    for (int j = 0; j < 9; ++j) {
      packet.cityMetricsBlock4A[j] = city->cityMetricsBlock4A[j];
    }
    for (int orderType = 0; orderType < 0x0e; ++orderType) {
      packet.orderCountByType[orderType] = city->orderCountByType5c[orderType];
    }
    packet.cityField78 = city->field78;
    packet.cityFieldB4 = city->fieldB4;
    short* stock = &city->cityStockCottonB6;
    for (int stockType = 0; stockType < 0x17; ++stockType) {
      packet.cityStock[stockType] = stock[stockType];
    }
    for (int slot = 0; slot < 0x10; ++slot) {
      packet.productionOrderTable[slot] = city->productionOrderTable1dc[slot];
    }
    for (int slot2 = 0; slot2 < 0x10; ++slot2) {
      packet.productionAccum[slot2] = city->productionAccum1fc[slot2];
    }
    packet.cityField26C = city->field26c;
    for (int record = 0; record < 0x17; ++record) {
      TProductionOrder* order = city->tradeCommodityRecordPtrs[record];
      if (order == 0) {
        packet.orderAccumulatedValues[record] = 0;
      } else {
        packet.orderAccumulatedValues[record] = order->accumulatedValue;
      }
    }
    TPopulationMgr* summary = city->productionSummary1d8;
    packet.popFieldAt8 = summary->fieldAt8;
    packet.popFieldAtC = summary->fieldAtC;
    packet.popStockLevel = summary->stockLevel1c;
    packet.popExtraAt1e = summary->extraAt1e;
    packet.popFieldAt20 = summary->fieldAt20;
    packet.popBucketWords[0] = summary->baselineSlots10->valueAt4;
    packet.popBucketWords[1] = summary->baselineSlots10->valueAt6;
    packet.popBucketWords[2] = summary->baselineSlots10->valueAt8;
    packet.popBucketWords[3] = summary->productionSlots14->valueAt4;
    packet.popBucketWords[4] = summary->productionSlots14->valueAt6;
    packet.popBucketWords[5] = summary->productionSlots14->valueAt8;
    packet.popBucketWords[6] = summary->pendingDeltaSlots18->valueAt4;
    packet.popBucketWords[7] = summary->pendingDeltaSlots18->valueAt6;
    packet.popBucketWords[8] = summary->pendingDeltaSlots18->valueAt8;
    g_pNetMgr006a6014->Send(&packet, destinationSlot == -3);
  }
}

// FUNCTION: IMPERIALISM 0x0054d1f0
void TMultiplayerMgr::EmitTurnEvent19NationStateArraysForSlot(short nationSlot,
                                                              int destinationSlot) {
  TurnEvent19Packet packet;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventCode = 0;
  packet.eventCode = 0x19;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.toNetworkId = -1;
  packet.messageLength = 0;
  packet.messageLength = 0x118;
  packet.pendingNationSlot = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
  if (destinationSlot == -2 || destinationSlot == -3) {
    packet.toNetworkId = 0;
  } else if (destinationSlot == -1) {
    packet.toNetworkId = -1;
  } else {
    packet.toNetworkId = g_pGameFlowState->nationSessionIds[destinationSlot];
  }
  TGreatPower* nation = g_apNationStates[nationSlot];
  packet.nationSlot = nationSlot;
  EmitNationDiplomacyNeedStateSnapshotEvent15(1, nationSlot);
  packet.needCapA6 = nation->needCapA6;
  for (int orderType = 0; orderType < 0x0e; ++orderType) {
    packet.orderCountByType[orderType] = nation->city->orderCountByType5c[orderType];
  }
  for (int i = 0; i < 0x17; ++i) {
    packet.externalStateByTarget[i] =
        nation->GetDiplomacyExternalStateByTarget(static_cast<short>(i));
  }
  for (int metricSlot = 0; metricSlot < 0x11; ++metricSlot) {
    packet.metricBySlot7C[metricSlot] =
        nation->QueryNationMetricBySlot7C(static_cast<short>(metricSlot));
  }
  for (short target = 0; target < 0x17; ++target) {
    packet.diplomacyPolicyByNation[target] = nation->diplomacyPolicyByNation[target];
    packet.diplomacyGrantByNation[target] = nation->diplomacyGrantByNation[target];
    packet.needLevelByNation[target] = nation->needLevelByNation[target];
  }
  g_pNetMgr006a6014->Send(&packet, destinationSlot == -3);
}

// Probe reachability; when every nation is reachable, run the save-game driver with the
// given mode/label. On failure (someone AWOL) optionally pose the localized "cannot
// save" advisory (string 0x2742/0x28) as a modal message command. Returns the
// all-reachable byte Boolean. `this` is unused; callers dispatch it on
// g_pGameFlowState.
// FUNCTION: IMPERIALISM 0x0054d4e0
unsigned char TMultiplayerMgr::TrySaveGameAndMaybeShowFailureDialog(int mode, char* label,
                                                                    char showFailureDialog) {
  unsigned char allReachable = g_pNetMgr006a6014->ProbeNationReachabilityAndMarkAwolBitmask() == 0;
  if (allReachable != 0) {
    SaveGameWithModeAndOptionalLabel(mode, label);
  }
  if (showFailureDialog != 0 && allReachable == 0) {
    CString message;
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, 0x2742, 0x28);
    g_pUiRuntimeContext->CreateModalMessageCommandAndQueue(&message, 0);
  }
  return allReachable;
}

// Trivial credential-init stub reused across the networking cluster (0x5e34b0):
// unconditionally reports success regardless of receiver.
// FUNCTION: IMPERIALISM 0x005e34b0
static char ReturnTrueRuntimeCredentialInitStub() {
  return 1;
}

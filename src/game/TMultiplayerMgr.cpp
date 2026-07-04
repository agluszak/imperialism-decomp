#include "game/TMultiplayerMgr.h"

#include "decomp_types.h"
#include "game/CString.h"
#include "game/mapped_flavor_text.h"
#include "game/NetMessage.h"
#include "game/TGreatPower.h"
#include "game/TMapMgr.h"
#include "game/TNetMgr.h"
#include "game/TSimMgr.h"
#include "game/TStream.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include <cstring>

// Leaf helpers reached through ILT thunks / autogen stubs. They are genuine __cdecl free
// functions (verified against the disassembly — none consume ECX as `this` on entry; the
// ECX loads before some calls are optimizer reuse, not a this-arg). Declared extern in the
// generic repo form per Hard Rule 9 and cast to their real typed signatures at the call sites.
extern undefined4 NoOpInitializeGlobalTurnEventQueueManager();
extern undefined4 ResetTurnEventQueueRuntimeRecordBuffer();
extern undefined4 LoadProfileStringAndAssignSharedRef();
extern undefined4 AssignStringSharedRefFromPointer();

// Profile-section string literals.
extern "C" const char s_PlayerName_0069801c[];
extern "C" const char s_GameName_00698010[];

// FUNCTION: IMPERIALISM 0x00542650
CRuntimeClass* TMultiplayerMgr::GetRuntimeClass() const {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00542670
TMultiplayerMgr::TMultiplayerMgr()
    : TEventHandler(), gameNameString(), defaultNationTextSlots(), nationDisplayNameSlots(),
      playerNameString(), playerNameMirror(), fieldb8() {
  InitializeUiResourceEntryBaseHeaderDefaults();
  memset(nationStatusControlSlots, 0, sizeof(nationStatusControlSlots));
  field40 = 0;
  primaryTurnEventQueueHead = 0;
  secondaryTurnEventQueueHead = 0;
  sessionPhaseTag = 0x6e616461;
  fieldF4 = 0;
}

// SYNTHETIC: IMPERIALISM 0x005427e0
// TMultiplayerMgr::`scalar deleting destructor'
TMultiplayerMgr::~TMultiplayerMgr() {}

// FUNCTION: IMPERIALISM 0x00542900
undefined TMultiplayerMgr::InitializeMultiplayerManagerForSessionContext(CString param_1) {
  this->InitializePacketHeaderFields_Tag20202020(0);
  field10 = reinterpret_cast<int>(static_cast<LPCSTR>(param_1));
  diplomacyQueueContext = 0;
  sessionReadyFlag = 0;
  processPrimaryEventQueue = 1;
  processSecondaryEventQueue = 1;

  TNetMgr* queueStorage = new TNetMgr();
  g_pNetMgr006a6014 = queueStorage;
  reinterpret_cast<void (*)()>(NoOpInitializeGlobalTurnEventQueueManager)();

  CString loadedString;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&loadedString, 0x2759, 1);

  for (int i = 0; i < kNationSlotCount; ++i) {
    nationSessionIds[0] = 0;
    nationStatusTags[0] = 0x756e6173;
    nationDisplayNameSlots[i] = loadedString;
    reinterpret_cast<void (*)(CString*)>(AssignStringSharedRefFromPointer)(
        &nationDisplayNameSlots[i]);
  }

  queueSyncDword = 0;
  activeNationSlotIndex = -1;
  pendingNationSlotIndex = -1;
  reinterpret_cast<void (*)()>(ResetTurnEventQueueRuntimeRecordBuffer)();

  GenerateMappedFlavorTextByCurrentContextNation(&playerNameString);
  reinterpret_cast<void (*)(CString*, const char*, const char*)>(
      LoadProfileStringAndAssignSharedRef)(&loadedString, s_PlayerName_0069801c,
                                           static_cast<LPCSTR>(playerNameString));
  playerNameString = loadedString;
  playerNameMirror = playerNameString;

  GenerateMappedFlavorTextByCurrentContextNation(&gameNameString);
  reinterpret_cast<void (*)(CString*, const char*, const char*)>(
      LoadProfileStringAndAssignSharedRef)(&loadedString, s_GameName_00698010,
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

struct TurnEvent3Mode18Packet : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15[3];
};

// FUNCTION: IMPERIALISM 0x005446a0
void TMultiplayerMgr::EmitTurnEvent3Mode18WithActiveNation() {
  TurnEvent3Mode18Packet packet;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pLocalizationTable->GetActiveNationId());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0;
  packet.eventCode = 3;
  packet.messageLength = 0x18;
  g_pNetMgr006a6014->Send(&packet, 1);
}

// FUNCTION: IMPERIALISM 0x00544e30
char TMultiplayerMgr::CanHandleCityDialogActionFalse(int action) {
  (void)action;
  return 0;
}

// ---------------------------------------------------------------------------
// Turn-event emitters. Each builds a 'time'-tagged NetMessage-derived packet on
// the stack and hands it to TNetMgr::Send (queueOnly per callsite). `this` is
// unused, exactly as in the original __thiscall bodies.
// ---------------------------------------------------------------------------

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
  packet.activeNationId = static_cast<unsigned char>(g_pLocalizationTable->GetActiveNationId());
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
  packet.activeNationId = static_cast<unsigned char>(g_pLocalizationTable->GetActiveNationId());
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
  packet.activeNationId = static_cast<unsigned char>(g_pLocalizationTable->GetActiveNationId());
  packet.byte0 = byte0;
  packet.byte1 = byte1;
  packet.byte2 = byte2;
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
  packet.activeNationId = static_cast<unsigned char>(g_pLocalizationTable->GetActiveNationId());
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
  packet.activeNationId = static_cast<unsigned char>(g_pLocalizationTable->GetActiveNationId());
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

// FUNCTION: IMPERIALISM 0x0054abf0
void TMultiplayerMgr::DispatchCityRedrawInvalidateEvent(short cityId) {
  CityRedrawInvalidateTurnEventPacket packet;
  packet.eventCode = 0x24;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 200;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pLocalizationTable->GetActiveNationId());
  packet.uiTurnToken = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
  packet.cityId = cityId;

  const TGlobalMapCityScoreRecord* src = &g_pGlobalMapState->cityScoreTable[cityId];
  packet.cityHeader00[0] = src->ownerNationCode00;
  packet.cityHeader00[1] = src->byte01;
  packet.cityHeader00[2] = src->developmentStage;
  packet.cityHeader00[3] = src->fortLevel03;
  packet.cityWord04 = src->ownerNationSlot;
  packet.cityWord06 = src->lastTurnTick;
  packet.cityByte08 = src->adjacentRegionCount08;

  for (int wordIndex = 0; wordIndex < 12; ++wordIndex) {
    packet.adjacentRegionIds0A[wordIndex] = src->adjacentRegionIds0A[wordIndex];
    packet.adjacentRegionIds22[wordIndex] = src->adjacentRegionIds0A[wordIndex + 12];
  }

  packet.cityBytes3A[0] = src->linkedRegionCount;
  packet.cityBytes3A[1] = src->byte3B;
  packet.cityBytes3A[2] = src->byte3C;
  packet.cityWord3E = src->field3E;
  packet.cityWord40 = src->field40;

  for (int linkedIndex = 0; linkedIndex < 32; ++linkedIndex) {
    packet.linkedRegionIds42[linkedIndex] = src->linkedRegionIds[linkedIndex];
  }
  packet.linkedRegionIds82[0] = src->linkedRegionIds[32];
  packet.linkedRegionIds82[1] = src->stage1CounterA;
  packet.linkedRegionIds82[2] = src->stage1CounterB;
  packet.linkedRegionIds82[3] = src->pad88;
  packet.linkedRegionIds82[4] = src->stage1CounterC;
  packet.linkedRegionIds82[5] = src->stage1CounterD;
  packet.linkedRegionIds82[6] = src->stage2CounterA;
  packet.linkedRegionIds82[7] = src->stage2CounterB;
  packet.linkedRegionIds82[8] = src->stage2CounterC;
  packet.linkedRegionIds82[9] = src->field94;

  packet.stationedUnitChain98 = src->stationedUnitChain98;
  packet.cityScoreValue9C = src->cityScoreValue;
  packet.cityBytesA0[0] = src->padA0[0];
  packet.cityBytesA0[1] = src->padA0[1];
  packet.cityBytesA0[2] = src->padA0[2];
  packet.cityBytesA0[3] = src->padA0[3];
  packet.cityNameA4 = src->cityNameA4;

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

// FUNCTION: IMPERIALISM 0x0054c5a0
void TMultiplayerMgr::DispatchJoinEmpireModeEventPacket24_27(int sourceNation, int targetNation,
                                                             int mode) {
  TJoinEmpireTurnEventPacket packet;
  packet.packetTag = 0x74696D65;
  packet.activeNationId = static_cast<unsigned char>(g_pLocalizationTable->GetActiveNationId());
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

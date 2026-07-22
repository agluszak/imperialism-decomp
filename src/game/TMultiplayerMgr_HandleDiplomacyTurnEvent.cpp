// TMultiplayerMgr::HandleDiplomacyTurnEventPacketByCode (0x00543910) is a single ~2.4KB
// monolithic dispatcher in the original. It lives in its own translation unit (mirroring
// TSimMgr_AdvanceGlobalTurnStateMachine.cpp) so its packet structs, the inline tick-ack
// helper, and its optimizer footprint do not perturb the codegen of the neighbouring
// TMultiplayerMgr methods (adding it to TMultiplayerMgr.cpp demonstrably re-shaped
// EmitNationDiplomacyNeedStateSnapshotEvent15's store scheduling).

#include "game/TMultiplayerMgr.h"

#include <stdlib.h>
#include <string.h>

#include "game/NetMessage.h"
#include "game/TArmyBattle.h"
#include "game/CIterator.h"
#include "game/TCivUnit.h"
#include "game/TMilitaryUnit.h"
#include "game/TArmyMgr.h"
#include "game/TAutoGreatPower.h"
#include "game/TCity.h"
#include "game/TSortedList.h"
#include "game/TCountry.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TLoadSavePicture.h"
#include "game/TMapMgr.h"
#include "game/TMinor.h"
#include "game/TNetMgr.h"
#include "game/TNavyMgr.h"
#include "game/TNextDiplomationCommand.h"
#include "game/TOcean.h"
#include "game/TLandSaleEvent.h"
#include "game/TStream.h"
#include "game/TTown.h"
#include "game/TTradeMgr.h"
#include "game/TSimMgr.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"

namespace {

// Serializer tag+object pair for the 0x31 dispatch (same shape as the definition in
// TMultiplayerMgr.cpp; the serializer reads it through void*).
struct TaggedSerializablePayload {
  int tag;
  TObject* object;
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

// Turn-event-0x24 header: the 0xa8-byte city-score record payload is a separate
// NationStateRecordA8 local constructed immediately after this header on the stack
// (the original initializes the header, then constructs the record, and Send reads
// messageLength = 0xc8 bytes across both locals).
struct TurnEvent24CityRecordHeader : TimelyNetMessagePrefix {
  short cityRecordIndex;  // +0x1c
  unsigned char pad1e[2]; // header total 0x20
};

// Turn-event-0x2d payload: a minor nation's need-level array. Derives the timely
// prefix so the header stamp helper (0x5438e0) is callable, as the original does.
struct TurnEvent2DMinorNeedPacket : TimelyNetMessagePrefix {
  short nationSlot;              // +0x1c
  short needLevelByNation[0x17]; // +0x1e, total 0x4c
};

// Turn-event-0x18 payload: per-great-power diplomacy policy/grant/need arrays.
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

// Turn-event-1 payload: the remaining turn-resume pending-nation bitmask (same shape
// as the definition in TMultiplayerMgr.cpp).
struct TurnEvent1PendingMaskPacket2 : TimelyMessageHeader {
  int pendingMask; // +0x18, total 0x1c
};

// Turn-event-0xA payload: the resuming nation announces its home region and city name.
struct TurnEventACityAnnouncePacket : TimelyNetMessagePrefix {
  unsigned char nationId1C; // +0x1c
  unsigned char pad1d;
  short homeTile1E;      // +0x1e
  char cityName20[0x24]; // +0x20 (strncpy'd 0x21), total 0x44
};

// Turn-event-0x25 status board (same shape as NationStatusEvent25Packet in
// TMultiplayerMgr.cpp): seven per-nation four-cc status tags.
struct NationStatusEvent25Packet2 : TimelyMessageHeader {
  int statusTags[7]; // +0x18, total 0x34
};

// Turn-event-0x1F payload: nation-unheaded notice — the 'uhed' status tag plus the
// vacated slot index (the +0x18 pair reuses the timely-header tail).
struct TurnEvent1FNationUnheadedPacket : TimelyMessageHeader {
  int statusTag18;  // +0x18 'uhed'
  int nationSlot1C; // +0x1c, total 0x20
};

// Build + send the event-3 tick acknowledge (loopback flag set). Expanded inline six
// times inside HandleDiplomacyTurnEventPacketByCode; the out-of-line sibling
// EmitTurnEvent3Mode18WithActiveNation (0x5446a0) serves the cross-TU callers.
static __inline void EmitTurnEvent3TickCompleteLoopback() {
  TimelyMessageHeader packet;
  packet.messageTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventCode = 0;
  packet.eventCode = 3;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0;
  packet.messageLength = 0x18;
  g_pNetMgr006a6014->Send(&packet, 1);
}

} // namespace

// Turn-resume telemetry pass. Hosting: drop pending bits for absent/ineligible nations
// and the local nation, broadcast the remaining mask (event 1), and flush the latched
// event code once the mask drains. Client: acknowledge the pending event code (2 =
// announce home city, event 0xA; 5 = rebuild diplomacy pressure and re-emit state
// arrays; 8 = re-emit the composite; 0x14/0x15 = plain event-0xF ack). All paths then
// mark the local nation 'redy' and broadcast the event-0x25 status board ('unkn'
// defaults).
// FUNCTION: IMPERIALISM 0x00543280
void TMultiplayerMgr::HandleTurnResumeStateTelemetry() {
  unsigned char hosting = g_pSimMgr->multiplayerSessionRole == 1;
  if (hosting != 0) {
    for (int slot = 0; slot < 7; ++slot) {
      TGreatPower* nation = g_apNationStates[slot];
      if (nation == 0 || nation->IsClient() == 0) {
        pendingNationBitmask &= ~(1 << slot);
      }
    }
    pendingNationBitmask &= ~(1 << g_pSimMgr->GetActiveNationId());
    unsigned char stillHosting = g_pSimMgr->multiplayerSessionRole == 1;
    if (stillHosting != 0) {
      TurnEvent1PendingMaskPacket2 packet;
      packet.InitializeEmitEventHeaderWithActiveNation();
      packet.eventCode = 0;
      packet.fromNetworkId = 0;
      packet.eventCode = 1;
      packet.toNetworkId = 0;
      packet.pendingMask = pendingNationBitmask;
      packet.messageLength = 0;
      packet.messageLength = 0x1c;
      packet.toNetworkId = 0;
      g_pNetMgr006a6014->Send(&packet, 0);
      if (pendingNationBitmask == 0 && pendingNationSlotIndex != -1) {
        HandleDiplomacyTurnEventPacketByCode();
      }
    }
  } else {
    switch (pendingNationSlotIndex) {
    case 2: {
      CString cityName;
      EmitTurnEvent19NationStateArraysForSlot(g_pSimMgr->GetActiveNationId(), -1);
      EmitTurnEvent2CNationStateCompositeForSlot(g_pSimMgr->GetActiveNationId(), -1);
      TurnEventACityAnnouncePacket packet;
      packet.messageTag = 0x74696d65;
      packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
      packet.eventCode = 0;
      packet.fromNetworkId = 0;
      packet.eventCode = 0xa;
      packet.toNetworkId = 0;
      packet.toNetworkId = -1;
      packet.messageLength = 0;
      packet.messageLength = 0x44;
      packet.uiTurnToken = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
      char nationId = static_cast<char>(g_pSimMgr->GetActiveNationId());
      packet.nationId1C = nationId;
      packet.homeTile1E = (short)g_apTerrainTypeDescriptorTable[nationId]->homeTileIndex;
      int cityRecordIndex =
          g_apTerrainTypeDescriptorTable[nationId]->GetHomeRegionCityRecordIndex();
      g_pGlobalMapState->AssignCityRecordDisplayName(cityRecordIndex, &cityName);
      strncpy(packet.cityName20, cityName, 0x21);
      g_pNetMgr006a6014->Send(&packet, 0);
      break;
    }
    case 5: {
      DispatchTurnEventPacketWithCodeAndPayloadBuffer(
          0x2e, -1, reinterpret_cast<void*>(g_pSimMgr->GetActiveNationId()));
      DispatchTurnEventPacketWithCodeAndPayloadBuffer(
          0x2f, -1, reinterpret_cast<void*>(g_pSimMgr->GetActiveNationId()));
      DispatchTurnEventPacketWithCodeAndPayloadBuffer(
          0x30, -1, reinterpret_cast<void*>(g_pSimMgr->GetActiveNationId()));
      for (int slot = 0; slot < 0x17; ++slot) {
        TMinor* minor = g_apSecondaryNationStateSlots[slot];
        if (minor != 0) {
          minor->RebuildDiplomacyEconomicPressureFromMapState();
        }
      }
      g_apNationStates[g_pSimMgr->GetActiveNationId()]
          ->ResetDiplomacyNeedScoresAndClearAidAllocationMatrix();
      EmitTurnEvent19NationStateArraysForSlot(g_pSimMgr->GetActiveNationId(), -1);
      EmitTurnEvent2CNationStateCompositeForSlot(g_pSimMgr->GetActiveNationId(), -1);
      TurnEventFResumeAckPacket packet;
      packet.messageTag = 0x74696d65;
      packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
      packet.eventCode = 0;
      packet.eventCode = 0xf;
      packet.fromNetworkId = 0;
      packet.toNetworkId = 0;
      packet.toNetworkId = -1;
      packet.messageLength = 0;
      packet.messageLength = 0x20;
      packet.uiTurnToken = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
      packet.nationSlot1C = g_pSimMgr->GetActiveNationId();
      g_pNetMgr006a6014->Send(&packet, 0);
      break;
    }
    case 8: {
      EmitTurnEvent2CNationStateCompositeForSlot(g_pSimMgr->GetActiveNationId(), -1);
      TurnEventFResumeAckPacket packet;
      packet.messageTag = 0x74696d65;
      packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
      packet.eventCode = 0;
      packet.eventCode = 0xf;
      packet.fromNetworkId = 0;
      packet.toNetworkId = 0;
      packet.toNetworkId = -1;
      packet.messageLength = 0;
      packet.messageLength = 0x20;
      packet.uiTurnToken = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
      packet.nationSlot1C = g_pSimMgr->GetActiveNationId();
      g_pNetMgr006a6014->Send(&packet, 0);
      break;
    }
    case 0x14:
    case 0x15: {
      TurnEventFResumeAckPacket packet;
      packet.messageTag = 0x74696d65;
      packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
      packet.eventCode = 0;
      packet.eventCode = 0xf;
      packet.fromNetworkId = 0;
      packet.toNetworkId = 0;
      packet.toNetworkId = -1;
      packet.messageLength = 0;
      packet.messageLength = 0x20;
      packet.uiTurnToken = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
      packet.nationSlot1C = g_pSimMgr->GetActiveNationId();
      g_pNetMgr006a6014->Send(&packet, 0);
      break;
    }
    default:
      break;
    }
  }

  int readySlot = g_pSimMgr->GetActiveNationId();
  if (readySlot == -1) {
    readySlot = static_cast<signed char>(activeNationTagIndex);
  }
  nationStatusTags[readySlot] = 0x72656479; // 'redy'
  NationStatusEvent25Packet2 packet;
  packet.messageTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.eventCode = 0x25;
  packet.messageLength = 0;
  for (int i = 0; i < 7; ++i) {
    packet.statusTags[i] = 0x756e6b6e; // 'unkn'
  }
  packet.messageLength = 0x34;
  packet.toNetworkId = 0;
  packet.statusTags[readySlot] = 0x72656479; // 'redy'
  g_pNetMgr006a6014->Send(&packet, 0);
}

// Post-resume diplomacy turn-event dispatcher: switches on pendingNationSlotIndex (the
// received turn-event code) and re-broadcasts the matching game-state snapshot family.
// Code 2 pushes the full session bootstrap (relation-matrix sync, nation directory,
// per-capital tile/city records, navy/terrain/nation descriptor dispatches, per-nation
// state arrays, minor need levels); 5 probes reachability (autosaving when everyone is
// reachable) then sends the diplomacy policy/grant/need arrays; 6 posts the 'NeXT'
// diplomacy command; 8 re-sends the per-nation state arrays; 0x15 re-syncs descriptors
// plus the 'army' tagged payload and per-nation need snapshots. Every path except code
// 6 ends with the event-3 tick acknowledge.
// FUNCTION: IMPERIALISM 0x00543910
void TMultiplayerMgr::HandleDiplomacyTurnEventPacketByCode() {
  switch (pendingNationSlotIndex) {
  case 2: {
    TurnEvent2SyncPacket* syncPacket =
        g_pDiplomacyTurnStateManager
            ->BuildTurnEvent2ArraySyncPacketFromBufferAndRefreshBaselineCopy();
    syncPacket->toNetworkId = 0;
    g_pNetMgr006a6014->Send(syncPacket, 0);
    delete syncPacket;
    RefreshNationStatusLabelsAndCodesForSlotOrAll(-1);

    {
      TurnEventBNationDirectoryPacket packet;
      packet.packetTag = 0x74696d65;
      packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
      packet.eventCode = 0;
      packet.fromNetworkId = 0;
      packet.eventCode = 0xb;
      packet.toNetworkId = 0;
      packet.toNetworkId = 0;
      packet.messageLength = 0;
      packet.messageLength = 0x668;
      packet.pendingNationSlot = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
      for (int slot = 0; slot < 0x17; ++slot) {
        packet.homeTileBySlot[slot] = (short)g_apTerrainTypeDescriptorTable[slot]->homeTileIndex;
        int cityRecordIndex = g_apTerrainTypeDescriptorTable[slot]->GetHomeRegionCityRecordIndex();
        CString cityName;
        g_pGlobalMapState->AssignCityRecordDisplayName(cityRecordIndex, &cityName);
        strncpy(packet.cityNameBySlot[slot], cityName, 0x21);
        CString nationName;
        g_apTerrainTypeDescriptorTable[slot]->AssignSharedStringFromDescriptorNameOrDefault(
            &nationName);
        strncpy(packet.nationNameBySlot[slot], nationName, 0x21);
        TZone* portZone =
            g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(static_cast<short>(slot));
        packet.portZoneOrdinalBySlot[slot] = portZone->GetContextOrdinalOrInvalid();
      }
      g_pNetMgr006a6014->Send(&packet, 0);
    }

    for (int capitalSlot = 0; capitalSlot < 7; ++capitalSlot) {
      int homeTile = g_apTerrainTypeDescriptorTable[capitalSlot]->homeTileIndex;
      short neighborTiles[7];
      TMapMgr::ComputeHexNeighborTileIndices(static_cast<short>(homeTile), neighborTiles,
                                             g_pGlobalMapState->hexNeighborWrapHorizontally20);
      neighborTiles[6] = static_cast<short>(homeTile);
      for (int k = 0; k < 7; ++k) {
        short tileIndex = neighborTiles[k];
        if (tileIndex != -1) {
          TurnEvent23TileStatePacket packet;
          packet.packetTag = 0x74696d65;
          packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
          packet.eventCode = 0;
          packet.fromNetworkId = 0;
          packet.eventCode = 0x23;
          packet.toNetworkId = 0;
          packet.toNetworkId = 0;
          packet.messageLength = 0;
          packet.messageLength = 0x44;
          packet.pendingNationSlot = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
          packet.tileIndex = tileIndex;
          packet.record = g_pGlobalMapState->terrainStateTable[tileIndex];
          g_pNetMgr006a6014->Send(&packet, 0);
        }
      }
      short cityRecordIndex = static_cast<short>(
          g_apTerrainTypeDescriptorTable[capitalSlot]->GetHomeRegionCityRecordIndex());
      TurnEvent24CityRecordHeader packetHeader;
      packetHeader.InitializeEmitEventHeaderWithActiveNation();
      NationStateRecordA8 cityRecord;
      packetHeader.eventCode = 0;
      packetHeader.eventCode = 0x24;
      packetHeader.fromNetworkId = 0;
      packetHeader.toNetworkId = 0;
      packetHeader.toNetworkId = 0;
      packetHeader.messageLength = 0;
      packetHeader.messageLength = 0xc8;
      packetHeader.uiTurnToken = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
      packetHeader.cityRecordIndex = cityRecordIndex;
      // Same 0xa8 record: the packet-side NationStateRecordA8 is a view of
      // TGlobalMapCityScoreRecord (identical layout, CString at +0xa4; the original
      // copies with the shared operator= 0x54ae90). Confined here pending a merge of
      // the two reconstructions.
      cityRecord = *reinterpret_cast<NationStateRecordA8*>(
          &g_pGlobalMapState->cityScoreTable[cityRecordIndex]);
      g_pNetMgr006a6014->Send(&packetHeader, 0);
    }

    DispatchTurnEventPacketWithCodeAndPayloadBuffer(0x2e, -2, reinterpret_cast<void*>(-1));
    for (int descriptorSlot = 0; descriptorSlot < 0x17; ++descriptorSlot) {
      if (g_apTerrainTypeDescriptorTable[descriptorSlot] != 0) {
        DispatchTurnEventPacketWithCodeAndPayloadBuffer(0x2f, -2,
                                                        reinterpret_cast<void*>(descriptorSlot));
      }
    }
    DispatchTurnEventPacketWithCodeAndPayloadBuffer(0x30, -2, reinterpret_cast<void*>(-1));

    for (int stateSlot = 0; stateSlot < 7; ++stateSlot) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(stateSlot)) != 0) {
        EmitTurnEvent19NationStateArraysForSlot(static_cast<short>(stateSlot), -2);
        EmitTurnEvent2CNationStateCompositeForSlot(stateSlot, -2);
      }
    }
    for (short minorSlot = 7; minorSlot < 0x17; ++minorSlot) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(minorSlot) != 0) {
        TurnEvent2DMinorNeedPacket packet;
        packet.InitializeEmitEventHeaderWithActiveNation();
        packet.eventCode = 0;
        packet.eventCode = 0x2d;
        packet.fromNetworkId = 0;
        packet.toNetworkId = 0;
        packet.toNetworkId = -1;
        packet.messageLength = 0;
        packet.messageLength = 0x4c;
        packet.uiTurnToken = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
        packet.DestinateTo(-2);
        packet.nationSlot = minorSlot;
        for (short j = 0; j < 0x17; ++j) {
          packet.needLevelByNation[j] =
              g_apSecondaryNationStateSlots[minorSlot]->needLevelByNation[j];
        }
        g_pNetMgr006a6014->Send(&packet, 0);
      }
    }

    RefreshNationStatusLabelsAndCodesForSlotOrAll(-1);
    EmitTurnEvent3TickCompleteLoopback();
    break;
  }

  case 5: {
    unsigned char allReachable =
        g_pNetMgr006a6014->ProbeNationReachabilityAndMarkAwolBitmask() == 0;
    if (allReachable != 0) {
      SaveGameWithModeAndOptionalLabel(0xa2, 0);
    }
    TurnEvent18DiplomacyArraysPacket packet;
    packet.packetTag = 0x74696d65;
    packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
    packet.eventCode = 0;
    packet.eventCode = 0x18;
    packet.fromNetworkId = 0;
    packet.toNetworkId = 0;
    packet.toNetworkId = 0;
    packet.messageLength = 0;
    packet.messageLength = 0x3e4;
    packet.pendingNationSlot = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
    for (int slot = 0; slot < 7; ++slot) {
      TGreatPower* nation = g_apNationStates[slot];
      if (nation != 0) {
        for (int j = 0; j < 0x17; ++j) {
          packet.diplomacyPolicyByNation[slot][j] = nation->diplomacyPolicyByNation[j];
          packet.diplomacyGrantByNation[slot][j] = nation->diplomacyGrantByNation[j];
          packet.needLevelByNation[slot][j] = nation->needLevelByNation[j];
        }
      }
    }
    g_pNetMgr006a6014->Send(&packet, 0);
    g_pDiplomacyTurnStateManager->ApplyDiplomacyInterNationStatesForTurn();
    EmitTurnEvent3TickCompleteLoopback();
    break;
  }

  case 6: {
    TNextDiplomationCommand* command = new TNextDiplomationCommand();
    command->DispatchUiPacketWithTagNEXT();
    return;
  }

  case 8: {
    for (int stateSlot = 0; stateSlot < 7; ++stateSlot) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(stateSlot)) != 0) {
        EmitTurnEvent19NationStateArraysForSlot(static_cast<short>(stateSlot), -2);
        EmitTurnEvent2CNationStateCompositeForSlot(stateSlot, -2);
      }
    }
    for (short minorSlot = 7; minorSlot < 0x17; ++minorSlot) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(minorSlot) != 0) {
        TurnEvent2DMinorNeedPacket packet;
        packet.InitializeEmitEventHeaderWithActiveNation();
        packet.eventCode = 0;
        packet.eventCode = 0x2d;
        packet.fromNetworkId = 0;
        packet.toNetworkId = 0;
        packet.toNetworkId = -1;
        packet.messageLength = 0;
        packet.messageLength = 0x4c;
        packet.uiTurnToken = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
        packet.toNetworkId = 0;
        packet.nationSlot = minorSlot;
        for (short j = 0; j < 0x17; ++j) {
          packet.needLevelByNation[j] =
              g_apSecondaryNationStateSlots[minorSlot]->needLevelByNation[j];
        }
        g_pNetMgr006a6014->Send(&packet, 0);
      }
    }
    EmitTurnEvent3TickCompleteLoopback();
    break;
  }

  case 0x14:
    EmitTurnEvent3TickCompleteLoopback();
    break;

  case 0x15: {
    DispatchTurnEventPacketWithCodeAndPayloadBuffer(0x2e, -2, reinterpret_cast<void*>(-1));
    for (int descriptorSlot = 0; descriptorSlot < 0x17; ++descriptorSlot) {
      if (g_apTerrainTypeDescriptorTable[descriptorSlot] != 0) {
        DispatchTurnEventPacketWithCodeAndPayloadBuffer(0x2f, -2,
                                                        reinterpret_cast<void*>(descriptorSlot));
      }
    }
    DispatchTurnEventPacketWithCodeAndPayloadBuffer(0x30, -2, reinterpret_cast<void*>(-1));

    TurnEvent2SyncPacket* syncPacket =
        g_pDiplomacyTurnStateManager
            ->BuildTurnEvent2ArraySyncPacketFromBufferAndRefreshBaselineCopy();
    syncPacket->toNetworkId = 0;
    g_pNetMgr006a6014->Send(syncPacket, 0);
    delete syncPacket;

    TaggedSerializablePayload armyPayload;
    armyPayload.tag = 0x61726d79;
    armyPayload.object = static_cast<TObject*>(g_pMapContextActionManager);
    DispatchTurnEventPacketWithCodeAndPayloadBuffer(0x31, -2, &armyPayload);

    for (int snapshotSlot = 0; snapshotSlot < 7; ++snapshotSlot) {
      TGreatPower* nation = g_apNationStates[snapshotSlot];
      if (nation != 0 && nation->IsRemote() != 0) {
        EmitNationDiplomacyNeedStateSnapshotEvent15(0, snapshotSlot);
      }
    }
    EmitTurnEvent3TickCompleteLoopback();
    break;
  }

  default:
    EmitTurnEvent3TickCompleteLoopback();
    break;
  }
}

// Receive path for turn events 0x28 and 0x2E..0x32. The 0x1c-byte timely header is
// pre-stamped ('time' + active nation) and then immediately overwritten by the stream
// read -- original behavior, kept as-is; the switch keys on the streamed event code and
// the acting nation comes from the streamed header (-1 during session teardown).
// FUNCTION: IMPERIALISM 0x00549ff0
void TMultiplayerMgr::HandleTurnEventCodes28_2E_2F_30_31_32(TStream* stream) {
  TimelyNetMessagePrefix header;
  header.messageTag = 0x74696d65;
  header.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  stream->ReadBytes(&header, 0x1c);
  unsigned char isClientSession = g_pSimMgr->multiplayerSessionRole == 2;
  short nation;
  if (isClientSession != 0) {
    nation = -1;
  } else {
    nation = static_cast<char>(header.activeNationId);
  }
  switch (header.eventCode) {
  case 0x2e:
    g_pNavyOrderManager->DeserializeNavyOrderListsByNation(stream, nation);
    g_pActiveMapOrderContext->RefreshMapActionContextNationOverlaysAndOrderRanks();
    break;
  case 0x2f:
    CreateMilitaryRecruitOrdersForSelectedTerrain(stream, nation);
    break;
  case 0x30:
    CreateCivilianWorkOrdersForSelectedNations(stream, nation);
    break;
  case 0x31: {
    // The inverted-inequality nesting reproduces the original body layout: the 'town'
    // handler falls through inline, 'star' and 'army' bodies are emitted after it.
    int payloadTag = stream->streamSlot50();
    if (payloadTag != 0x61726d79) {     // 'army'
      if (payloadTag != 0x73746172) {   // 'star'
        if (payloadTag == 0x746f776e) { // 'town'
          TTown* town = new TTown();
          town->InitializeTownMarker(g_szEmptyString, 0, 0, g_pSimMgr->GetActiveNationId());
          town->ReadFrom(stream);
          TTown* existing =
              g_pGlobalMapState->FindTownMarkerForTileByOwnerNation(town->tileIndex14);
          if (existing != 0) {
            memcpy(existing, town, sizeof(TTown));
            town->Free();
          } else {
            g_apNationStates[town->ownerNation1c]->townMarkerList->AddTail(town);
          }
        }
      } else {
        if (stream->streamSlot50() == 0x6c616e64) { // 'land'
          short tileIndex = stream->ReadShort();
          short nationCode = stream->ReadShort();
          TLandSaleEvent* saleEvent = new TLandSaleEvent();
          saleEvent->ILandSaleEvent(tileIndex, nationCode);
          g_apNationStates[static_cast<short>(g_pSimMgr->GetActiveNationId())]->AddTurnStartEvent(
              saleEvent);
        }
      }
    } else {
      g_pMapContextActionManager->ReadFrom(stream);
    }
    break;
  }
  case 0x28: {
    TArmyBattle* battle = new TArmyBattle();
    battle->ReadFrom(stream);
    battle->StartBattle();
    break;
  }
  case 0x32:
    g_pNationInteractionStateManager->ReadFrom(stream);
    g_apNationStates[static_cast<short>(g_pSimMgr->GetActiveNationId())]
        ->ReleaseDiplomacyTrackedObjectSlots850();
    break;
  default:
    break;
  }
}

// FUNCTION: IMPERIALISM 0x0054a6d0
void TMultiplayerMgr::CreateMilitaryRecruitOrdersForSelectedTerrain(TStream* stream,
                                                                    short nationSlot) {
  // Stream leads with a nation letter ('a' + slot); everything below - including the
  // count read - is skipped when it doesn't match the requested slot.
  int terrainSlot = stream->ReadInteger() - 0x61; // - 'a'
  unsigned char terrainSelected =
      static_cast<unsigned char>(nationSlot == -1 || nationSlot == terrainSlot);
  if (terrainSelected != 0) {
    if (g_apTerrainTypeDescriptorTable[terrainSlot] != 0) {
      CIterator recruitIter(g_apTerrainTypeDescriptorTable[terrainSlot]->militaryUnitList44);
      for (TUnit* pendingRecruit = static_cast<TUnit*>(recruitIter.Reset()); recruitIter.More();
           pendingRecruit = static_cast<TUnit*>(recruitIter.Advance())) {
        pendingRecruit->DetachUnitOrderFromOwnerAndReset();
      }
      g_apTerrainTypeDescriptorTable[terrainSlot]->militaryUnitList44->FreePayloads();
    }
    short recruitOrderCount = stream->ReadShort();
    for (int recruitOrderIdx = recruitOrderCount; recruitOrderIdx != 0; --recruitOrderIdx) {
      TMilitaryUnit* recruitOrder = new TMilitaryUnit();
      recruitOrder->InitializeRecruitOrderState(0, -1, static_cast<short>(terrainSlot), 0);
      recruitOrder->ReadFrom(stream);
      recruitOrder->AssertValid();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0054a840
void TMultiplayerMgr::CreateCivilianWorkOrdersForSelectedNations(TStream* stream,
                                                                 short nationSlot) {
  // For each of the 7 great powers: when selected, detach + free its queued civilian
  // work orders, then (always) read this nation's order count and records from the
  // stream, discarding freshly-read orders for non-selected nations to keep the
  // stream cursor in sync.
  for (int nationIdx = 0; nationIdx < 7; ++nationIdx) {
    unsigned char nationSelected =
        static_cast<unsigned char>(nationSlot == -1 || nationSlot == nationIdx);
    if (g_apNationStates[nationIdx] != 0 && nationSelected != 0) {
      CIterator workOrderIter(g_apNationStates[nationIdx]->trackedObjectList);
      for (TUnit* pendingWorkOrder = static_cast<TUnit*>(workOrderIter.Reset());
           workOrderIter.More(); pendingWorkOrder = static_cast<TUnit*>(workOrderIter.Advance())) {
        pendingWorkOrder->DetachUnitOrderFromOwnerAndReset();
      }
      g_apNationStates[nationIdx]->trackedObjectList->FreePayloads();
    }
    short workOrderCount = stream->ReadShort();
    for (int workOrderIdx = workOrderCount; workOrderIdx != 0; --workOrderIdx) {
      TCivUnit* workOrder = new TCivUnit();
      workOrder->InitializeCivWorkOrderState(0, -1, nationIdx);
      workOrder->ReadFrom(stream);
      workOrder->AssertValid();
      if (nationSelected == 0) {
        workOrder->DetachUnitOrderFromOwnerAndReset();
        workOrder->Free();
      }
    }
  }
}

// Replace the nation in `nationSlot` with a freshly rolled AI (TAutoGreatPower):
// broadcast the 'uhed' (event-0x1F) notice when hosting, deep-copy the vacating
// nation's scalar/array state into the new object while swapping ownership of the
// list/queue/city subobjects (the city's owner back-reference is repointed), install
// the AI into both nation tables, re-derive war candidate flags, mark the scenario row
// AI-controlled, and free the old object. All exits then drop the session id, tag the
// slot 'suna', refresh status labels, and (hosting) re-broadcast the pending mask.
// FUNCTION: IMPERIALISM 0x0054bd20
void TMultiplayerMgr::ReplaceNationStateForSlotAndRefreshStatus(int nationSlot) {
  unsigned char isLocalNation = nationSlot == g_pSimMgr->GetActiveNationId();
  int sessionRole = g_pSimMgr->multiplayerSessionRole;
  unsigned char isClientSession = sessionRole == 2;
  if (isClientSession == 0) {
    unsigned char hosting = sessionRole == 1;
    if (hosting != 0) {
      TurnEvent1FNationUnheadedPacket packet;
      packet.messageTag = 0x74696d65;
      packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
      packet.eventCode = 0;
      packet.fromNetworkId = 0;
      packet.toNetworkId = 0;
      packet.eventCode = 0x1f;
      packet.messageLength = 0;
      packet.messageLength = 0x20;
      packet.DestinateTo(-2);
      packet.statusTag18 = 0x64656875; // 'uhed'
      packet.nationSlot1C = nationSlot;
      g_pNetMgr006a6014->Send(&packet, 0);
    }
    TGreatPower* oldNation = g_apNationStates[nationSlot];
    if (oldNation != 0 && oldNation->diplomacyEligibilityA0 != 0 && isLocalNation == 0) {
      int policyDice5 = rand() % 5;
      int policyDice6 = rand() % 6;
      int policyDice4 = rand() % 4;
      TAutoGreatPower* newNation = new TAutoGreatPower();
      newNation->InitializeNationMinisterSubsystemsByPolicyIds(
          nationSlot, 2, static_cast<short>(policyDice4), static_cast<short>(policyDice6),
          static_cast<short>(policyDice5));

      newNation->identitySharedString0 = oldNation->identitySharedString0;
      newNation->identitySharedString1 = oldNation->identitySharedString1;
      newNation->nationSlot = oldNation->nationSlot;
      newNation->encodedNationSlot = oldNation->encodedNationSlot;
      newNation->treasuryValue10 = oldNation->treasuryValue10;
      memcpy(newNation->needLevelByNation, oldNation->needLevelByNation,
             sizeof(newNation->needLevelByNation));
      TSortedList* militaryUnits = newNation->militaryUnitList44;
      newNation->militaryUnitList44 = oldNation->militaryUnitList44;
      oldNation->militaryUnitList44 = militaryUnits;
      memcpy(newNation->unitNameOrdinalByType, oldNation->unitNameOrdinalByType,
             sizeof(newNation->unitNameOrdinalByType));
      newNation->unitNameCounter84 = oldNation->unitNameCounter84;
      newNation->homeTileIndex = oldNation->homeTileIndex;
      newNation->overlayAnchorTileCache8c = oldNation->overlayAnchorTileCache8c;
      TLongintList* ownedRegions = newNation->ownedRegionList;
      newNation->ownedRegionList = oldNation->ownedRegionList;
      oldNation->ownedRegionList = ownedRegions;
      newNation->diplomacyCounterA2 = oldNation->diplomacyCounterA2;
      newNation->tradeCapacity = oldNation->tradeCapacity;
      newNation->needCapA6 = oldNation->needCapA6;
      newNation->needsOverCapFlag = oldNation->needsOverCapFlag;
      newNation->grantTotalCost = oldNation->grantTotalCost;
      newNation->diplomacyCounterB0 = oldNation->diplomacyCounterB0;
      memcpy(newNation->diplomacyPolicyByNation, oldNation->diplomacyPolicyByNation,
             sizeof(newNation->diplomacyPolicyByNation));
      memcpy(newNation->diplomacyGrantByNation, oldNation->diplomacyGrantByNation,
             sizeof(newNation->diplomacyGrantByNation));
      memcpy(newNation->needCurrentByType, oldNation->needCurrentByType,
             sizeof(newNation->needCurrentByType));
      memcpy(newNation->needTargetByType, oldNation->needTargetByType,
             sizeof(newNation->needTargetByType));
      memcpy(newNation->relationDeltaCurrent, oldNation->relationDeltaCurrent,
             sizeof(newNation->relationDeltaCurrent));
      memcpy(newNation->relationDeltaSnapshot, oldNation->relationDeltaSnapshot,
             sizeof(newNation->relationDeltaSnapshot));
      memcpy(newNation->diplomacyState1c6, oldNation->diplomacyState1c6,
             sizeof(newNation->diplomacyState1c6));
      memcpy(newNation->diplomacyState1f4, oldNation->diplomacyState1f4,
             sizeof(newNation->diplomacyState1f4));
      memcpy(newNation->diplomacyState222, oldNation->diplomacyState222,
             sizeof(newNation->diplomacyState222));
      memcpy(newNation->diplomacyState250, oldNation->diplomacyState250,
             sizeof(newNation->diplomacyState250));
      memcpy(newNation->aidAllocationMatrix, oldNation->aidAllocationMatrix,
             sizeof(newNation->aidAllocationMatrix));
      newNation->budgetPoolBase = oldNation->budgetPoolBase;
      newNation->budgetPoolDelta = oldNation->budgetPoolDelta;
      TSortedByRelationshipList* turnEvents = newNation->turnEventQueue;
      newNation->turnEventQueue = oldNation->turnEventQueue;
      oldNation->turnEventQueue = turnEvents;
      TSortedByRelationshipList* proposals = newNation->proposalQueue;
      newNation->proposalQueue = oldNation->proposalQueue;
      oldNation->proposalQueue = proposals;
      for (int trackedSlot = 0; trackedSlot < 0x11; ++trackedSlot) {
        TSortedByRelationshipList* tracked = newNation->diplomacyTrackedSlots[trackedSlot];
        newNation->diplomacyTrackedSlots[trackedSlot] =
            oldNation->diplomacyTrackedSlots[trackedSlot];
        oldNation->diplomacyTrackedSlots[trackedSlot] = tracked;
      }
      TCity* city = oldNation->city;
      oldNation->city = newNation->city;
      newNation->city = city;
      if (city != 0) {
        city->ownerNationAc = newNation;
      }
      TSortedList* townMarkers = newNation->townMarkerList;
      newNation->townMarkerList = oldNation->townMarkerList;
      oldNation->townMarkerList = townMarkers;
      TSortedList* trackedObjects = newNation->trackedObjectList;
      newNation->trackedObjectList = oldNation->trackedObjectList;
      oldNation->trackedObjectList = trackedObjects;
      memcpy(newNation->candidateNationFlags, oldNation->candidateNationFlags,
             sizeof(newNation->candidateNationFlags));
      // 0xd-byte block copy from serializedStatusFlags through expansionEventGate
      // (field8d5 is deliberately left at its freshly constructed value).
      memcpy(newNation->serializedStatusFlags, oldNation->serializedStatusFlags, 0xd);
      memcpy(newNation->field8d6, oldNation->field8d6, sizeof(newNation->field8d6));
      newNation->field900 = oldNation->field900;
      newNation->field904 = oldNation->field904;

      g_apNationStates[nationSlot] = newNation;
      g_apTerrainTypeDescriptorTable[nationSlot] = newNation;
      newNation->QueueMapActionMissionsForPortZoneCandidates();
      for (int targetSlot = 0; targetSlot < 0x17; ++targetSlot) {
        if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationSlot, targetSlot) != 0) {
          newNation->candidateNationFlags[targetSlot] = 1;
        }
      }
      g_pSimMgr->nationControlModes[nationSlot] = 2;
      oldNation->Free();
    }
    unsigned char stillHosting = g_pSimMgr->multiplayerSessionRole == 1;
    if (stillHosting != 0 && isLocalNation == 0) {
      g_pNetMgr006a6014->NotifyIfNationMatchesSessionActiveNation(nationSessionIds[nationSlot]);
    }
  }
  unsigned char tornDownNow = g_pSimMgr->multiplayerSessionRole == 2;
  if (tornDownNow != 0) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation != 0) {
      nation->diplomacyEligibilityA0 = 0;
    }
  }
  nationSessionIds[nationSlot] = 0;
  nationStatusTags[nationSlot] = 0x756e6173; // 'suna'
  RefreshNationStatusLabelsAndCodesForSlotOrAll(nationSlot);
  unsigned char hostingMask = g_pSimMgr->multiplayerSessionRole == 1;
  if (hostingMask != 0) {
    pendingNationBitmask &= ~(1 << nationSlot);
    unsigned char hostingBroadcast = g_pSimMgr->multiplayerSessionRole == 1;
    if (hostingBroadcast != 0) {
      TurnEvent1PendingMaskPacket2 packet;
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
      if (pendingNationBitmask == 0 && pendingNationSlotIndex != -1) {
        HandleDiplomacyTurnEventPacketByCode();
      }
    }
  }
}

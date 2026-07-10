// TMultiplayerMgr::HandleDiplomacyTurnEventPacketByCode (0x00543910) is a single ~2.4KB
// monolithic dispatcher in the original. It lives in its own translation unit (mirroring
// TSimMgr_AdvanceGlobalTurnStateMachine.cpp) so its packet structs, the inline tick-ack
// helper, and its optimizer footprint do not perturb the codegen of the neighbouring
// TMultiplayerMgr methods (adding it to TMultiplayerMgr.cpp demonstrably re-shaped
// EmitNationDiplomacyNeedStateSnapshotEvent15's store scheduling).

#include "game/TMultiplayerMgr.h"

#include <string.h>

#include "game/NetMessage.h"
#include "game/TArmyMgr.h"
#include "game/TCountry.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TLoadSavePicture.h"
#include "game/TMapMgr.h"
#include "game/TMinor.h"
#include "game/TNetMgr.h"
#include "game/TNextDiplomationCommand.h"
#include "game/TOcean.h"
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
  short homeRegionBySlot[0x17];      // +0x1c
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
        packet.homeRegionBySlot[slot] =
            (short)g_apTerrainTypeDescriptorTable[slot]->homeRegionIndex;
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
      int homeTile = g_apTerrainTypeDescriptorTable[capitalSlot]->homeRegionIndex;
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
      if (nation != 0 && nation->ShouldDispatchImmediatelySlot28() != 0) {
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
